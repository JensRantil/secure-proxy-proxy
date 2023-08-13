package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	// Using JensRantil fork here since it has a security fix. Let's move back
	// to upstream fork as soon as [1] has been merged.
	//
	// [1] https://github.com/magisterquis/connectproxy/pull/2
	"github.com/JensRantil/connectproxy"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	xproxy "golang.org/x/net/proxy"

	"github.com/elazarl/goproxy"

	"github.com/alecthomas/kingpin/v2"
)

var (
	app        = kingpin.New("secure-proxy-proxy", "A TLS-only proxy that routes requests downstream to specific proxy depending on host.")
	configFile = app.Flag("config", "Config file to read up.").Default("config.yaml").OpenFile(os.O_RDONLY, 0)

	// * TODO: Add `newproxy` subcommand that asks a series of questions and modifies the YAML file.
	serveCmd          = app.Command("serve", "Serve the proxy.")
	listen            = serveCmd.Flag("listen", "Interface proxy should listen on.").Default(":8080").String()
	prometheusListen  = serveCmd.Flag("prometheus-listen", "Interface Prometheus should scrape.").Default(":9000").String()
	noTls             = serveCmd.Flag("no-tls", "Explicitly disable TLS. BAD!").Bool()
	tlsKeyFile        = serveCmd.Flag("tls-key-file", "PEM file containing the TLS secret key.").ExistingFile()
	tlsCertFile       = serveCmd.Flag("tls-cert-file", "PEM file containing the TLS certificate.").ExistingFile()
	downstreamTimeout = serveCmd.Flag("downstream-timeout", "Timeout for downstream connections.").Default("3s").Duration()

	validateCmd = app.Command("validate", "Validate the configuration file can be parsed. Non-zero exit code if fails. Useful for CI.")
)

func main() {
	cmd := kingpin.MustParse(app.Parse(os.Args[1:]))

	config := mustReadConfig(*configFile)

	switch cmd {
	case serveCmd.FullCommand():
		serve(config)
	case validateCmd.FullCommand():
		// no-op. Validation is done implicitly through the mustReadConfig(...) call.
		fmt.Println("Config file parsed properly.")
	}
}

func mustReadConfig(f *os.File) Config {
	conf, err := readConfig(f)
	if err != nil {
		log.Fatalln("unable to read config:", err)
	}
	return conf
}

func serve(config Config) {
	// Occasionally, the proxy library will print something like
	//
	//     2019/10/27 23:36:20 [006] WARN: Error copying to client: readfrom tcp [::1]:59047->[::1]:8888: read tcp [::1]:8080->[::1]:59046: read: connection reset by peer
	//
	// . This is not an issues in itself, but simply too verbose logging. Please track [1] for a fix.
	//
	// [1] https://github.com/elazarl/goproxy/issues/160
	proxy := mustBuildProxy(config)

	go func() {
		handler := http.NewServeMux()
		handler.Handle("/metrics", promhttp.Handler())

		server := &http.Server{Addr: *prometheusListen, Handler: handler}
		log.Printf("Starting Prometheus/metrics server on address %s...", *prometheusListen)
		server.ListenAndServe()
	}()

	log.Printf("Starting proxy server on address %s...", *listen)

	if *noTls {
		log.Println("WARNING!!! NOT serving using TLS!")
		log.Fatalln(http.ListenAndServe(*listen, proxy))
	} else {
		log.Println("TLS cert file:", *tlsCertFile)
		log.Println("TLS key file: ", *tlsKeyFile)
		log.Fatalln(http.ListenAndServeTLS(*listen, *tlsCertFile, *tlsKeyFile, proxy))
	}
}

// Prometheus metrics.
var (
	invalidRequest = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: buildMetricName("invalid_requests_total"),
			Help: "Counter of the number of non CONNECT requests that have been rejected.",
		},
		[]string{"method"},
	)
	routeMetric = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: buildMetricName("proxy_requests_total"),
			Help: "Count the number of route matches.",
		},
		[]string{"route_type", "route"},
	)
	dialSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: buildMetricName("dial_seconds"),
			Help: "Histogram of how long it took to connect using dial.",
		},
		[]string{"route_type", "route"},
	)
	dialTimeout = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: buildMetricName("dial_timeouts_total"),
			Help: "Count the number of route matches.",
		},
		[]string{"route_type", "route"},
	)
)

func buildMetricName(name string) string {
	return prometheus.BuildFQName("secureproxyproxy", "", name)
}

func mustBuildProxy(config Config) http.Handler {
	if !strings.Contains(os.Getenv("GODEBUG"), "http2server=0") {
		log.Fatalln("HTTP/2 must be disabled. Make sure `GODEBUG` environment variable has set `http2server=0`.")
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			invalidRequest.WithLabelValues(r.Method).Inc()

			// TODO: If StatusForbidden the correct HTTP code?
			return r, goproxy.NewResponse(r,
				goproxy.ContentTypeText, http.StatusForbidden,
				"Only CONNECT requests are allowed through proxy.")
		},
	)

	proxy.ConnectDial = func(network string, addr string) (net.Conn, error) {
		log.Printf("Proxying to '%s'.", addr)
		start := time.Now()

		dialer, metric, err := constructDialer(config, addr)
		if err != nil {
			return nil, err
		}
		defer dialSeconds.WithLabelValues(metric...).Observe(time.Now().Sub(start).Seconds())

		// TODO: Execute testTls in a separate goroutine to reduce the dial latency.

		// NOTE: This function call will initiate a _NEW_ TLS connection and
		// make sure the handshake goes through. This is not 100% fault proof
		// as the downstread HTTP server might employ something like [1] which
		// allows _both_ TLS and unencrypted traffic on the same port. The
		// _real_, proper solution, would be to sniff the initial bytes and
		// close the connection if they don't look like TLS traffic. [2] look
		// something that would help for that.
		//
		// [1] https://github.com/soheilhy/cmux
		// [2] https://github.com/soheilhy/cmux/blob/e09e9389d85d8492d313d73d1469c029e710623f/matchers.go#L82
		err = testTls(dialer, network, addr)
		var conn net.Conn
		if err == nil {
			conn, err = dialer.Dial(network, addr)
		}

		if _, ok := err.(connectproxy.ErrorConnectionTimeout); ok {
			dialTimeout.WithLabelValues(metric...).Inc()
		}
		if err != nil {
			log.Printf("Error connecting to '%s': %s", addr, err)
		}
		return conn, err
	}

	return proxy
}

func testTls(dialer xproxy.Dialer, network, addr string) error {
	conn, err := dialer.Dial(network, addr)
	if err != nil {
		return err
	}

	// HACK. http.ReadRequest also does this.
	reqURL, err := url.Parse("http://" + addr)
	if err != nil {
		return fmt.Errorf("unable to parse host: %s", err)
	}

	hostParts := strings.Split(reqURL.Host, ":") // Host field might contain port.
	tlsConn := tls.Client(conn, &tls.Config{ServerName: hostParts[0]})
	defer tlsConn.Close()
	return tlsConn.Handshake()
}

func constructDialer(config Config, addr string) (xproxy.Dialer, []string, error) {
	proxyConfig := &connectproxy.Config{
		DialTimeout: *downstreamTimeout,
	}

	for routeindex, route := range config.Routes {
		if route.Matches(addr) {
			metric := []string{"route", strconv.Itoa(routeindex)}
			routeMetric.WithLabelValues(metric...).Inc()
			dialer, err := connectproxy.NewWithConfig(route.Proxy().Address, xproxy.Direct, proxyConfig)
			return dialer, metric, err
		}
	}

	if route := config.DefaultRoute; route != nil {
		metric := []string{"default-proxy", "n/a"}
		routeMetric.WithLabelValues(metric...).Inc()

		dialer, err := connectproxy.NewWithConfig(route.Address, xproxy.Direct, proxyConfig)
		return dialer, metric, err
	}

	metric := []string{"direct", "n/a"}
	routeMetric.WithLabelValues(metric...).Inc()
	return xproxy.Direct, metric, nil
}
