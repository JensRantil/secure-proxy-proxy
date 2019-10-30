Secury Proxy Proxy
==================
Secure Proxy Proxy (SPP) is an HTTP(S) forward proxy that only allows
forwarding TLS traffic. It does this in two different ways:

 * It rejects all HTTP methods (`GET`, `POST` etc.) except `CONNECT`. This
   means that it rejects any traffic which it knows isn't encrypted.
 * For `CONNECT` requests, it probes the downstream connection that it can do a
   TLS handshake. This adds security at the expense of latency.

SPP supports two types of downstream destinations for the `CONNECT` TCP
tunnels:

 * Other forward proxies. If it wasn't this the name of the proxy would be
   "Secure Proxy". Routing to know which downstream proxy to go through is done
   using the destination host+port in `CONNECT` (that is, `google.com:443` in
   `CONNECT google.com:443`). It can either be based on exact match or through
   regular expression. The routing rules are tested in order.
 * Direct tunneling to `google.com:443` without passing through a downstream
   forward HTTP proxy.

If no routing rule can be found, the proxy proxies to a default proxy if it
exists. If no default proxy is defined in config, it makes a direct connection
to the destination the upstream client has asked to connect to.

See `config.yaml` for an example configuration.

Usage
-----
```bash
$ go get github.com/JensRantil/secure-proxy-proxy
$ GODEBUG=http2server=0 secure-proxy-proxy --help
usage: secure-secure-proxy [<flags>] <command> [<args> ...]

A TLS-only proxy that routes requests downstream to specific proxy depending on host.

Flags:
  --help                Show context-sensitive help (also try --help-long and --help-man).
  --config=config.yaml  Config file to read up.

Commands:
  help [<command>...]
    Show help.

  serve [<flags>]
    Serve the proxy.

  validate
    Validate the configuration file can be parsed. Non-zero exit code if fails. Useful for CI.


```
