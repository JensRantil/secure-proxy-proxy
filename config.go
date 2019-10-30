package main

import (
	"fmt"
	"net/url"
	"os"
	"regexp"

	multierror "github.com/hashicorp/go-multierror"
	yaml "gopkg.in/yaml.v2"
)

// Config is a validated configuration.
type Config struct {
	DefaultRoute *Proxy
	Routes       []Route
}

// RawConfig if as configuration is stored in the yaml file.
type RawConfig struct {
	DefaultRoute *RawProxy  `yaml:"defaultProxy"`
	Routes       []RawRoute `yaml:"routes"`
}

func (r RawConfig) Validate() (c Config, err error) {
	var merr *multierror.Error
	if r.DefaultRoute != nil {
		defaultRoute, drerr := r.DefaultRoute.Validate()
		c.DefaultRoute = &defaultRoute
		merr = multierror.Append(nil, drerr)
	}

	for _, route := range r.Routes {
		parsedRoute, err := route.Validate()
		merr = multierror.Append(merr, err)
		c.Routes = append(c.Routes, parsedRoute)
	}

	err = merr.ErrorOrNil()
	return
}

type Route interface {
	Matches(connectstr string) bool
	Proxy() Proxy
}

type proxyRoute struct {
	proxy Proxy
}

func (p proxyRoute) Proxy() Proxy {
	return p.proxy
}

type fixedRoute struct {
	proxyRoute
	connectstr string
}

func (r fixedRoute) Matches(connectstr string) bool {
	return connectstr == r.connectstr
}

func newFixedRoute(route RawRoute) (cr Route, err error) {
	var c fixedRoute

	proxy, err := route.Proxy.Validate()
	c.proxyRoute = proxyRoute{proxy}

	c.connectstr = route.Pattern

	cr = c
	return
}

type regexpRoute struct {
	proxyRoute
	pattern *regexp.Regexp
}

func (r regexpRoute) Matches(connectstr string) bool {
	return r.pattern.MatchString(connectstr)
}

func newRegexpRoute(route RawRoute) (cr Route, err error) {
	var c regexpRoute

	proxy, err := route.Proxy.Validate()
	if err != nil {
		return
	}
	c.proxyRoute = proxyRoute{proxy}

	c.pattern, err = regexp.Compile(route.Pattern)

	cr = c
	return
}

var typeByString = map[string]func(RawRoute) (Route, error){
	"exact":  newFixedRoute,
	"regexp": newRegexpRoute,
}

type RawRoute struct {
	Type    string   `yaml:"type"`
	Pattern string   `yaml:"pattern"`
	Proxy   RawProxy `yaml:"proxy"`
}

func (route RawRoute) Validate() (c Route, err error) {
	creator, existed := typeByString[route.Type]
	if !existed {
		err = fmt.Errorf("route type %s unrecognized", route.Type)
		return
	}
	c, err = creator(route)

	return
}

type Proxy struct {
	Address *url.URL
}

type RawProxy struct {
	Address string `yaml:"address"`
}

func (p RawProxy) Validate() (c Proxy, err error) {
	u, err := url.Parse(p.Address)
	c.Address = u
	return
}

func readConfig(f *os.File) (conf Config, err error) {
	var raw RawConfig
	if err = yaml.NewDecoder(f).Decode(&raw); err != nil {
		return
	}
	conf, err = raw.Validate()
	return
}
