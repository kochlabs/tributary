package api

import (
	"net"
	"net/http"
	"strings"
)

// RedirectToHTTPS answers plain-HTTP requests (port 80) with a redirect to
// the same host and path over HTTPS, so typing the bare address works.
// httpsAddr is the HTTPS listen address; its port is added unless it's 443.
func RedirectToHTTPS(httpsAddr string) http.Handler {
	_, port, _ := net.SplitHostPort(httpsAddr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if host == "" {
			http.Error(w, "use HTTPS", http.StatusBadRequest)
			return
		}
		if strings.Contains(host, ":") {
			host = "[" + host + "]" // IPv6 literal
		}
		if port != "" && port != "443" {
			host += ":" + port
		}
		code := http.StatusMovedPermanently
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			code = http.StatusPermanentRedirect // keep the method and body
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), code)
	})
}
