package api

import (
	"net/http/httptest"
	"testing"
)

func TestRedirectToHTTPS(t *testing.T) {
	cases := []struct{ listen, method, host, uri, code, want string }{
		{":443", "GET", "192.168.20.230", "/explorer?view=paths", "301", "https://192.168.20.230/explorer?view=paths"},
		{":443", "GET", "netflow.example.ts.net:80", "/", "301", "https://netflow.example.ts.net/"},
		{":8443", "GET", "kl-svc-netflow-1", "/login", "301", "https://kl-svc-netflow-1:8443/login"},
		{":443", "GET", "[fd7a:115c::1]:80", "/", "301", "https://[fd7a:115c::1]/"},
		{":443", "POST", "host", "/api/x", "308", "https://host/api/x"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "http://"+c.host+c.uri, nil)
		r.Host = c.host
		w := httptest.NewRecorder()
		RedirectToHTTPS(c.listen).ServeHTTP(w, r)
		if got := w.Header().Get("Location"); got != c.want || w.Code != map[string]int{"301": 301, "308": 308}[c.code] {
			t.Errorf("%s %s%s: %d %q, want %s %q", c.method, c.host, c.uri, w.Code, got, c.code, c.want)
		}
	}
}
