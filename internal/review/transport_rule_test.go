package review

import "testing"

func TestCleartextTransportFlagsHTTPWithCredentials(t *testing.T) {
	src := `package api

import "net/http"

func Handler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	_ = token
}

func main() {
	_ = http.ListenAndServe(":8080", nil)
}
`
	var found bool
	for _, f := range (CleartextTransportRule{}).Check(goDiff("cmd/api/main.go", src)) {
		if f.Rule == "cleartext-transport" && f.Severity == "medium" {
			found = true
		}
	}
	if !found {
		t.Fatal("cleartext credential server not flagged")
	}
}

func TestCleartextTransportSkipsTLSAndNoCreds(t *testing.T) {
	tls := `package api

import "net/http"

func main() {
	_ = http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil)
}

func Handler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	_ = token
}
`
	for _, f := range (CleartextTransportRule{}).Check(goDiff("cmd/api/main.go", tls)) {
		if f.Rule == "cleartext-transport" {
			t.Fatalf("TLS server flagged: %+v", f)
		}
	}
	plain := `package api

import "net/http"

func main() {
	_ = http.ListenAndServe(":8080", nil)
}

func Health(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}
`
	for _, f := range (CleartextTransportRule{}).Check(goDiff("cmd/health/main.go", plain)) {
		if f.Rule == "cleartext-transport" {
			t.Fatalf("credential-free server flagged: %+v", f)
		}
	}
}

func TestUnauthenticatedRouteFlagsParamRouteOutsideAPI(t *testing.T) {
	src := `package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func NewRouter() chi.Router {
	r := chi.NewRouter()
	r.Route("/api/v2", func(r chi.Router) {
		r.Use(requireScope)
		r.Get("/plugins/{name}/config", getConfig)
	})
	r.Get("/plugins/{name}/*", servePluginUI)
	return r
}
`
	var found bool
	for _, f := range (UnauthenticatedRouteRule{}).Check(goDiff("api/server.go", src)) {
		if f.Rule == "unauthenticated-route" && f.Severity == "low" {
			found = true
		}
	}
	if !found {
		t.Fatal("parameterized route outside /api not flagged")
	}
}

func TestUnauthenticatedRouteSkipsAPIAndStatic(t *testing.T) {
	src := `package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func NewRouter() chi.Router {
	r := chi.NewRouter()
	r.Route("/api/v2", func(r chi.Router) {
		r.Use(requireScope)
		r.Get("/plugins/{name}/config", getConfig)
	})
	r.Handle("/assets/*", http.FileServer(nil))
	r.Get("/healthz", healthz)
	return r
}
`
	for _, f := range (UnauthenticatedRouteRule{}).Check(goDiff("api/server.go", src)) {
		if f.Rule == "unauthenticated-route" {
			t.Fatalf("api/static route flagged: %+v", f)
		}
	}
}

func TestUnauthenticatedRouteSkipsWithAuthReceiver(t *testing.T) {
	src := `package api

import "github.com/go-chi/chi/v5"

func NewRouter(r chi.Router) chi.Router {
	r.Route("/api/v2", func(r chi.Router) {
		r.Get("/status", status)
	})
	pluginUI := r.With(srv.pluginUIAuth)
	pluginUI.Get("/plugins/{name}", servePluginIndex)
	pluginUI.Get("/plugins/{name}/*", servePluginUI)
	return r
}
`
	for _, f := range (UnauthenticatedRouteRule{}).Check(goDiff("api/server.go", src)) {
		if f.Rule == "unauthenticated-route" {
			t.Fatalf("route on auth-wrapped receiver flagged: %+v", f)
		}
	}
}
