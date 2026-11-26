package tuna

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPostJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.URL.Path != "/prefix/v1/connect" || r.UserAgent() != "tuna-test/1":
			w.WriteHeader(http.StatusTeapot)
		case strings.Contains(string(body), `"token":"moved"`):
			http.Redirect(w, r, "https://elsewhere.example/v1/connect", http.StatusMovedPermanently)
		case strings.Contains(string(body), `"token":"bad"`):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"code":"BadRequest","error":"Incorrect token","request_id":"r1"}`)
		case strings.Contains(string(body), `"token":"down"`):
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "<html>bad gateway</html>")
		case strings.Contains(string(body), `"token":"proxy"`):
			w.Header().Set("Retry-After", "86400")
			w.WriteHeader(http.StatusServiceUnavailable)
		case strings.Contains(string(body), `"token":"busy"`):
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"code":"ServiceUnavailable","error":"busy"}`)
		default:
			_, _ = io.WriteString(w, `{"tunnel_session_id":"s42","banner":"`+strings.Repeat("x", 10000)+`"}`)
		}
	}))
	defer srv.Close()

	post := func(token string, out any) error {
		return postJSON(context.Background(), newHTTPClient(nil), srv.URL+"/prefix/", "/v1/connect", "tuna-test/1",
			connectRequest{Token: token}, out)
	}

	var cr connectResponse
	if err := post("ok", &cr); err != nil || cr.TunnelSessionID != "s42" || len(cr.Banner) != 10000 {
		t.Fatalf("ok: err=%v session=%q banner=%d", err, cr.TunnelSessionID, len(cr.Banner))
	}

	for token, permanent := range map[string]bool{"bad": true, "moved": true, "busy": false, "down": false} {
		if err := post(token, nil); IsPermanent(err) != permanent {
			t.Fatalf("%s: err=%v, want permanent=%v", token, err, permanent)
		}
	}

	var se *ServerError
	if err := post("busy", nil); !errors.As(err, &se) || se.RetryAfter != 3*time.Second {
		t.Fatalf("busy: err=%v", err)
	}
	if err := post("proxy", nil); !errors.As(err, &se) || se.RetryAfter != maxRetryAfter {
		t.Fatalf("proxy: err=%v", err)
	}
}

func TestPostJSONTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"tunnel_session_id":"tls"}`)
	}))
	defer srv.Close()

	var cr connectResponse
	if err := postJSON(context.Background(), newHTTPClient(nil), srv.URL, "/v1/connect", "tuna-test/1", connectRequest{}, &cr); err == nil {
		t.Fatal("self-signed certificate accepted with system roots")
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	if err := postJSON(context.Background(), newHTTPClient(&tls.Config{RootCAs: pool}), srv.URL, "/v1/connect", "tuna-test/1", connectRequest{}, &cr); err != nil || cr.TunnelSessionID != "tls" {
		t.Fatalf("err=%v session=%q", err, cr.TunnelSessionID)
	}
}
