package tuna

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	apiTimeout      = 15 * time.Second
	maxResponseSize = 1 << 20
	maxRetryAfter   = 5 * time.Minute
)

// ServerError is an error response from the tuna.am API.
type ServerError struct {
	// Status is the HTTP status code.
	Status int `json:"-"`
	// Code is the machine-readable error code.
	Code string `json:"code"`
	// Message is the human-readable error text.
	Message string `json:"error"`
	// RequestID identifies the request for tuna.am support.
	RequestID string `json:"request_id"`
	// RetryAfter is the delay requested by the server, if any.
	RetryAfter time.Duration `json:"-"`

	beforeFirstConnect bool
}

func (e *ServerError) Error() string {
	if e.RequestID != "" {
		return fmt.Sprintf("tuna: %s (request id %s)", e.Message, e.RequestID)
	}
	return "tuna: " + e.Message
}

func (e *ServerError) permanent() bool {
	if e.Status >= 300 && e.Status < 400 {
		return true
	}
	if e.beforeFirstConnect && e.Status >= 400 && e.Status < 500 && e.Status != http.StatusRequestTimeout && e.Status != http.StatusTooManyRequests {
		return true
	}
	switch e.Code {
	case "PaymentRequired", "Unauthorized", "AuthorizationRequired", "Forbidden", "BadRequest", "NotFound", "UpgradeRequired":
		return true
	}
	return false
}

type connectRequest struct {
	ClientVersion   int      `json:"client_version"`
	ClientName      string   `json:"client_name"`
	SDKVersion      string   `json:"sdk_version"`
	ForwardsTo      string   `json:"forwards_to"`
	Protocol        string   `json:"protocol"`
	Location        string   `json:"location"`
	Subdomain       string   `json:"subdomain"`
	Domain          string   `json:"domain"`
	Token           string   `json:"token"`
	OS              string   `json:"os"`
	Arch            string   `json:"arch"`
	PortOrAlias     string   `json:"port_or_alias"`
	TunnelSessionID *string  `json:"tunnel_session_id"`
	ProxyProtocol   int      `json:"proxy_protocol"`
	CidrAllowList   []string `json:"cidr_allow_list,omitempty"`
	CidrDenyList    []string `json:"cidr_deny_list,omitempty"`
}

type connectResponse struct {
	TunnelSessionID string `json:"tunnel_session_id"`
	Token           string `json:"token"`
	Address         string `json:"address"`
	Banner          string `json:"banner"`
	PublicURL       string `json:"public_url"`
	DomainName      string `json:"domain_name"`
	EndpointPort    uint32 `json:"endpoint_port"`
	HostKeys        []struct {
		Key string `json:"key"`
	} `json:"host_keys"`
}

func checkServerURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("tuna: invalid server URL: %w", err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("tuna: invalid server URL %q: want https://host", s)
	}
	return nil
}

func newHTTPClient(tlsConfig *tls.Config) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsConfig
	tr.DisableKeepAlives = true
	return &http.Client{
		Transport: tr,
		Timeout:   apiTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func postJSON(ctx context.Context, hc *http.Client, serverURL, path, userAgent string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(serverURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("tuna: invalid server URL: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		se := &ServerError{Status: resp.StatusCode}
		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			se.Message = fmt.Sprintf("server redirects to %q, check the server URL", resp.Header.Get("Location"))
		case json.Unmarshal(respBody, se) != nil || se.Message == "":
			se.Message = fmt.Sprintf("server responded with status %d", resp.StatusCode)
		}
		if sec, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && sec > 0 {
			se.RetryAfter = min(time.Duration(sec)*time.Second, maxRetryAfter)
		}
		return se
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(respBody, out)
}
