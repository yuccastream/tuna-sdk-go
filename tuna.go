// Package tuna opens tuna.am tunnels from Go code.
//
// Listen returns a net.Listener that receives connections arriving at the
// tunnel's public address. Forward proxies them to a local address.
//
// A tunnel survives network failures: it reconnects with backoff and keeps
// its public address. It ends on Close, cancellation of its context or a
// permanent error (see IsPermanent).
package tuna

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

const (
	// Version is the SDK version.
	Version = "0.1.0"
	// DefaultServerURL is the tuna.am API used when Options.ServerURL is empty.
	DefaultServerURL = "https://api.tuna.am"
)

const (
	clientVersion      = 2
	sshUser            = "tuna"
	dialTimeout        = 10 * time.Second
	eventsDrainTimeout = time.Second
	keepAliveRequest   = "keepalive@openssh.com"
	eventsCommand      = "events"
	minBackoff         = time.Second
	maxBackoff         = 15 * time.Second
)

var (
	keepAliveInterval = 5 * time.Second
	keepAliveTimeout  = 15 * time.Second
)

// Options configures a tunnel. Only Protocol is required.
type Options struct {
	// APIKey is a tuna.am API key with the tunnels:connect scope.
	// Defaults to the TUNA_API_KEY environment variable.
	APIKey string
	// Protocol is "http" or "tcp".
	Protocol string
	// Location is needed only for names and ports reserved in the legacy
	// "ru" or "nl" zones. Empty lets the server pick the zone.
	Location string
	// Subdomain is a reserved subdomain for HTTP tunnels.
	Subdomain string
	// Domain is a custom domain for HTTP tunnels.
	Domain string
	// Port is a reserved TCP port or its alias.
	Port string
	// ProxyProtocol enables the PROXY protocol header (1 or 2) for TCP tunnels.
	ProxyProtocol int
	// CIDRAllow lists client CIDRs allowed to reach a TCP tunnel.
	CIDRAllow []string
	// CIDRDeny lists client CIDRs rejected by a TCP tunnel.
	CIDRDeny []string
	// ServerURL is the tuna.am API address. Defaults to DefaultServerURL.
	ServerURL string
	// TLSConfig is used for connections to the API. Nil means the system roots.
	TLSConfig *tls.Config
	// ClientName is reported to the server. Defaults to "tuna-sdk-go/<Version>".
	ClientName string
	// ConnectTimeout limits how long Listen and Forward wait for the tunnel
	// to come up for the first time. Zero means no limit. Reconnects are not
	// limited.
	ConnectTimeout time.Duration
	// OnEvent receives tunnel events. Calls never overlap, but they come from
	// the tunnel's own goroutines, so OnEvent must return quickly. It may
	// call Tunnel.Close.
	OnEvent func(Event)
}

// EventType identifies the kind of an Event.
type EventType string

const (
	// EventConnected is sent once, when the tunnel comes up for the first time.
	EventConnected EventType = "connected"
	// EventReconnected is sent when the tunnel comes up again after a failure.
	EventReconnected EventType = "reconnected"
	// EventReconnecting is sent after a failed attempt or a lost connection,
	// before the next attempt.
	EventReconnecting EventType = "reconnecting"
	// EventBanner carries a server message for the user.
	EventBanner EventType = "banner"
	// EventSessionExpiring warns that the session time limit is near.
	EventSessionExpiring EventType = "session_expiring"
	// EventTerminated is sent when the server closes the tunnel for good.
	EventTerminated EventType = "terminated"
	// EventLocalError reports a failure to reach the local address in Forward.
	EventLocalError EventType = "local_error"
)

// Event describes a change in the tunnel state.
type Event struct {
	// Type is the kind of the event.
	Type EventType
	// URL is the public address, set for EventConnected and EventReconnected.
	URL string
	// Message is human-readable text, set for EventBanner and EventTerminated.
	Message string
	// Reason is the machine-readable cause, set for EventTerminated.
	Reason string
	// Err is the cause, set for EventReconnecting and EventLocalError.
	Err error
	// RetryIn is the delay before the next attempt, set for EventReconnecting.
	RetryIn time.Duration
	// ExpiresIn is the time left, set for EventSessionExpiring.
	ExpiresIn time.Duration
}

// TerminatedError means the server closed the tunnel for good.
type TerminatedError struct {
	// Reason is the machine-readable cause, e.g. "deleted" or "session_limit".
	Reason string
}

var terminateMessages = map[string]string{
	"deleted":       "tunnel was deleted",
	"suspended":     "tunnel was suspended",
	"session_limit": "session time limit reached",
	"session_ended": "client session ended",
	"reconnect":     "tunnel was taken over by another connection",
}

func (e *TerminatedError) Error() string { return "tuna: " + e.message() }

func (e *TerminatedError) message() string {
	if msg, ok := terminateMessages[e.Reason]; ok {
		return msg
	}
	return fmt.Sprintf("tunnel terminated by server (%s)", e.Reason)
}

// ErrKeepAliveTimeout means the node stopped answering keepalive requests.
var ErrKeepAliveTimeout = errors.New("tuna: keepalive timeout")

// IsPermanent reports whether retrying after err is pointless.
func IsPermanent(err error) bool {
	var se *ServerError
	var te *TerminatedError
	return errors.As(err, &te) || (errors.As(err, &se) && se.permanent())
}

// Tunnel is a net.Listener for connections to the tunnel's public address.
// It survives reconnects; Accept fails only after Close or a permanent error.
type Tunnel struct {
	o          Options
	forwardsTo string
	hc         *http.Client
	cancel     context.CancelFunc
	closeCtx   context.Context
	closeFn    context.CancelFunc
	conns      chan net.Conn
	url        atomic.Pointer[string]
	emitMu     sync.Mutex

	keepAliveInterval time.Duration
	keepAliveTimeout  time.Duration

	ready    chan struct{}
	done     chan struct{}
	doneOnce sync.Once
	err      error
	lastErr  error

	everUp      bool
	sessionID   string
	bannerShown bool
}

// Listen connects the tunnel and returns once it is up or a permanent error
// occurs.
//
// ctx bounds the whole life of the tunnel, not only the first connection:
// cancelling it closes the tunnel together with every accepted connection.
// Use Options.ConnectTimeout to limit the wait for the first connection. If
// ctx or ConnectTimeout ends before the tunnel comes up, the returned error
// wraps context.DeadlineExceeded or context.Canceled and the last failure.
func Listen(ctx context.Context, o Options) (*Tunnel, error) {
	return listen(ctx, o, "")
}

// Forward proxies tunnel connections to localAddr ("host:port" or
// "unix:///path.sock"). It blocks until a permanent error occurs or ctx is
// cancelled. Cancellation after the tunnel came up returns nil; before that
// Forward fails like Listen.
func Forward(ctx context.Context, o Options, localAddr string) error {
	t, err := listen(ctx, o, localAddr)
	if err != nil {
		return err
	}
	defer func() { _ = t.Close() }()
	for {
		c, err := t.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go t.pipe(c, localAddr)
	}
}

func listen(ctx context.Context, o Options, forwardsTo string) (*Tunnel, error) {
	if o.APIKey == "" {
		o.APIKey = os.Getenv("TUNA_API_KEY")
	}
	if o.APIKey == "" {
		return nil, errors.New("tuna: API key is required: set Options.APIKey or TUNA_API_KEY")
	}
	if o.Protocol != "http" && o.Protocol != "tcp" {
		return nil, fmt.Errorf("tuna: unsupported protocol %q", o.Protocol)
	}
	if o.ServerURL == "" {
		o.ServerURL = DefaultServerURL
	}
	if err := checkServerURL(o.ServerURL); err != nil {
		return nil, err
	}
	if o.ClientName == "" {
		o.ClientName = "tuna-sdk-go/" + Version
	}
	if strings.ContainsFunc(o.ClientName, unicode.IsControl) {
		return nil, errors.New("tuna: ClientName must not contain control characters")
	}

	runCtx, cancel := context.WithCancel(ctx)
	closeCtx, closeFn := context.WithCancel(context.Background())
	t := &Tunnel{
		o:          o,
		forwardsTo: forwardsTo,
		hc:         newHTTPClient(o.TLSConfig),
		cancel:     cancel,
		closeCtx:   closeCtx,
		closeFn:    closeFn,
		conns:      make(chan net.Conn),
		ready:      make(chan struct{}),
		done:       make(chan struct{}),

		keepAliveInterval: keepAliveInterval,
		keepAliveTimeout:  keepAliveTimeout,
	}
	go t.run(runCtx)
	var timeout <-chan time.Time
	if o.ConnectTimeout > 0 {
		timer := time.NewTimer(o.ConnectTimeout)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-t.ready:
		return t, nil
	case <-timeout:
		select {
		case <-t.ready:
			return t, nil
		default:
		}
		cancel()
		<-t.done
		return nil, t.startError(fmt.Errorf("tuna: tunnel did not come up within %s: %w", o.ConnectTimeout, context.DeadlineExceeded))
	case <-t.done:
		if err := ctx.Err(); err != nil {
			return nil, t.startError(fmt.Errorf("tuna: %w", err))
		}
		return nil, t.err
	}
}

func (t *Tunnel) startError(err error) error {
	if t.lastErr == nil {
		return err
	}
	return fmt.Errorf("%w (last attempt: %w)", err, t.lastErr)
}

// Accept waits for the next connection to the public address. Accepted
// connections support deadlines, so http.Server timeouts and Hijack work.
func (t *Tunnel) Accept() (net.Conn, error) {
	if t.closeCtx.Err() != nil {
		return nil, net.ErrClosed
	}
	select {
	case c := <-t.conns:
		return c, nil
	case <-t.closeCtx.Done():
		return nil, net.ErrClosed
	case <-t.done:
		return nil, t.err
	}
}

// Close stops accepting connections and reconnecting, like Close of any
// net.Listener, so http.Server.Shutdown lets in-flight requests finish.
// Connections accepted earlier keep working: the tunnel stays connected to
// the node until the last of them is closed. Cancel the context passed to
// Listen to cut them off as well. Close does not wait.
func (t *Tunnel) Close() error {
	t.closeFn()
	return nil
}

// Addr returns the public address as a net.Addr with network "tuna".
func (t *Tunnel) Addr() net.Addr { return tunnelAddr(t.URL()) }

// URL returns the current public address, e.g. https://name.tuna.am or tcp://ru.tuna.am:40000.
func (t *Tunnel) URL() string {
	if u := t.url.Load(); u != nil {
		return *u
	}
	return ""
}

type tunnelAddr string

func (a tunnelAddr) Network() string { return "tuna" }
func (a tunnelAddr) String() string  { return string(a) }

func (t *Tunnel) emit(e Event) {
	if t.o.OnEvent == nil {
		return
	}
	t.emitMu.Lock()
	defer t.emitMu.Unlock()
	t.o.OnEvent(e)
}

func (t *Tunnel) finish(err error) {
	t.doneOnce.Do(func() {
		t.err = err
		close(t.done)
		t.cancel()
	})
}

func (t *Tunnel) run(ctx context.Context) {
	backoff := minBackoff
	for {
		connected, err := t.session(ctx)
		if ctx.Err() != nil || t.closeCtx.Err() != nil {
			t.finish(net.ErrClosed)
			return
		}
		var se *ServerError
		if !t.everUp && errors.As(err, &se) {
			se.beforeFirstConnect = true
		}
		t.lastErr = err
		if IsPermanent(err) {
			var te *TerminatedError
			if errors.As(err, &te) {
				t.emit(Event{Type: EventTerminated, Reason: te.Reason, Message: te.message()})
			}
			t.finish(err)
			return
		}
		if connected {
			backoff = minBackoff
		}
		wait := retryDelay(backoff, err)
		t.emit(Event{Type: EventReconnecting, Err: err, RetryIn: wait})
		select {
		case <-ctx.Done():
			t.finish(net.ErrClosed)
			return
		case <-t.closeCtx.Done():
			t.finish(net.ErrClosed)
			return
		case <-time.After(wait):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func retryDelay(backoff time.Duration, err error) time.Duration {
	wait := min(maxBackoff, minBackoff+rand.N(backoff))
	var se *ServerError
	if errors.As(err, &se) && se.RetryAfter > wait {
		wait = se.RetryAfter
	}
	return wait
}

func (t *Tunnel) session(ctx context.Context) (connected bool, err error) {
	setupCtx, cancelSetup := context.WithCancel(ctx)
	defer cancelSetup()
	stopSetup := context.AfterFunc(t.closeCtx, cancelSetup)
	defer stopSetup()

	sessionID := t.sessionID
	var cr connectResponse
	err = postJSON(setupCtx, t.hc, t.o.ServerURL, "/v1/connect", t.o.ClientName, connectRequest{
		ClientVersion:   clientVersion,
		ClientName:      t.o.ClientName,
		SDKVersion:      Version,
		ForwardsTo:      t.forwardsTo,
		Protocol:        t.o.Protocol,
		Location:        t.o.Location,
		Subdomain:       t.o.Subdomain,
		Domain:          t.o.Domain,
		Token:           t.o.APIKey,
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		PortOrAlias:     t.o.Port,
		TunnelSessionID: &sessionID,
		ProxyProtocol:   t.o.ProxyProtocol,
		CidrAllowList:   t.o.CIDRAllow,
		CidrDenyList:    t.o.CIDRDeny,
	}, &cr)
	if err != nil {
		return false, err
	}
	t.sessionID = cr.TunnelSessionID
	if cr.Banner != "" && !t.bannerShown {
		t.bannerShown = true
		t.emit(Event{Type: EventBanner, Message: cr.Banner})
	}

	conn, chans, reqs, err := dial(setupCtx, &cr)
	if err != nil {
		return false, err
	}
	client := ssh.NewClient(conn, chans, reqs)

	dead := make(chan struct{})
	var (
		failOnce sync.Once
		failErr  error
	)
	fail := func(err error) {
		failOnce.Do(func() {
			failErr = err
			close(dead)
			_ = client.Close()
		})
	}
	stop := context.AfterFunc(ctx, func() { fail(ctx.Err()) })
	defer stop()
	defer fail(nil)

	go keepAlive(client, t.keepAliveInterval, t.keepAliveTimeout, dead, fail)

	var (
		activeMu sync.Mutex
		active   int
		closing  bool
	)
	release := func() {
		activeMu.Lock()
		active--
		idle := closing && active == 0
		activeMu.Unlock()
		if idle {
			fail(net.ErrClosed)
		}
	}
	go func() {
		select {
		case <-t.closeCtx.Done():
		case <-dead:
			return
		}
		activeMu.Lock()
		closing = true
		idle := active == 0
		activeMu.Unlock()
		if idle {
			fail(net.ErrClosed)
		}
	}()

	ln, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		select {
		case <-dead:
			return false, failErr
		default:
		}
		return false, fmt.Errorf("tuna: remote forward: %w", err)
	}

	eventsDone := make(chan struct{})
	go func() {
		defer close(eventsDone)
		t.events(client, fail)
	}()

	url := cr.publicURL(t.o.Protocol)
	t.url.Store(&url)
	if t.everUp {
		t.emit(Event{Type: EventReconnected, URL: url})
	} else {
		t.everUp = true
		t.emit(Event{Type: EventConnected, URL: url})
		close(t.ready)
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-eventsDone:
			case <-time.After(eventsDrainTimeout):
			}
			fail(fmt.Errorf("tuna: connection to node lost: %w", err))
			return true, failErr
		}
		activeMu.Lock()
		if closing {
			activeMu.Unlock()
			_ = c.Close()
			continue
		}
		active++
		activeMu.Unlock()
		var tc net.Conn = &trackedConn{Conn: c, release: release}
		if t.forwardsTo == "" {
			tc = bridge(tc)
		}
		select {
		case t.conns <- tc:
		case <-dead:
			_ = tc.Close()
		case <-t.closeCtx.Done():
			_ = tc.Close()
		}
	}
}

type trackedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

type bridgedConn struct {
	net.Conn
	local, remote net.Addr
}

func (c *bridgedConn) LocalAddr() net.Addr  { return c.local }
func (c *bridgedConn) RemoteAddr() net.Addr { return c.remote }

func bridge(c net.Conn) net.Conn {
	app, side := net.Pipe()
	go func() { _, _ = io.Copy(side, c); _ = side.Close() }()
	go func() { _, _ = io.Copy(c, side); _ = c.Close() }()
	return &bridgedConn{Conn: app, local: c.LocalAddr(), remote: c.RemoteAddr()}
}

func (cr *connectResponse) publicURL(protocol string) string {
	if cr.PublicURL != "" {
		return cr.PublicURL
	}
	if protocol == "tcp" {
		return fmt.Sprintf("tcp://%s:%d", cr.DomainName, cr.EndpointPort)
	}
	return "https://" + cr.DomainName
}

func dial(ctx context.Context, cr *connectResponse) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	var keys [][]byte
	for _, hk := range cr.HostKeys {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hk.Key))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("tuna: parse host key: %w", err)
		}
		keys = append(keys, k.Marshal())
	}
	cfg := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{ssh.Password(cr.Token)},
		HostKeyCallback: func(host string, _ net.Addr, key ssh.PublicKey) error {
			got := key.Marshal()
			for _, k := range keys {
				if string(k) == string(got) {
					return nil
				}
			}
			return fmt.Errorf("tuna: host key verification failed for %s", host)
		},
	}

	d := net.Dialer{Timeout: dialTimeout}
	nc, err := d.DialContext(ctx, "tcp", cr.Address)
	if err != nil {
		return nil, nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
	defer stop()
	_ = nc.SetDeadline(time.Now().Add(dialTimeout))
	conn, chans, reqs, err := ssh.NewClientConn(nc, cr.Address, cfg)
	if err != nil {
		_ = nc.Close()
		return nil, nil, nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	return conn, chans, reqs, nil
}

type nodeEvent struct {
	Type      string `json:"type"`
	Reason    string `json:"reason"`
	ExpiresIn int64  `json:"expires_in"`
}

func (t *Tunnel) events(client *ssh.Client, fail func(error)) {
	s, err := client.NewSession()
	if err != nil {
		return
	}
	defer func() { _ = s.Close() }()
	out, err := s.StdoutPipe()
	if err != nil {
		return
	}
	if err := s.Start(eventsCommand); err != nil {
		return
	}
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		var ev nodeEvent
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		switch ev.Type {
		case "terminate":
			fail(&TerminatedError{Reason: ev.Reason})
			return
		case "session_expiring":
			t.emit(Event{Type: EventSessionExpiring, ExpiresIn: time.Duration(ev.ExpiresIn) * time.Second})
		}
	}
}

func keepAlive(client *ssh.Client, interval, timeout time.Duration, dead <-chan struct{}, fail func(error)) {
	lastReply := time.Now()
	for {
		select {
		case <-time.After(interval):
		case <-dead:
			return
		}
		res := make(chan error, 1)
		go func() {
			_, _, err := client.SendRequest(keepAliveRequest, true, nil)
			res <- err
		}()
		select {
		case err := <-res:
			if err != nil {
				fail(err)
				return
			}
			lastReply = time.Now()
		case <-time.After(timeout - time.Since(lastReply)):
			fail(ErrKeepAliveTimeout)
			return
		case <-dead:
			return
		}
	}
}

func (t *Tunnel) pipe(remote net.Conn, localAddr string) {
	defer func() { _ = remote.Close() }()
	network, addr := "tcp", localAddr
	if p, ok := strings.CutPrefix(addr, "unix://"); ok {
		network, addr = "unix", p
	}
	local, err := net.DialTimeout(network, addr, dialTimeout)
	if err != nil {
		t.emit(Event{Type: EventLocalError, Err: err})
		return
	}
	defer func() { _ = local.Close() }()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(local, remote); done <- struct{}{} }()
	go func() { _, _ = io.Copy(remote, local); done <- struct{}{} }()
	<-done
}
