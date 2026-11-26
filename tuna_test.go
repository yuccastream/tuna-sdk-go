package tuna

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type nodeSession struct {
	conn   ssh.Conn
	port   uint32
	events chan ssh.Channel
}

func (s *nodeSession) open(t *testing.T) ssh.Channel {
	t.Helper()
	payload := ssh.Marshal(struct {
		Addr       string
		Port       uint32
		OriginAddr string
		OriginPort uint32
	}{"127.0.0.1", s.port, "203.0.113.1", 5555})
	ch, reqs, err := s.conn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		t.Fatalf("open forwarded-tcpip: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	return ch
}

func (s *nodeSession) eventsChannel(t *testing.T) ssh.Channel {
	t.Helper()
	select {
	case ch := <-s.events:
		return ch
	case <-time.After(5 * time.Second):
		t.Fatal("events channel was not opened")
		return nil
	}
}

type fakeNode struct {
	ln              net.Listener
	cfg             *ssh.ServerConfig
	authorizedKey   string
	sessions        chan *nodeSession
	noEvents        bool
	silentKeepalive bool
	silent          bool
}

func newFakeNode(t *testing.T) *fakeNode {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	n := &fakeNode{
		cfg: &ssh.ServerConfig{
			PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
				if c.User() != sshUser || string(pw) != "node-token" {
					return nil, errors.New("denied")
				}
				return nil, nil
			},
		},
		authorizedKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
		sessions:      make(chan *nodeSession, 10),
	}
	n.cfg.AddHostKey(signer)
	n.ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.ln.Close() })
	go func() {
		for {
			nc, err := n.ln.Accept()
			if err != nil {
				return
			}
			go n.serve(nc)
		}
	}()
	return n
}

func (n *fakeNode) serve(nc net.Conn) {
	conn, chans, reqs, err := ssh.NewServerConn(nc, n.cfg)
	if err != nil {
		_ = nc.Close()
		return
	}
	s := &nodeSession{conn: conn, port: 40000, events: make(chan ssh.Channel, 1)}
	go func() {
		for nch := range chans {
			if n.noEvents {
				continue
			}
			ch, creqs, err := nch.Accept()
			if err != nil {
				continue
			}
			go func() {
				for r := range creqs {
					if r.Type == "exec" && execCommand(r.Payload) == eventsCommand {
						_ = r.Reply(true, nil)
						s.events <- ch
						continue
					}
					_ = r.Reply(false, nil)
				}
			}()
		}
	}()
	for req := range reqs {
		switch {
		case n.silent:
		case req.Type == "tcpip-forward":
			_ = req.Reply(true, ssh.Marshal(struct{ Port uint32 }{s.port}))
			n.sessions <- s
		case strings.HasPrefix(req.Type, "keepalive@"):
			if !n.silentKeepalive {
				_ = req.Reply(true, nil)
			}
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func execCommand(payload []byte) string {
	var msg struct{ Command string }
	if ssh.Unmarshal(payload, &msg) != nil {
		return ""
	}
	return msg.Command
}

type apiReply struct {
	status     int
	retryAfter string
	body       string
}

type fakeAPI struct {
	srv     *httptest.Server
	mu      sync.Mutex
	reqs    []connectRequest
	replies []apiReply
}

func connectBody(address, hostKey string) string {
	body, _ := json.Marshal(map[string]any{
		"tunnel_session_id": "s1",
		"token":             "node-token",
		"address":           address,
		"banner":            "welcome",
		"public_url":        "https://demo.tuna.am",
		"domain_name":       "demo.tuna.am",
		"host_keys":         []map[string]string{{"key": hostKey}},
	})
	return string(body)
}

func newFakeAPI(t *testing.T, node *fakeNode, replies ...apiReply) *fakeAPI {
	t.Helper()
	a := &fakeAPI{replies: replies}
	ok := connectBody(node.ln.Addr().String(), node.authorizedKey)
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/connect" {
			return
		}
		var req connectRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		a.mu.Lock()
		a.reqs = append(a.reqs, req)
		reply := apiReply{status: http.StatusOK, body: ok}
		if len(a.replies) > 0 {
			reply, a.replies = a.replies[0], a.replies[1:]
		}
		a.mu.Unlock()
		if reply.retryAfter != "" {
			w.Header().Set("Retry-After", reply.retryAfter)
		}
		w.WriteHeader(reply.status)
		_, _ = io.WriteString(w, reply.body)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *fakeAPI) requests() []connectRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]connectRequest(nil), a.reqs...)
}

type recorder struct {
	ch chan Event
}

func newRecorder() *recorder { return &recorder{ch: make(chan Event, 100)} }

func (r *recorder) on(e Event) { r.ch <- e }

func (r *recorder) waitAny(t *testing.T, types ...EventType) Event {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case e := <-r.ch:
			if slices.Contains(types, e.Type) {
				return e
			}
		case <-timeout:
			t.Fatalf("none of %v events", types)
		}
	}
}

func (r *recorder) wait(t *testing.T, typ EventType) Event {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case e := <-r.ch:
			if e.Type == typ {
				return e
			}
		case <-timeout:
			t.Fatalf("no %s event", typ)
		}
	}
}

func testOptions(api *fakeAPI, rec *recorder) Options {
	return Options{
		APIKey:    "key",
		Protocol:  "http",
		ServerURL: api.srv.URL,
		OnEvent:   rec.on,
	}
}

func roundTrip(t *testing.T, node ssh.Channel, local net.Conn) {
	t.Helper()
	if _, err := node.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(local, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("read %q: %v", buf, err)
	}
}

func TestListenReconnectsWithSession(t *testing.T) {
	node := newFakeNode(t)
	api := newFakeAPI(t, node)
	rec := newRecorder()

	var banners atomic.Int32
	o := testOptions(api, rec)
	o.OnEvent = func(e Event) {
		if e.Type == EventBanner {
			banners.Add(1)
		}
		rec.on(e)
	}
	tun, err := Listen(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tun.Close() }()
	if tun.URL() != "https://demo.tuna.am" {
		t.Fatalf("url %q", tun.URL())
	}

	s := <-node.sessions
	ch := s.open(t)
	c, err := tun.Accept()
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, ch, c)

	_ = s.conn.Close()
	if e := rec.wait(t, EventReconnecting); e.Err == nil || !strings.Contains(e.Err.Error(), "connection to node lost") {
		t.Fatalf("reconnecting err %v", e.Err)
	}
	rec.wait(t, EventReconnected)

	reqs := api.requests()
	if len(reqs) != 2 {
		t.Fatalf("%d connect requests", len(reqs))
	}
	if reqs[0].TunnelSessionID == nil || *reqs[0].TunnelSessionID != "" {
		t.Fatalf("first request must send empty tunnel_session_id, got %v", reqs[0].TunnelSessionID)
	}
	if reqs[1].TunnelSessionID == nil || *reqs[1].TunnelSessionID != "s1" {
		t.Fatalf("retry must send tunnel_session_id s1, got %v", reqs[1].TunnelSessionID)
	}
	if reqs[0].Token != "key" || reqs[0].ClientName != "tuna-sdk-go/"+Version || reqs[0].SDKVersion != Version || reqs[0].Location != "" {
		t.Fatalf("request %+v", reqs[0])
	}
	if n := banners.Load(); n != 1 {
		t.Fatalf("banner shown %d times", n)
	}

	s2 := <-node.sessions
	ch2 := s2.open(t)
	c2, err := tun.Accept()
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, ch2, c2)
}

func TestTerminateEvent(t *testing.T) {
	node := newFakeNode(t)
	api := newFakeAPI(t, node)
	rec := newRecorder()

	tun, err := Listen(context.Background(), testOptions(api, rec))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tun.Close() }()

	events := (<-node.sessions).eventsChannel(t)
	_, _ = io.WriteString(events, `{"type":"unknown"}`+"\n"+`{"type":"session_expiring","expires_in":300}`+"\n"+`{"type":"terminate","reason":"deleted"}`+"\n")

	if e := rec.wait(t, EventSessionExpiring); e.ExpiresIn != 300*time.Second {
		t.Fatalf("expires_in %s", e.ExpiresIn)
	}
	if e := rec.wait(t, EventTerminated); e.Reason != "deleted" {
		t.Fatalf("reason %q", e.Reason)
	}
	var te *TerminatedError
	if _, err := tun.Accept(); !errors.As(err, &te) || te.Reason != "deleted" || !IsPermanent(err) {
		t.Fatalf("accept: %v", err)
	}
	if n := len(api.requests()); n != 1 {
		t.Fatalf("terminate must not reconnect, %d requests", n)
	}
}

func TestPermanentError(t *testing.T) {
	node := newFakeNode(t)
	api := newFakeAPI(t, node, apiReply{
		status: http.StatusForbidden,
		body:   `{"code":"Forbidden","error":"This key cannot start tunnels"}`,
	})

	_, err := Listen(context.Background(), testOptions(api, newRecorder()))
	var se *ServerError
	if !errors.As(err, &se) || se.Code != "Forbidden" || !IsPermanent(err) {
		t.Fatalf("err %v", err)
	}
	if n := len(api.requests()); n != 1 {
		t.Fatalf("%d requests", n)
	}
}

func TestRetryAfter(t *testing.T) {
	node := newFakeNode(t)
	api := newFakeAPI(t, node, apiReply{
		status:     http.StatusServiceUnavailable,
		retryAfter: "2",
		body:       `{"code":"ServiceUnavailable","error":"no nodes"}`,
	})
	rec := newRecorder()

	start := time.Now()
	tun, err := Listen(context.Background(), testOptions(api, rec))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tun.Close() }()
	if e := rec.wait(t, EventReconnecting); e.RetryIn < 2*time.Second {
		t.Fatalf("retry in %s", e.RetryIn)
	}
	if elapsed := time.Since(start); elapsed < 2*time.Second {
		t.Fatalf("retried after %s", elapsed)
	}
}

func TestNodeWithoutEventsChannel(t *testing.T) {
	node := newFakeNode(t)
	node.noEvents = true
	api := newFakeAPI(t, node)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tun, err := Listen(ctx, testOptions(api, newRecorder()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tun.Close() }()

	ch := (<-node.sessions).open(t)
	c, err := tun.Accept()
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, ch, c)
}

func TestKeepAliveTimeout(t *testing.T) {
	interval, timeout := keepAliveInterval, keepAliveTimeout
	keepAliveInterval, keepAliveTimeout = 50*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { keepAliveInterval, keepAliveTimeout = interval, timeout })

	node := newFakeNode(t)
	node.silentKeepalive = true
	api := newFakeAPI(t, node)
	rec := newRecorder()

	tun, err := Listen(context.Background(), testOptions(api, rec))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tun.Close() }()
	if e := rec.wait(t, EventReconnecting); !errors.Is(e.Err, ErrKeepAliveTimeout) {
		t.Fatalf("err %v", e.Err)
	}
}

func TestForward(t *testing.T) {
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = local.Close() }()
	go func() {
		for {
			c, err := local.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()

	node := newFakeNode(t)
	api := newFakeAPI(t, node)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	rec := newRecorder()
	go func() { done <- Forward(ctx, testOptions(api, rec), local.Addr().String()) }()

	s := <-node.sessions
	rec.wait(t, EventConnected)
	ch := s.open(t)
	if _, err := ch.Write([]byte("echo")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(ch, buf); err != nil || string(buf) != "echo" {
		t.Fatalf("read %q: %v", buf, err)
	}
	if forwardsTo := api.requests()[0].ForwardsTo; forwardsTo != local.Addr().String() {
		t.Fatalf("forwards_to %q", forwardsTo)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("forward: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forward did not stop")
	}
}

func TestListenRequiresAPIKey(t *testing.T) {
	t.Setenv("TUNA_API_KEY", "")
	if _, err := Listen(context.Background(), Options{Protocol: "http"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestTerminateWinsOverDisconnect(t *testing.T) {
	for range 30 {
		node := newFakeNode(t)
		api := newFakeAPI(t, node)
		rec := newRecorder()
		tun, err := Listen(context.Background(), testOptions(api, rec))
		if err != nil {
			t.Fatal(err)
		}
		s := <-node.sessions
		_, _ = io.WriteString(s.eventsChannel(t), `{"type":"terminate","reason":"deleted"}`+"\n")
		_ = s.conn.Close()
		if e := rec.waitAny(t, EventTerminated, EventReconnecting); e.Type != EventTerminated {
			t.Fatalf("terminate followed by disconnect led to %s: %v", e.Type, e.Err)
		}
		_ = tun.Close()
	}
}

func TestInvalidServerURL(t *testing.T) {
	for _, u := range []string{"api.tuna.am", "ftp://api.tuna.am", "://bad", "https://"} {
		_, err := Listen(context.Background(), Options{APIKey: "k", Protocol: "http", ServerURL: u})
		if err == nil || !strings.Contains(err.Error(), "server URL") {
			t.Fatalf("%q: err %v", u, err)
		}
	}
}

func TestRedirectIsPermanent(t *testing.T) {
	node := newFakeNode(t)
	api := newFakeAPI(t, node, apiReply{status: http.StatusMovedPermanently})
	_, err := Listen(context.Background(), testOptions(api, newRecorder()))
	if !IsPermanent(err) {
		t.Fatalf("err %v", err)
	}
	if n := len(api.requests()); n != 1 {
		t.Fatalf("%d requests", n)
	}
}

func TestListenDeadlineReportsLastError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err = Listen(ctx, Options{APIKey: "k", Protocol: "http", ServerURL: "http://" + addr})
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("err %v", err)
	}
}

func TestCancelDuringHandshake(t *testing.T) {
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
		}
	}()
	node := newFakeNode(t)
	api := newFakeAPI(t, node, apiReply{status: http.StatusOK, body: connectBody(silent.Addr().String(), node.authorizedKey)})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Listen(ctx, testOptions(api, newRecorder())); err == nil {
		t.Fatal("expected error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Listen returned %s after cancellation", elapsed)
	}
}

func TestHostKeyMismatch(t *testing.T) {
	node := newFakeNode(t)
	other := newFakeNode(t)
	api := newFakeAPI(t, node, apiReply{status: http.StatusOK, body: connectBody(node.ln.Addr().String(), other.authorizedKey)})
	rec := newRecorder()
	tun, err := Listen(context.Background(), testOptions(api, rec))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tun.Close() }()
	if e := rec.wait(t, EventReconnecting); e.Err == nil || !strings.Contains(e.Err.Error(), "host key verification failed") {
		t.Fatalf("err %v", e.Err)
	}
}

func TestEventsDoNotOverlap(t *testing.T) {
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	_ = dead.Close()

	node := newFakeNode(t)
	api := newFakeAPI(t, node)
	var inside, overlaps, localErrors atomic.Int32
	connected := make(chan struct{}, 1)
	o := testOptions(api, newRecorder())
	o.OnEvent = func(e Event) {
		if inside.Add(1) > 1 {
			overlaps.Add(1)
		}
		defer inside.Add(-1)
		switch e.Type {
		case EventConnected:
			connected <- struct{}{}
		case EventLocalError:
			localErrors.Add(1)
			time.Sleep(20 * time.Millisecond)
		}
	}
	ctx := t.Context()
	go func() { _ = Forward(ctx, o, deadAddr) }()
	s := <-node.sessions
	<-connected
	for range 5 {
		s.open(t)
	}
	deadline := time.Now().Add(5 * time.Second)
	for localErrors.Load() < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if localErrors.Load() != 5 || overlaps.Load() != 0 {
		t.Fatalf("local errors %d, overlapping calls %d", localErrors.Load(), overlaps.Load())
	}
}

func TestCloseFromOnEvent(t *testing.T) {
	node := newFakeNode(t)
	api := newFakeAPI(t, node)
	var tun atomic.Pointer[Tunnel]
	closed := make(chan struct{})
	o := testOptions(api, newRecorder())
	o.OnEvent = func(e Event) {
		if e.Type == EventReconnecting {
			_ = tun.Load().Close()
			close(closed)
		}
	}
	tn, err := Listen(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	tun.Store(tn)
	_ = (<-node.sessions).conn.Close()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close called from OnEvent did not return")
	}
	if _, err := tn.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("accept: %v", err)
	}
}

func TestRetryDelay(t *testing.T) {
	first := map[time.Duration]bool{}
	for range 100 {
		d := retryDelay(minBackoff, nil)
		if d < minBackoff || d > 2*minBackoff {
			t.Fatalf("first delay %s", d)
		}
		first[d] = true
		if d := retryDelay(maxBackoff, nil); d < minBackoff || d > maxBackoff {
			t.Fatalf("max delay %s", d)
		}
	}
	if len(first) < 2 {
		t.Fatal("first delay has no jitter")
	}
	if d := retryDelay(minBackoff, &ServerError{RetryAfter: time.Minute}); d != time.Minute {
		t.Fatalf("retry-after delay %s", d)
	}
}

func TestPublicURLFallback(t *testing.T) {
	cr := connectResponse{DomainName: "ru.tuna.am", EndpointPort: 40000}
	if u := cr.publicURL("tcp"); u != "tcp://ru.tuna.am:40000" {
		t.Fatal(u)
	}
	cr.DomainName = "demo.tuna.am"
	if u := cr.publicURL("http"); u != "https://demo.tuna.am" {
		t.Fatal(u)
	}
}

func TestForwardUnix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "echo.sock")
	local, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = local.Close() }()
	go func() {
		c, err := local.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(c, c)
		_ = c.Close()
	}()

	node := newFakeNode(t)
	api := newFakeAPI(t, node)
	rec := newRecorder()
	ctx := t.Context()
	go func() { _ = Forward(ctx, testOptions(api, rec), "unix://"+path) }()

	s := <-node.sessions
	rec.wait(t, EventConnected)
	ch := s.open(t)
	if _, err := ch.Write([]byte("unix")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(ch, buf); err != nil || string(buf) != "unix" {
		t.Fatalf("read %q: %v", buf, err)
	}
}

func serveTunnel(t *testing.T, srv *http.Server) *nodeSession {
	t.Helper()
	node := newFakeNode(t)
	api := newFakeAPI(t, node)
	tun, err := Listen(t.Context(), testOptions(api, newRecorder()))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(tun) }()
	t.Cleanup(func() { _ = srv.Close() })
	return <-node.sessions
}

func within[T any](t *testing.T, d time.Duration, f func() T) T {
	t.Helper()
	res := make(chan T, 1)
	go func() { res <- f() }()
	select {
	case v := <-res:
		return v
	case <-time.After(d):
		t.Fatalf("no result within %s", d)
		var zero T
		return zero
	}
}

func readResponse(ch io.Reader) string {
	resp, err := http.ReadResponse(bufio.NewReader(ch), nil)
	if err != nil {
		return err.Error()
	}
	body, _ := io.ReadAll(resp.Body)
	return resp.Status + " " + string(body)
}

func TestListenHijack(t *testing.T) {
	s := serveTunnel(t, &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = c.Close()
	})})
	ch := s.open(t)
	_, _ = io.WriteString(ch, "GET /ws HTTP/1.1\r\nHost: demo.tuna.am\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	if got := within(t, time.Second, func() string { return readResponse(ch) }); !strings.HasPrefix(got, "101") {
		t.Fatalf("response %q", got)
	}
}

func TestListenReadHeaderTimeout(t *testing.T) {
	s := serveTunnel(t, &http.Server{
		Handler:           http.NotFoundHandler(),
		ReadHeaderTimeout: 200 * time.Millisecond,
	})
	ch := s.open(t)
	_, _ = io.WriteString(ch, "GET / HTTP/1.1\r\nHost: demo")
	within(t, time.Second, func() error { _, err := io.ReadAll(ch); return err })
}

func TestListenRemoteAddr(t *testing.T) {
	got := make(chan string, 1)
	s := serveTunnel(t, &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.RemoteAddr
	})})
	ch := s.open(t)
	_, _ = io.WriteString(ch, "GET / HTTP/1.1\r\nHost: demo.tuna.am\r\n\r\n")
	if addr := within(t, time.Second, func() string { return <-got }); addr != "203.0.113.1:5555" {
		t.Fatalf("remote addr %q", addr)
	}
}

func TestShutdownFinishesInFlight(t *testing.T) {
	node := newFakeNode(t)
	api := newFakeAPI(t, node)
	rec := newRecorder()
	tun, err := Listen(t.Context(), testOptions(api, rec))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_, _ = io.WriteString(w, "done")
	})}
	go func() { _ = srv.Serve(tun) }()

	s := <-node.sessions
	ch := s.open(t)
	_, _ = io.WriteString(ch, "GET / HTTP/1.1\r\nHost: demo.tuna.am\r\n\r\n")
	time.Sleep(100 * time.Millisecond)
	shutdown := make(chan error, 1)
	go func() { shutdown <- srv.Shutdown(context.Background()) }()

	if got := within(t, 2*time.Second, func() string { return readResponse(ch) }); got != "200 OK done" {
		t.Fatalf("response %q", got)
	}
	if err := within(t, 2*time.Second, func() error { return <-shutdown }); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	within(t, 2*time.Second, func() error { return s.conn.Wait() })
	if _, err := tun.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("accept after close: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(api.requests()); n != 1 {
		t.Fatalf("closed tunnel reconnected: %d requests", n)
	}
	select {
	case e := <-rec.ch:
		if e.Type == EventReconnecting {
			t.Fatalf("closed tunnel emitted %s: %v", e.Type, e.Err)
		}
	default:
	}
}

func TestCloseRejectsNewConnections(t *testing.T) {
	node := newFakeNode(t)
	api := newFakeAPI(t, node)
	tun, err := Listen(t.Context(), testOptions(api, newRecorder()))
	if err != nil {
		t.Fatal(err)
	}
	s := <-node.sessions
	ch := s.open(t)
	c, err := tun.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = tun.Close()

	late := s.open(t)
	within(t, time.Second, func() error { _, err := io.ReadAll(late); return err })
	roundTrip(t, ch, c)

	_ = c.Close()
	within(t, 2*time.Second, func() error { return s.conn.Wait() })
}

func TestSilentNodeIsSkipped(t *testing.T) {
	interval, timeout := keepAliveInterval, keepAliveTimeout
	keepAliveInterval, keepAliveTimeout = 50*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { keepAliveInterval, keepAliveTimeout = interval, timeout })

	silent := newFakeNode(t)
	silent.silent = true
	node := newFakeNode(t)
	api := newFakeAPI(t, node, apiReply{status: http.StatusOK, body: connectBody(silent.ln.Addr().String(), silent.authorizedKey)})
	rec := newRecorder()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tun, err := Listen(ctx, testOptions(api, rec))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tun.Close() }()
	if e := rec.waitAny(t, EventReconnecting, EventConnected); e.Type != EventReconnecting || !errors.Is(e.Err, ErrKeepAliveTimeout) {
		t.Fatalf("first event %s: %v", e.Type, e.Err)
	}
	if n := len(api.requests()); n != 2 {
		t.Fatalf("%d connect requests", n)
	}
}

func TestNonJSONNotFound(t *testing.T) {
	node := newFakeNode(t)
	api := newFakeAPI(t, node, apiReply{status: http.StatusNotFound, body: "<html>not found</html>"})
	_, err := Listen(context.Background(), testOptions(api, newRecorder()))
	if !IsPermanent(err) {
		t.Fatalf("err %v", err)
	}
	if n := len(api.requests()); n != 1 {
		t.Fatalf("%d requests", n)
	}
}

func TestNonJSONNotFoundAfterConnect(t *testing.T) {
	node := newFakeNode(t)
	ok := connectBody(node.ln.Addr().String(), node.authorizedKey)
	api := newFakeAPI(t, node,
		apiReply{status: http.StatusOK, body: ok},
		apiReply{status: http.StatusNotFound, body: "<html>not found</html>"},
	)
	rec := newRecorder()
	tun, err := Listen(t.Context(), testOptions(api, rec))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tun.Close() }()
	_ = (<-node.sessions).conn.Close()
	rec.wait(t, EventReconnecting)
	var se *ServerError
	if e := rec.wait(t, EventReconnecting); !errors.As(e.Err, &se) || se.Status != http.StatusNotFound || IsPermanent(e.Err) {
		t.Fatalf("err %v", e.Err)
	}
	rec.wait(t, EventReconnected)
}

func TestClientNameControlCharacters(t *testing.T) {
	_, err := Listen(context.Background(), Options{APIKey: "k", Protocol: "http", ClientName: "x\r\nX-Evil: 1"})
	if err == nil || !strings.Contains(err.Error(), "control characters") {
		t.Fatalf("err %v", err)
	}
}

func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestForwardDeadlineBeforeConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := Forward(ctx, Options{APIKey: "k", Protocol: "http", ServerURL: "http://" + closedAddr(t)}, "127.0.0.1:1")
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("err %v", err)
	}
}

func TestConnectTimeout(t *testing.T) {
	start := time.Now()
	_, err := Listen(context.Background(), Options{
		APIKey:         "k",
		Protocol:       "http",
		ServerURL:      "http://" + closedAddr(t),
		ConnectTimeout: 300 * time.Millisecond,
	})
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("err %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("returned after %s", elapsed)
	}
}

func TestNoGoroutineLeaks(t *testing.T) {
	node := newFakeNode(t)
	api := newFakeAPI(t, node)
	before := runtime.NumGoroutine()

	tun, err := Listen(context.Background(), testOptions(api, newRecorder()))
	if err != nil {
		t.Fatal(err)
	}
	s := <-node.sessions
	ch := s.open(t)
	c, err := tun.Accept()
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, ch, c)
	_ = c.Close()
	_ = tun.Close()

	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		buf := make([]byte, 1<<16)
		t.Fatalf("%d goroutines, %d before\n%s", n, before, buf[:runtime.Stack(buf, true)])
	}
}
