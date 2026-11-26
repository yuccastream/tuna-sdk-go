# tuna-sdk-go

[![Go Reference](https://pkg.go.dev/badge/github.com/yuccastream/tuna-sdk-go.svg)](https://pkg.go.dev/github.com/yuccastream/tuna-sdk-go)

Open [tuna.am](https://tuna.am) tunnels straight from Go code: expose a local
HTTP or TCP service at a public address without installing the `tuna` CLI.

- Two ways in: `Listen` returns a `net.Listener` for your own server,
  `Forward` proxies connections to a local address.
- Survives network failures: reconnects with backoff and keeps the same
  public address.
- Small: only the standard library and `golang.org/x/crypto/ssh`.

The API is not stable yet: it may change before v1.

## Install

```shell
go get github.com/yuccastream/tuna-sdk-go
```

The package name is `tuna`. Requires Go 1.26 or later.

## Authentication

Create an API key with the `tunnels:connect` scope at
[my.tuna.am](https://my.tuna.am) and pass it in `Options.APIKey` or the
`TUNA_API_KEY` environment variable.

## Serve HTTP without a local port

```go
ln, err := tuna.Listen(ctx, tuna.Options{Protocol: "http"})
if err != nil {
	return err
}
defer ln.Close()

fmt.Println("public URL:", ln.URL())
return http.Serve(ln, handler)
```

`Close` works like on any `net.Listener`: `http.Server.Shutdown` lets
in-flight requests finish before the tunnel disconnects.

## Forward to a local service

```go
err := tuna.Forward(ctx, tuna.Options{
	Protocol: "tcp",
	Port:     "my-db",
	OnEvent: func(e tuna.Event) {
		if e.Type == tuna.EventConnected {
			log.Printf("forwarding %s -> 127.0.0.1:5432", e.URL)
		}
	},
}, "127.0.0.1:5432")
```

The local address is `host:port` or `unix:///path/to.sock`. `Forward` blocks
until `ctx` is cancelled or the tunnel ends for good.

## Options

| Field | Meaning |
|---|---|
| `Protocol` | `http` or `tcp`, required |
| `APIKey` | API key, defaults to `$TUNA_API_KEY` |
| `Subdomain`, `Domain` | reserved subdomain or custom domain for HTTP |
| `Port` | reserved TCP port or its alias |
| `ProxyProtocol` | PROXY protocol header version for TCP: `1` or `2` |
| `CIDRAllow`, `CIDRDeny` | client CIDRs filtered by the tuna.am node, TCP only |
| `Location` | only for names and ports reserved in the legacy `ru` or `nl` zones; empty lets the server pick |
| `OnEvent` | callback for tunnel events |
| `ConnectTimeout` | limit on the wait for the first connection; zero means no limit |
| `ServerURL`, `TLSConfig`, `ClientName` | API address, TLS settings for it, client name reported to the server |

## Events and errors

`OnEvent` receives `connected`, `reconnecting`, `reconnected`, `banner`,
`session_expiring`, `terminated` and `local_error`. Calls never overlap and run
on the tunnel's goroutines, so keep the callback short.

Network failures and temporary server errors are retried: the pause grows from
1 to 15 seconds with random jitter, and `Retry-After` is respected. The tunnel
ends with an error when retrying is pointless; check it with `IsPermanent`:

- `*ServerError` — the API rejected the request: bad or revoked key, missing
  scope, unknown reserved name, unpaid plan;
- `*TerminatedError` — the server closed the tunnel: it was deleted,
  suspended or hit the session time limit.

## Behaviour worth knowing

- The context passed to `Listen` bounds the whole life of the tunnel, not
  only the first connection; cancelling it cuts off every accepted
  connection. To give up early when the tunnel does not come up, set
  `ConnectTimeout`.
- `Close` stops accepting and reconnecting, but the tunnel stays connected
  until the last accepted connection is closed. `http.Server.Shutdown` does
  not wait for or close hijacked connections such as WebSockets: they keep
  the tunnel open until your code closes them or the context is cancelled.
- When the visitor closes its side of a connection, the connection is closed
  in both directions: a response sent after that is lost.
- The `Host` header and the PROXY protocol header reach your service as sent.
- The API client is `net/http` and honours `HTTPS_PROXY`. Connections to
  tuna.am nodes are plain SSH over TCP and do not use the proxy.
- Use `TLSConfig` for a private CA or for environments without system root
  certificates, such as `scratch` images.

## Protocol

The SDK implements the public tuna.am client protocol: `POST /v1/connect`
followed by a standard SSH remote forward to the node. Docs:
[tuna.am/docs/guides/client-protocol](https://tuna.am/docs/guides/client-protocol/).

[tuna-tiny](https://tuna.am/docs/guides/install/install-tiny/), a 2 MB tunnel client for routers,
embedded devices and `scratch` containers, is built on this SDK.

## Contributing

This repository is a read-only mirror of the SDK directory in the tuna.am
monorepo. Issues and pull requests are welcome here: accepted changes are
applied upstream and come back with the next release.

## License

[MIT](LICENSE)
