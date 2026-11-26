package tuna_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	tuna "github.com/yuccastream/tuna-sdk-go"
)

func ExampleListen() {
	ln, err := tuna.Listen(context.Background(), tuna.Options{Protocol: "http"})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	fmt.Println("public URL:", ln.URL())
	err = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "hello from", r.Host)
	}))
	log.Print(err)
}

func ExampleForward() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	err := tuna.Forward(ctx, tuna.Options{
		Protocol:  "tcp",
		Port:      "my-db",
		CIDRAllow: []string{"203.0.113.0/24"},
		OnEvent: func(e tuna.Event) {
			switch e.Type {
			case tuna.EventConnected, tuna.EventReconnected:
				log.Printf("forwarding %s -> 127.0.0.1:5432", e.URL)
			case tuna.EventReconnecting:
				log.Printf("connection error (%v), retry in %s", e.Err, e.RetryIn)
			case tuna.EventSessionExpiring:
				log.Printf("session expires in %s", e.ExpiresIn)
			case tuna.EventLocalError:
				log.Printf("local service unavailable: %v", e.Err)
			case tuna.EventBanner, tuna.EventTerminated:
				log.Print(e.Message)
			}
		},
	}, "127.0.0.1:5432")
	if err != nil {
		log.Print(err)
	}
}
