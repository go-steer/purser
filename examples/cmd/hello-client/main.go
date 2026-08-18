// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command hello-client calls hello-server over mutual TLS and prints
// the identity the server saw.
//
// Like the server, it is one binary for both profiles: -profile pki
// presents a standard CA's client certificate, -profile spiffe presents
// an X509-SVID. The transport comes from client.Transport, which exists
// because net/http quietly drops to HTTP/1.1 the moment a caller sets
// TLSClientConfig.
//
// Exit status is the point when this runs in a smoke test: 0 only if
// the server answered 200 with a caller identity.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-steer/purser/client"
	"github.com/go-steer/purser/examples/internal/hello"
	"github.com/go-steer/purser/examples/internal/profile"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "hello-client: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("hello-client", flag.ContinueOnError)

	url := fs.String("url", "https://127.0.0.1:8443", "base URL of hello-server")
	count := fs.Int("count", 1, "number of requests to make; 0 means forever")
	interval := fs.Duration("interval", 5*time.Second, "delay between requests when -count is not 1")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request timeout")
	retries := fs.Int("retries", 0, "retry a failed request this many times before giving up")
	retryDelay := fs.Duration("retry-delay", 500*time.Millisecond, "delay between retries")

	var creds profile.Flags
	creds.Register(fs, profile.RoleClient)

	if err := fs.Parse(args); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	tlsCfg, closeCreds, err := creds.Client(log)
	if err != nil {
		return err
	}
	defer func() {
		if err := closeCreds(); err != nil {
			log.Error("close credential source", "err", err)
		}
	}()

	// client.Transport, not a hand-rolled &http.Transport: it clones
	// http.DefaultTransport's timeouts, sets ForceAttemptHTTP2 — which
	// net/http only does for itself while TLSClientConfig is nil — and
	// clips the config's NextProtos so net/http's HTTP/2 setup cannot
	// append into a slice the caller still holds.
	httpc := &http.Client{Transport: client.Transport(tlsCfg)}
	defer httpc.CloseIdleConnections()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	for i := 0; *count == 0 || i < *count; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(*interval):
			}
		}

		g, err := greetWithRetries(ctx, httpc, *url, *timeout, *retries, *retryDelay)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// Keep going when looping forever — a sidecar-style client
			// that exits on the first blip during a credential rotation
			// is a worse demonstration than one that reports and
			// retries.
			if *count != 1 {
				log.Error("request failed", "err", err)
				continue
			}
			return err
		}
		if err := enc.Encode(g); err != nil {
			return fmt.Errorf("write result: %w", err)
		}
	}
	return nil
}

// greetWithRetries retries the whole request, handshake included.
//
// Retrying matters in Kubernetes, where a client pod routinely starts
// before its server's endpoints are ready, and on any platform that
// delivers credentials asynchronously: GKE's managed workload identity
// takes a few minutes to populate the mount on a cold pod.
func greetWithRetries(
	ctx context.Context,
	c *http.Client,
	url string,
	timeout time.Duration,
	retries int,
	delay time.Duration,
) (hello.Greeting, error) {
	var errs []error
	for attempt := 0; ; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		g, err := hello.Greet(reqCtx, c, url)
		cancel()
		if err == nil {
			return g, nil
		}
		errs = append(errs, err)

		if attempt >= retries || ctx.Err() != nil {
			return hello.Greeting{}, errors.Join(errs...)
		}
		select {
		case <-ctx.Done():
			return hello.Greeting{}, errors.Join(errs...)
		case <-time.After(delay):
		}
	}
}
