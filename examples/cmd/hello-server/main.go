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

// Command hello-server serves one mutually authenticated JSON endpoint
// and reports who called it.
//
// It is the same binary under both mTLS profiles: -profile pki reads
// callers from a standard CA's client certificates, -profile spiffe
// from X509-SVIDs. Everything below the flag parsing is profile-blind,
// which is the point — purser hands back a *tls.Config and an
// authenticator, and a server does not need to know which idiom
// verified the peer.
//
// Two listeners, deliberately:
//
//   - -addr serves the mutually authenticated API. A peer that cannot
//     present an acceptable certificate never reaches a handler.
//   - -admin-addr serves /healthz in plaintext, on a separate port, for
//     Kubernetes probes. A kubelet has no client certificate, so a
//     probe against the mTLS port could only ever fail — and lowering
//     the mTLS port's requirements to let it through would open the API
//     to anyone who can reach the port. Bind it to the pod, not the
//     network.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-steer/purser/examples/internal/hello"
	"github.com/go-steer/purser/examples/internal/profile"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "hello-server: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("hello-server", flag.ContinueOnError)

	addr := fs.String("addr", "0.0.0.0:8443", "address for the mutually authenticated API")
	adminAddr := fs.String("admin-addr", "127.0.0.1:8080", "address for the plaintext /healthz probe endpoint")
	addrFile := fs.String("addr-file", "",
		"write the API listener's resolved address here once bound; for scripts that pass -addr :0")
	name := fs.String("name", hostname(), "name reported as served_by")
	shutdownGrace := fs.Duration("shutdown-grace", 5*time.Second, "how long to let in-flight requests finish")

	var creds profile.Flags
	creds.Register(fs, profile.RoleServer)

	if err := fs.Parse(args); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	tlsCfg, auth, closeCreds, err := creds.Server(log)
	if err != nil {
		return err
	}
	defer func() {
		if err := closeCreds(); err != nil {
			log.Error("close credential source", "err", err)
		}
	}()

	mux := http.NewServeMux()
	mux.Handle(hello.Path, hello.Authenticate(auth, log, hello.Handler(*name, log)))

	api := &http.Server{
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}

	// Listen before serving so the resolved port is known: -addr :0 is
	// how the local demo avoids picking a port that is already taken,
	// and a script cannot dial a port it has to guess. The socket is
	// bound by the time addr-file exists, so a client that connects the
	// instant it appears is queued rather than refused.
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if *addrFile != "" {
		if err := os.WriteFile(*addrFile, []byte(ln.Addr().String()+"\n"), 0o600); err != nil {
			_ = ln.Close()
			return fmt.Errorf("write -addr-file: %w", err)
		}
	}

	admin := &http.Server{
		Addr:              *adminAddr,
		Handler:           healthz(),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}

	log.Info("serving",
		"profile", creds.Profile,
		"api", "https://"+ln.Addr().String()+hello.Path,
		"admin", "http://"+*adminAddr+"/healthz")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errs := make(chan error, 2)
	go func() { errs <- ignoreClosed(api.ServeTLS(ln, "", "")) }()
	go func() { errs <- ignoreClosed(admin.ListenAndServe()) }()

	select {
	case err := <-errs:
		// One listener dying takes the process with it: a server that
		// keeps answering probes while its API is down is worse than
		// one that restarts.
		_ = api.Close()
		_ = admin.Close()
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), *shutdownGrace)
	defer cancel()
	err = errors.Join(api.Shutdown(shutCtx), admin.Shutdown(shutCtx))
	if err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

// healthz answers the kubelet. It reports that the process is up and
// nothing else: it is unauthenticated, so it must not describe the
// credential state to whoever can reach the port.
func healthz() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})
	return mux
}

func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "hello-server"
	}
	return h
}
