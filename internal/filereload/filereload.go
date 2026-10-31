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

// Package filereload keeps a value parsed from files on disk current,
// for credentials that a platform rewrites in place as they rotate.
//
// It is the machinery behind every file-backed source in authn/mtls.
// The sources decide what to read and how to parse it; this package
// decides when to read it again, what to do when a read fails, and how
// to stop. Those rules are subtle enough that they are written once:
//
//   - The first load is synchronous and its failure is the caller's, so
//     a process whose credentials are missing never starts serving.
//   - Later loads run on a goroutine of the reloader's own, never on a
//     caller's path, so a wedged mount stalls the reloader and not every
//     TLS handshake in the process.
//   - A failed reload keeps the last good value and reports the error.
//   - Errors reach the caller's callback on a second goroutine, one at a
//     time, through a bounded queue, with panics recovered. See
//     Reloader.reportError for why each of those matters.
//
// ReadStable is the companion for loaders: it reads a set of files
// twice and refuses a generation that changed underneath it.
package filereload

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultInterval is how often a reloader re-reads when its caller
// asks for the default (a zero interval).
//
// Parsing a few small PEM documents is far cheaper than being wrong
// about a rotation, so this errs toward freshness. It is well under
// GKE's roughly five-minute trust-anchor propagation delay and
// Kubernetes' pod-certificate refresh margin, which are the real floors
// on how quickly a change can take effect.
const DefaultInterval = 30 * time.Second

// errQueueDepth is how many reload failures may be waiting on the error
// callback before further ones are dropped.
//
// Deep enough that an ordinarily slow callback loses nothing at a 30s
// tick, shallow enough to stay a constant. What it buys is a bound: the
// queue, not the goroutine count, is what grows when a callback wedges.
const errQueueDepth = 8

// ErrClosed is returned by Current after Close.
var ErrClosed = errors.New("filereload: closed")

// ErrNotLoaded is returned by Current on a reloader that did not come
// from Start, such as a zero value.
var ErrNotLoaded = errors.New("filereload: nothing loaded")

// ErrTorn is wrapped by ReadStable's error when a file changed between
// its two reads.
var ErrTorn = errors.New("changed while being read, so this generation may be torn; " +
	"retrying on the next reload")

// File is one input to ReadStable: a path, and what it holds, for error
// messages ("SVID chain", "trust bundle").
type File struct {
	Path string
	What string
}

// Reloader holds the most recent value a load function produced and
// refreshes it on an interval.
type Reloader[T any] struct {
	load    func() (*T, error)
	onError func(error)
	state   atomic.Pointer[T]

	// errs queues reload failures for the single goroutine that runs
	// onError. Nil when the caller supplied no callback.
	errs      chan error
	stop      chan struct{}
	closeOnce sync.Once
	done      chan struct{}
}

// Start loads once and, unless interval is negative, starts a goroutine
// that loads again every interval (DefaultInterval when interval is
// zero). onError, which may be nil, is told about every failed reload.
//
// The initial load is synchronous and its failure is returned. Call
// Close to stop the reloader.
func Start[T any](load func() (*T, error), interval time.Duration, onError func(error)) (*Reloader[T], error) {
	r := &Reloader[T]{
		load:    load,
		onError: onError,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	v, err := load()
	if err != nil {
		return nil, err
	}
	r.state.Store(v)

	if interval < 0 {
		close(r.done)
		return r, nil
	}
	if interval == 0 {
		interval = DefaultInterval
	}
	if onError != nil {
		r.errs = make(chan error, errQueueDepth)
		go r.reportLoop()
	}
	go r.reloadLoop(interval)
	return r, nil
}

// Current returns the most recently loaded value. It returns ErrClosed
// after Close, rather than serving a value that has stopped refreshing,
// and ErrNotLoaded for a reloader that never started.
//
// The value is shared with every other caller and must not be modified.
func (r *Reloader[T]) Current() (*T, error) {
	if r == nil || r.stop == nil {
		return nil, ErrNotLoaded
	}
	if r.isClosed() {
		return nil, ErrClosed
	}
	v := r.state.Load()
	if v == nil {
		// Unreachable via Start, which stores a value before returning.
		return nil, ErrNotLoaded
	}
	return v, nil
}

// isClosed reports whether Close has been called.
func (r *Reloader[T]) isClosed() bool {
	select {
	case <-r.stop:
		return true
	default:
		return false
	}
}

// Close stops the reload goroutine and makes every subsequent Current
// report ErrClosed. It is idempotent, safe to call concurrently, and
// safe to call from the error callback.
//
// It returns once the reload goroutine has exited. The goroutine
// running the error callback is not waited for, and a callback in
// progress may outlive this call.
//
// The wait is not bounded: the reload goroutine notices Close only
// between loads, so if a load is blocked reading a wedged mount, Close
// blocks with it. Current already fails by then, since it checks the
// closed flag rather than the goroutine, so what is lost is the
// caller's shutdown path rather than any safety property. A timeout
// would trade a visible hang for a leaked goroutine still writing to
// the reloader. Callers who must bound shutdown should give Close its
// own goroutine.
func (r *Reloader[T]) Close() error {
	if r == nil || r.stop == nil {
		// A zero value never started a goroutine, and close(nil) would
		// panic.
		return nil
	}
	r.closeOnce.Do(func() { close(r.stop) })
	<-r.done
	return nil
}

// reloadLoop loads on every tick until Close.
func (r *Reloader[T]) reloadLoop(interval time.Duration) {
	defer close(r.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			v, err := r.load()
			if err != nil {
				// Keep the last good value: a stale credential may
				// still be valid, and the sources refuse to serve one
				// that is not.
				r.reportError(err)
				continue
			}
			r.state.Store(v)
		}
	}
}

// reportError queues err for the error goroutine, dropping it if that
// goroutine is behind.
//
// Delivery is off the reload loop because calling the callback inline
// would put caller-supplied code on that loop's critical path, where
// three ordinary things become severe: a callback that blocks stops all
// future reloads, so a credential quietly ages out to expiry even after
// the files recover; a callback that calls Close deadlocks outright,
// since Close waits for the loop that is waiting for the callback; and
// a panic takes down the process from a goroutine the caller never
// started and cannot recover on.
//
// The send is non-blocking so that the reload loop is not merely off
// the callback's critical path but independent of it. The errors
// dropped when the queue is full all say what the queued ones already
// said: the reload is still failing.
func (r *Reloader[T]) reportError(err error) {
	if r.errs == nil {
		return
	}
	select {
	case r.errs <- err:
	default:
	}
}

// reportLoop runs the error callback, one call at a time, until Close.
//
// One long-lived goroutine rather than one per failure: a callback that
// blocks should cost a bounded queue, not an unbounded pile of
// goroutines for as long as the mount stays unreadable.
func (r *Reloader[T]) reportLoop() {
	for {
		select {
		case <-r.stop:
			return
		case err := <-r.errs:
			r.deliver(err)
		}
	}
}

// deliver calls the error callback with a panic in it recovered.
func (r *Reloader[T]) deliver(err error) {
	defer func() { _ = recover() }()
	r.onError(err)
}

// ReadStable reads every file twice and returns the contents, in
// order, only if both reads agree. Otherwise it returns an error
// wrapping ErrTorn, and the caller retries on its next reload. A read
// failure is reported as "read <What>: <cause>".
//
// A rotating writer can be caught mid-write, and PEM parsers do not
// reliably say so: a reader that drops a trailing partial block turns a
// truncated chain or bundle into a shorter valid one. Two identical
// reads is not a proof — a writer could finish between them — but it
// turns the common case, a write in progress right now, from a silent
// wrong answer into a retry.
func ReadStable(files ...File) ([][]byte, error) {
	read := func() ([][]byte, error) {
		out := make([][]byte, len(files))
		for i, f := range files {
			b, err := os.ReadFile(f.Path)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", f.What, err)
			}
			out[i] = b
		}
		return out, nil
	}
	first, err := read()
	if err != nil {
		return nil, err
	}
	second, err := read()
	if err != nil {
		return nil, err
	}
	for i := range first {
		if !bytes.Equal(first[i], second[i]) {
			return nil, fmt.Errorf("%s at %q %w", files[i].What, files[i].Path, ErrTorn)
		}
	}
	return first, nil
}
