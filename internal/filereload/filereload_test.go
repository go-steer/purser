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

package filereload

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// counter is a load function whose result and failure the test controls.
type counter struct {
	n    atomic.Int64
	fail atomic.Bool
}

func (c *counter) load() (*int64, error) {
	if c.fail.Load() {
		return nil, errors.New("load failed")
	}
	v := c.n.Add(1)
	return &v, nil
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestStartReturnsTheFirstLoadError(t *testing.T) {
	t.Parallel()
	c := &counter{}
	c.fail.Store(true)
	if _, err := Start(c.load, -1, nil); err == nil {
		t.Fatal("Start succeeded although the first load failed")
	}
}

func TestReloadsOnTheInterval(t *testing.T) {
	t.Parallel()
	c := &counter{}
	r, err := Start(c.load, time.Millisecond, nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Close() }()

	waitFor(t, "a reload", func() bool {
		v, err := r.Current()
		return err == nil && *v > 1
	})
}

func TestNegativeIntervalLoadsOnce(t *testing.T) {
	t.Parallel()
	c := &counter{}
	r, err := Start(c.load, -1, nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if v, err := r.Current(); err != nil || *v != 1 {
		t.Fatalf("Current() = %v, %v; want the single first load", v, err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := r.Current(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Current after Close = %v, want ErrClosed", err)
	}
}

func TestZeroIntervalMeansTheDefault(t *testing.T) {
	t.Parallel()
	c := &counter{}
	r, err := Start(c.load, 0, nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Close() }()
	// The default is 30s, so nothing reloads within a test's lifetime.
	time.Sleep(10 * time.Millisecond)
	if v, _ := r.Current(); *v != 1 {
		t.Fatalf("reloaded after %d loads with the default interval", *v)
	}
}

func TestAFailedReloadKeepsTheLastValueAndReports(t *testing.T) {
	t.Parallel()
	c := &counter{}
	var reported atomic.Int64
	r, err := Start(c.load, time.Millisecond, func(error) { reported.Add(1) })
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Close() }()

	c.fail.Store(true)
	before, _ := r.Current()
	waitFor(t, "a reported reload failure", func() bool { return reported.Load() > 0 })
	after, err := r.Current()
	if err != nil {
		t.Fatalf("Current after a failed reload: %v", err)
	}
	if *after < *before {
		t.Fatalf("value went backwards after a failed reload: %d then %d", *before, *after)
	}
}

func TestErrorCallbackMayBlockAndPanic(t *testing.T) {
	t.Parallel()
	c := &counter{}
	release := make(chan struct{})
	var calls atomic.Int64
	onError := func(error) {
		if calls.Add(1) == 1 {
			panic("a callback that panics must not take the process down")
		}
		<-release // every later call blocks
	}
	var attempts atomic.Int64
	load := func() (*int64, error) { attempts.Add(1); return c.load() }
	r, err := Start(load, time.Millisecond, onError)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { close(release); _ = r.Close() }()

	c.fail.Store(true)
	waitFor(t, "the callback to block", func() bool { return calls.Load() >= 2 })
	// The reload loop keeps loading while the callback is blocked:
	// delivery is off its path.
	before := attempts.Load()
	waitFor(t, "reloads to continue while the callback blocks", func() bool {
		return attempts.Load() > before+3
	})
}

func TestCloseFromTheErrorCallbackReturns(t *testing.T) {
	t.Parallel()
	c := &counter{}
	var r *Reloader[int64]
	closed := make(chan struct{})
	var once sync.Once
	onError := func(error) {
		once.Do(func() {
			// Close from inside the callback must return: it waits for
			// the reload loop, which must not be waiting for us.
			_ = r.Close()
			close(closed)
		})
	}
	var err error
	r, err = Start(c.load, time.Millisecond, onError)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	c.fail.Store(true)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close called from the error callback did not return")
	}
}

func TestCloseIsIdempotentAndConcurrent(t *testing.T) {
	t.Parallel()
	c := &counter{}
	r, err := Start(c.load, time.Millisecond, func(error) {})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); _ = r.Close() }()
	}
	wg.Wait()
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestZeroAndNilReloaders(t *testing.T) {
	t.Parallel()
	var zero Reloader[int64]
	if _, err := zero.Current(); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("zero Current = %v, want ErrNotLoaded", err)
	}
	if err := zero.Close(); err != nil {
		t.Errorf("zero Close = %v", err)
	}
	var nilR *Reloader[int64]
	if _, err := nilR.Current(); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("nil Current = %v, want ErrNotLoaded", err)
	}
	if err := nilR.Close(); err != nil {
		t.Errorf("nil Close = %v", err)
	}
	// A value whose channels exist but that never stored anything.
	half := &Reloader[int64]{stop: make(chan struct{}), done: make(chan struct{})}
	if _, err := half.Current(); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("unloaded Current = %v, want ErrNotLoaded", err)
	}
}

func TestReadStable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ReadStable(File{Path: a, What: "first"}, File{Path: b, What: "second"})
	if err != nil {
		t.Fatalf("ReadStable: %v", err)
	}
	if string(got[0]) != "one" || string(got[1]) != "two" {
		t.Fatalf("ReadStable = %q, want [one two] in order", got)
	}

	_, err = ReadStable(File{Path: filepath.Join(dir, "missing"), What: "absent thing"})
	if err == nil || !strings.Contains(err.Error(), "read absent thing") {
		t.Fatalf("missing file error = %v, want it to name what was being read", err)
	}
}

func TestReadStableReportsATornRead(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rotating")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				_ = os.WriteFile(path, []byte(strings.Repeat("x", i%7+1)), 0o600)
			}
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, err := ReadStable(File{Path: path, What: "rotating file"})
		if errors.Is(err, ErrTorn) {
			if !strings.Contains(err.Error(), "rotating file") {
				t.Fatalf("torn error %q does not say which file", err)
			}
			return
		}
	}
	t.Fatal("a continuously rewritten file never produced a torn read")
}
