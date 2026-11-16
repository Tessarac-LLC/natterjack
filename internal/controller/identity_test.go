/*
Copyright 2026 Tessarac, LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
)

func newWatch(now *time.Time, elected chan struct{}) *IdentityWatch {
	return &IdentityWatch{
		Every:         15 * time.Second,
		StepDownAfter: 2 * time.Minute,
		Elected:       elected,
		Now:           func() time.Time { return *now },
		Log:           logr.Discard(),
	}
}

func TestLeaderWithoutCredentialsStepsDown(t *testing.T) {
	now := time.Unix(1000, 0)
	elected := make(chan struct{})
	close(elected)
	w := newWatch(&now, elected)
	denied := errors.New("no service account role association")

	if err := w.record(denied, true); err != nil {
		t.Fatalf("stepped down at the first failure: %v", err)
	}
	if err := w.Check(nil); err == nil || !strings.Contains(err.Error(), "no cloud credentials") {
		t.Fatalf("ready without credentials: %v", err)
	}
	now = now.Add(2*time.Minute - time.Second)
	if err := w.record(denied, true); err != nil {
		t.Fatalf("stepped down before StepDownAfter: %v", err)
	}
	now = now.Add(time.Second)
	err := w.record(denied, true)
	if err == nil || !errors.Is(err, denied) || !strings.Contains(err.Error(), "giving up leadership") {
		t.Fatalf("leader kept the lease after two minutes without credentials: %v", err)
	}
}

func TestStandbyWithoutCredentialsIsOnlyUnready(t *testing.T) {
	now := time.Unix(1000, 0)
	w := newWatch(&now, make(chan struct{}))
	denied := errors.New("no EC2 IMDS role found")
	for range 20 {
		if err := w.record(denied, false); err != nil {
			t.Fatalf("a standby replica has no lease to give up: %v", err)
		}
		now = now.Add(time.Minute)
	}
	if w.Check(nil) == nil {
		t.Fatal("standby without credentials reported ready")
	}
}

func TestCredentialsReturningResetsTheClock(t *testing.T) {
	now := time.Unix(1000, 0)
	w := newWatch(&now, nil)
	denied := errors.New("expired")
	_ = w.record(denied, true)
	now = now.Add(90 * time.Second)
	if err := w.record(nil, true); err != nil {
		t.Fatal(err)
	}
	if err := w.Check(nil); err != nil {
		t.Fatalf("not ready once credentials returned: %v", err)
	}
	_ = w.record(denied, true)
	now = now.Add(90 * time.Second)
	if err := w.record(denied, true); err != nil {
		t.Fatalf("an earlier failure counted toward stepping down: %v", err)
	}
}

func TestStartStepsDownAndStops(t *testing.T) {
	now := time.Unix(1000, 0)
	elected := make(chan struct{})
	close(elected)
	w := newWatch(&now, elected)
	w.Every = time.Millisecond
	w.Retrieve = func(context.Context) error {
		now = now.Add(time.Minute)
		return errors.New("denied")
	}
	done := make(chan error, 1)
	go func() { done <- w.Start(t.Context()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Start returned without an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start never stepped down")
	}

	ctx, cancel := context.WithCancel(t.Context())
	w2 := newWatch(&now, make(chan struct{}))
	w2.Every = time.Millisecond
	w2.Retrieve = func(context.Context) error { return nil }
	go func() { done <- w2.Start(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned %v when its context ended", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start ignored its context")
	}
}
