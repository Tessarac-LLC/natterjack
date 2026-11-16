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
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

// IdentityWatch checks this replica's cloud credentials on every replica,
// leader or not. A replica that cannot get credentials is not ready, and a
// leader that has been unable to for StepDownAfter gives up the lease, so a
// replica that can takes over.
//
// Credentials belong to the pod, not the process: a pod admitted before its
// workload identity existed never gets any, and restarting its container
// does not change that. Only moving leadership, or recreating the pod, does.
type IdentityWatch struct {
	// Retrieve gets credentials, from the SDK's cache when they are fresh.
	Retrieve func(context.Context) error
	// Every is how often credentials are checked.
	Every time.Duration
	// StepDownAfter is how long a leader may go without credentials.
	StepDownAfter time.Duration
	// Elected is closed once this replica leads.
	Elected <-chan struct{}
	Now     func() time.Time
	Log     logr.Logger

	mu      sync.Mutex
	err     error
	failing time.Time
}

// NeedLeaderElection is false: every replica reports its own credentials.
func (w *IdentityWatch) NeedLeaderElection() bool { return false }

// Start checks credentials until ctx ends. It returns an error, stopping the
// manager and releasing the lease, when this replica leads and has been
// without credentials for StepDownAfter.
func (w *IdentityWatch) Start(ctx context.Context) error {
	t := time.NewTicker(w.Every)
	defer t.Stop()
	for {
		if err := w.check(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (w *IdentityWatch) check(ctx context.Context) error {
	rctx, cancel := context.WithTimeout(ctx, w.Every)
	err := w.Retrieve(rctx)
	cancel()
	select {
	case <-ctx.Done():
		// Shutting down: the failure is the cancellation, not the identity.
		return nil
	default:
		return w.record(err, w.leading())
	}
}

// record notes one result and says whether to step down.
func (w *IdentityWatch) record(err error, leading bool) error {
	now := w.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	if err == nil {
		if w.err != nil {
			w.Log.Info("cloud credentials available again")
		}
		w.err, w.failing = nil, time.Time{}
		return nil
	}
	if w.err == nil {
		w.failing = now
		w.Log.Error(err, "cannot get cloud credentials")
	}
	w.err = err
	if leading && now.Sub(w.failing) >= w.StepDownAfter {
		return fmt.Errorf("giving up leadership after %s without cloud credentials, so a replica that has them takes over: %w",
			w.StepDownAfter, err)
	}
	return nil
}

func (w *IdentityWatch) leading() bool {
	select {
	case <-w.Elected:
		return true
	default:
		return false
	}
}

// Check is a healthz.Checker: not ready without credentials.
func (w *IdentityWatch) Check(*http.Request) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return fmt.Errorf("no cloud credentials: %w", w.err)
	}
	return nil
}
