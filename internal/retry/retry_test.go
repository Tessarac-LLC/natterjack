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

package retry

import (
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestLimiterNeverWaitsLongerThanResync(t *testing.T) {
	l := Limiter(30 * time.Second)
	item := reconcile.Request{}
	if d := l.When(item); d != first {
		t.Fatalf("first retry after %s, want %s", d, first)
	}
	var last time.Duration
	for range 40 {
		last = l.When(item)
		if last > 30*time.Second {
			t.Fatalf("retry after %s, longer than the resync", last)
		}
	}
	if last != 30*time.Second {
		t.Fatalf("backoff settled at %s, want the resync", last)
	}
	l.Forget(item)
	if d := l.When(item); d != first {
		t.Fatalf("after a success the next retry is %s, want %s", d, first)
	}
}

func TestLimiterWithResyncBelowFirstDelay(t *testing.T) {
	if d := Limiter(time.Millisecond).When(reconcile.Request{}); d != first {
		t.Fatalf("retry after %s, want %s", d, first)
	}
}
