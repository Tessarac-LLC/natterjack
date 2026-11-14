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

// Package retry sets how soon a failed reconcile runs again.
package retry

import (
	"time"

	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// first is the delay after the first failure.
const first = 100 * time.Millisecond

// Limiter backs off after each failure, doubling from 100ms, but never waits
// longer than resync. The default backs off to 1000s, so a failure that
// cleared (a sysctl fixed, the cloud API back) would leave the data path or
// the slots stale for up to 16 minutes instead of one resync.
func Limiter(resync time.Duration) workqueue.TypedRateLimiter[reconcile.Request] {
	return workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](first, max(resync, first))
}
