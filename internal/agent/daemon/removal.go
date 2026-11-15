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


package daemon

import (
	"context"
	"fmt"
	"sync/atomic"

	appsv1 "k8s.io/api/apps/v1"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
)

// RemovalWatch learns, while the agent runs, that its DaemonSet is being
// removed. Uninstalling deletes the agent's RBAC and ServiceAccount at the
// same moment as the DaemonSet, so by the time the agent is told to stop it
// may no longer be allowed to ask; a watch established earlier still
// delivers the deletion.
type RemovalWatch struct {
	removed atomic.Bool
}

// Watch follows the DaemonSet with the given name through c, which should
// cache only that DaemonSet.
func (w *RemovalWatch) Watch(ctx context.Context, c cache.Cache, name string) error {
	inf, err := c.GetInformer(ctx, &appsv1.DaemonSet{})
	if err != nil {
		return fmt.Errorf("watch the agent DaemonSet: %w", err)
	}
	seen := func(obj any, deleted bool) {
		if t, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
			obj = t.Obj
		}
		ds, ok := obj.(*appsv1.DaemonSet)
		if !ok || ds.Name != name {
			return
		}
		if deleted || ds.DeletionTimestamp != nil {
			w.removed.Store(true)
		}
	}
	_, err = inf.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { seen(obj, false) },
		UpdateFunc: func(_, obj any) { seen(obj, false) },
		DeleteFunc: func(obj any) { seen(obj, true) },
	})
	if err != nil {
		return fmt.Errorf("watch the agent DaemonSet: %w", err)
	}
	return nil
}

// Removed reports whether the DaemonSet was deleted or is being deleted.
func (w *RemovalWatch) Removed() bool { return w.removed.Load() }
