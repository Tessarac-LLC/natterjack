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
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func daemonSet(t *testing.T, name string) *appsv1.DaemonSet {
	t.Helper()
	l := map[string]string{"app": name}
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: l},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: l},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "agent", Image: "agent"}}},
			},
		},
	}
	create(t, ds)
	return ds
}

func TestRemovalWatch(t *testing.T) {
	for _, tc := range []struct {
		name        string
		propagation metav1.DeletionPropagation
	}{
		// Helm deletes in the background: the DaemonSet is gone at once.
		{"background", metav1.DeletePropagationBackground},
		// Foreground deletion first marks it with a deletion time.
		{"foreground", metav1.DeletePropagationForeground},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mine := daemonSet(t, "agent-"+tc.name)
			other := daemonSet(t, "other-"+tc.name)
			// The whole namespace, not just this DaemonSet as the agent
			// caches, so another DaemonSet's deletion reaches the watch.
			c, err := cache.New(restCfg, cache.Options{
				Scheme:            testScheme,
				DefaultNamespaces: map[string]cache.Config{ns: {}},
			})
			if err != nil {
				t.Fatal(err)
			}
			w := &RemovalWatch{}
			if err := w.Watch(t.Context(), c, mine.Name); err != nil {
				t.Fatal(err)
			}
			go func() { _ = c.Start(t.Context()) }()
			if !c.WaitForCacheSync(t.Context()) {
				t.Fatal("cache did not sync")
			}
			if w.Removed() {
				t.Fatal("removed before anything was deleted")
			}
			if err := k8s.Delete(t.Context(), other); err != nil {
				t.Fatal(err)
			}
			time.Sleep(200 * time.Millisecond)
			if w.Removed() {
				t.Fatal("another DaemonSet's deletion counted")
			}
			if err := k8s.Delete(t.Context(), mine, client.PropagationPolicy(tc.propagation)); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for !w.Removed() {
				if time.Now().After(deadline) {
					t.Fatal("deletion of the agent DaemonSet not seen")
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}
