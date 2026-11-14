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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
)

// PolicyReconciler reports whether each EgressPolicy and ClusterEgressPolicy
// names an existing pool. Agents enforce policies; this tells users whether
// theirs is in force.
type PolicyReconciler struct {
	Client client.Client
}

// SetupWithManager registers one controller per policy kind. Both also react
// to pools being created or deleted.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).Named("egresspolicy").For(&v1.EgressPolicy{}).
		Watches(&v1.EgressPool{}, handler.EnqueueRequestsFromMapFunc(r.namespacedFor)).
		Complete(reconcile.Func(r.reconcileNamespaced))
	if err != nil {
		return fmt.Errorf("set up egresspolicy controller: %w", err)
	}
	err = ctrl.NewControllerManagedBy(mgr).Named("clusteregresspolicy").For(&v1.ClusterEgressPolicy{}).
		Watches(&v1.EgressPool{}, handler.EnqueueRequestsFromMapFunc(r.clusterFor)).
		Complete(reconcile.Func(r.reconcileCluster))
	if err != nil {
		return fmt.Errorf("set up clusteregresspolicy controller: %w", err)
	}
	return nil
}

func (r *PolicyReconciler) namespacedFor(ctx context.Context, pool client.Object) []reconcile.Request {
	var list v1.EgressPolicyList
	if err := r.Client.List(ctx, &list); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range list.Items {
		if list.Items[i].Spec.PoolName == pool.GetName() {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
		}
	}
	return out
}

func (r *PolicyReconciler) clusterFor(ctx context.Context, pool client.Object) []reconcile.Request {
	var list v1.ClusterEgressPolicyList
	if err := r.Client.List(ctx, &list); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range list.Items {
		if list.Items[i].Spec.PoolName == pool.GetName() {
			out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: list.Items[i].Name}})
		}
	}
	return out
}

func (r *PolicyReconciler) reconcileNamespaced(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var p v1.EgressPolicy
	if err := r.Client.Get(ctx, req.NamespacedName, &p); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	return reconcile.Result{}, r.accept(ctx, &p, p.Spec.PoolName, &p.Status)
}

func (r *PolicyReconciler) reconcileCluster(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var p v1.ClusterEgressPolicy
	if err := r.Client.Get(ctx, req.NamespacedName, &p); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	return reconcile.Result{}, r.accept(ctx, &p, p.Spec.PoolName, &p.Status)
}

// accept sets the Accepted condition. st must be obj's status.
func (r *PolicyReconciler) accept(ctx context.Context, obj client.Object, pool string, st *v1.PolicyStatus) error {
	c := metav1.Condition{Type: v1.ConditionAccepted, ObservedGeneration: obj.GetGeneration()}
	err := r.Client.Get(ctx, types.NamespacedName{Name: pool}, &v1.EgressPool{})
	switch {
	case err == nil:
		c.Status, c.Reason, c.Message = metav1.ConditionTrue, "PoolFound", fmt.Sprintf("traffic selected by this policy leaves through EgressPool %s", pool)
	case client.IgnoreNotFound(err) == nil:
		c.Status, c.Reason, c.Message = metav1.ConditionFalse, "PoolNotFound", fmt.Sprintf("EgressPool %s does not exist; selected traffic uses the cluster's default route", pool)
	default:
		return fmt.Errorf("get pool %s: %w", pool, err)
	}
	before := st.DeepCopy()
	st.ObservedGeneration = obj.GetGeneration()
	meta.SetStatusCondition(&st.Conditions, c)
	if before.ObservedGeneration == st.ObservedGeneration && meta.IsStatusConditionPresentAndEqual(before.Conditions, c.Type, c.Status) &&
		meta.FindStatusCondition(before.Conditions, c.Type).Message == c.Message {
		return nil
	}
	if err := r.Client.Status().Update(ctx, obj); err != nil {
		return fmt.Errorf("update status of %s: %w", obj.GetName(), err)
	}
	return nil
}
