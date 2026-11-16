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
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
	"github.com/Tessarac-LLC/natterjack/internal/cloud"
	"github.com/Tessarac-LLC/natterjack/internal/retry"
)

// Disruption taints set by tools that remove nodes.
var disruptionTaints = map[string]string{
	"karpenter.sh/disrupted":            "Karpenter is removing node %s",
	"ToBeDeletedByClusterAutoscaler":    "the cluster autoscaler is removing node %s",
	"node.kubernetes.io/out-of-service": "node %s is out of service",
}

const terminationHandlerTaintPrefix = "aws-node-termination-handler/"

// avoidFor is how long a node that refused an attach is skipped.
const avoidFor = 10 * time.Minute

// AgentRestartGrace is how long a slot stays on a node whose agent pod is
// gone, so that a rolling update of the agents moves no slot. A node that
// fails goes not ready and loses its slot at once.
const AgentRestartGrace = 60 * time.Second

// Reconciler assigns every pool's slots to nodes. It runs as one reconcile
// for all pools, because a node holds at most one slot whatever the pool.
type Reconciler struct {
	Client   client.Client
	Provider cloud.Provider
	Recorder events.EventRecorder
	// ClusterName is the value of the natterjack.io/cluster tag.
	ClusterName string
	// Namespace and AgentSelector find the agent pods.
	Namespace     string
	AgentSelector labels.Selector
	// ServiceAccount the controller runs as, named in credential errors.
	ServiceAccount string
	// IdentityHint, when set, is added to cloud errors: why this pod may
	// have no credentials and what to do.
	IdentityHint string
	// Resync is how often the cloud is re-read when nothing in the cluster
	// changes.
	Resync time.Duration
	Health *Health
	Now    func() time.Time

	mu     sync.Mutex
	avoid  map[string]avoided
	strays string
	// agents remembers, per node, the slot its agent last served and since
	// when it has had no running agent.
	agents map[string]agentSeen
}

type agentSeen struct {
	served string
	gone   time.Time
}

type avoided struct {
	reason string
	until  time.Time
}

// request is the single key every event maps to.
var request = reconcile.Request{NamespacedName: types.NamespacedName{Name: "natterjack"}}

// SetupWithManager registers the reconciler.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	all := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{request}
	})
	agents := predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetNamespace() == r.Namespace && r.AgentSelector.Matches(labels.Set(o.GetLabels()))
	})
	err := ctrl.NewControllerManagedBy(mgr).
		Named("egresspool").
		Watches(&v1.EgressPool{}, all, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.Node{}, all, builder.WithPredicates(nodeChanged)).
		Watches(&corev1.Pod{}, all, builder.WithPredicates(agents)).
		WithOptions(controller.Options{RateLimiter: retry.Limiter(r.Resync)}).
		Complete(r)
	if err != nil {
		return fmt.Errorf("set up egresspool controller: %w", err)
	}
	return nil
}

// nodeChanged ignores heartbeat-only node updates.
var nodeChanged = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		o, okO := e.ObjectOld.(*corev1.Node)
		n, okN := e.ObjectNew.(*corev1.Node)
		if !okO || !okN {
			return true
		}
		return o.Spec.Unschedulable != n.Spec.Unschedulable ||
			!equality.Semantic.DeepEqual(o.Spec.Taints, n.Spec.Taints) ||
			!equality.Semantic.DeepEqual(o.Labels, n.Labels) ||
			nodeReady(o) != nodeReady(n) ||
			o.DeletionTimestamp != n.DeletionTimestamp
	},
}

// Reconcile implements reconcile.Reconciler.
func (r *Reconciler) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx)
	now := r.Now()

	var pools v1.EgressPoolList
	if err := r.Client.List(ctx, &pools); err != nil {
		return reconcile.Result{}, fmt.Errorf("list egress pools: %w", err)
	}
	var nodeList corev1.NodeList
	if err := r.Client.List(ctx, &nodeList); err != nil {
		return reconcile.Result{}, fmt.Errorf("list nodes: %w", err)
	}
	var pods corev1.PodList
	if err := r.Client.List(ctx, &pods, client.InNamespace(r.Namespace), client.MatchingLabelsSelector{Selector: r.AgentSelector}); err != nil {
		return reconcile.Result{}, fmt.Errorf("list agent pods: %w", err)
	}

	slots, err := r.Provider.Slots(ctx, cloud.Discovery{ClusterName: r.ClusterName})
	if err != nil {
		return reconcile.Result{}, r.cloudDown(ctx, pools.Items, r.cloudError("discover slots", err))
	}
	strays, err := r.Provider.Strays(ctx, r.ClusterName)
	if err != nil {
		return reconcile.Result{}, r.cloudDown(ctx, pools.Items, r.cloudError("list slots of other clusters", err))
	}
	r.Health.Set(nil)

	nodes, agents := r.observe(ctx, nodeList.Items, pods.Items, now)
	in := Input{Slots: slots, Nodes: nodes, Now: now, Avoid: r.avoided(now), AgentGrace: AgentRestartGrace}
	for i := range pools.Items {
		in.Pools = append(in.Pools, Pool{Name: pools.Items[i].Name, Spec: pools.Items[i].Spec})
	}
	plan := Compute(in)
	poolsByName := map[string]*v1.EgressPool{}
	for i := range pools.Items {
		poolsByName[pools.Items[i].Name] = &pools.Items[i]
	}

	changed := false
	var errs []error
	for _, d := range plan.Detaches {
		if a := agentOn(nodes, d.Node); a != "" {
			if err := r.setAgent(ctx, agents[a], nil); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		if err := r.Provider.Detach(ctx, d.Slot, d.Force); err != nil {
			errs = append(errs, r.cloudError("detach "+d.Slot, err))
			r.event(poolsByName, plan, d.Slot, corev1.EventTypeWarning, "DetachFailed", "Detach", "detaching slot %s: %v", d.Slot, err)
			continue
		}
		changed = true
		slotMoves.WithLabelValues(poolOf(plan, d.Slot)).Inc()
		r.event(poolsByName, plan, d.Slot, corev1.EventTypeNormal, "SlotDetached", "Detach", "detached slot %s from node %s: %s", d.Slot, d.Node, d.Reason)
	}
	for _, a := range plan.Attaches {
		err := r.Provider.Attach(ctx, a.Slot, a.Instance)
		if err != nil {
			delete(plan.Agents, agentOn(nodes, a.Node))
			if errors.Is(err, cloud.ErrNoFreeDeviceIndex) {
				r.avoidNode(a.Node, "no free network interface slot", now)
			}
			errs = append(errs, r.cloudError("attach "+a.Slot, err))
			r.event(poolsByName, plan, a.Slot, corev1.EventTypeWarning, "AttachFailed", "Attach", "attaching slot %s to node %s: %v", a.Slot, a.Node, err)
			continue
		}
		changed = true
		r.event(poolsByName, plan, a.Slot, corev1.EventTypeNormal, "SlotAttached", "Attach", "attached slot %s to node %s", a.Slot, a.Node)
	}
	for _, name := range slices.Sorted(maps.Keys(agents)) {
		// A terminating agent keeps what it has: clearing it could make
		// it tear down the gateway its replacement takes over.
		if agents[name].DeletionTimestamp != nil {
			continue
		}
		var want *AgentWant
		if w, ok := plan.Agents[name]; ok {
			want = &w
		}
		if err := r.setAgent(ctx, agents[name], want); err != nil {
			errs = append(errs, err)
		}
	}

	zones := nodeZones(nodes)
	for _, pool := range poolsByName {
		if err := r.updateStatus(ctx, pool, plan.Pools[pool.Name], zones); err != nil {
			errs = append(errs, err)
		}
	}
	r.reportStrays(poolsByName, plan.Unmatched, strays)
	record(plan, strays)

	if len(errs) > 0 {
		return reconcile.Result{}, errors.Join(errs...)
	}
	after := r.Resync
	if plan.RequeueAfter > 0 && plan.RequeueAfter < after {
		after = plan.RequeueAfter
	}
	if changed {
		// Observe the attachments the cloud just made.
		after = min(after, 5*time.Second)
	}
	log.V(1).Info("reconciled", "slots", len(slots), "attaches", len(plan.Attaches), "detaches", len(plan.Detaches), "requeueAfter", after)
	return reconcile.Result{RequeueAfter: after}, nil
}

// observe turns nodes and agent pods into the planner's view. Nodes the
// provider cannot map to an instance (for example, serverless nodes) are
// left out: they can neither hold a slot nor need one.
func (r *Reconciler) observe(ctx context.Context, nodeList []corev1.Node, pods []corev1.Pod, now time.Time) ([]Node, map[string]*corev1.Pod) {
	log := logf.FromContext(ctx)
	agents := map[string]*corev1.Pod{}
	byNode := map[string]*corev1.Pod{}
	for i := range pods {
		p := &pods[i]
		agents[p.Name] = p
		if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || p.Spec.NodeName == "" {
			continue
		}
		// During a rollout the older pod keeps the gateway.
		if cur := byNode[p.Spec.NodeName]; cur == nil || p.CreationTimestamp.Before(&cur.CreationTimestamp) {
			byNode[p.Spec.NodeName] = p
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	seen := map[string]agentSeen{}
	var nodes []Node
	for i := range nodeList {
		n := &nodeList[i]
		inst, err := r.Provider.InstanceForProviderID(n.Spec.ProviderID)
		if err != nil {
			log.V(1).Info("skipping node without a usable provider ID", "node", n.Name, "providerID", n.Spec.ProviderID)
			continue
		}
		node := Node{
			Name: n.Name, Instance: inst.ID, Zone: inst.Zone, Created: n.CreationTimestamp.Time,
			Labels: n.Labels, Taints: n.Spec.Taints, Ready: nodeReady(n), Disruption: disruption(n),
		}
		was := r.agents[n.Name]
		if p := byNode[n.Name]; p != nil {
			node.Agent = agentOf(p)
			switch a := node.Agent; {
			case a.GatewayReady:
				was.served = a.Gateway.SlotID
			case a.Gateway == nil && a.Serves == "" && !a.Pending:
				was.served = ""
			}
			was.gone = time.Time{}
		} else if was.gone.IsZero() {
			was.gone = now
		}
		node.AgentGone, node.LastServed = was.gone, was.served
		seen[n.Name] = was
		nodes = append(nodes, node)
	}
	r.agents = seen
	return nodes, agents
}

func agentOf(p *corev1.Pod) *Agent {
	a := &Agent{Pod: p.Name, Pending: true}
	for _, c := range p.Status.Conditions {
		switch c.Type {
		case corev1.ContainersReady:
			a.Ready = c.Status == corev1.ConditionTrue
		case v1.ConditionGatewayReady:
			a.Pending = c.Reason == v1.ReasonSelfTestPending
			if slot, ok := strings.CutPrefix(c.Message, v1.GatewayReadyMessage("")); ok && c.Status == corev1.ConditionTrue {
				a.Serves = slot
			}
		}
	}
	if raw := p.Annotations[v1.AnnotationGateway]; raw != "" {
		var g v1.Gateway
		if json.Unmarshal([]byte(raw), &g) == nil {
			a.Gateway = &g
			a.GatewayReady = v1.GatewayReady(p, g.SlotID)
		}
	}
	if raw := p.Annotations[v1.AnnotationDrainStarted]; raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			a.DrainStarted = t
		}
	}
	return a
}

func nodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func disruption(n *corev1.Node) string {
	if n.DeletionTimestamp != nil {
		return fmt.Sprintf("node %s is being deleted", n.Name)
	}
	for _, t := range n.Spec.Taints {
		if msg, ok := disruptionTaints[t.Key]; ok {
			return fmt.Sprintf(msg, n.Name)
		}
		if strings.HasPrefix(t.Key, terminationHandlerTaintPrefix) {
			return fmt.Sprintf("AWS Node Termination Handler is removing node %s (%s)", n.Name, strings.TrimPrefix(t.Key, terminationHandlerTaintPrefix))
		}
	}
	if n.Spec.Unschedulable {
		return fmt.Sprintf("node %s is cordoned", n.Name)
	}
	return ""
}

func agentOn(nodes []Node, node string) string {
	for _, n := range nodes {
		if n.Name == node && n.Agent != nil {
			return n.Agent.Pod
		}
	}
	return ""
}

func nodeZones(nodes []Node) []string {
	z := map[string]bool{}
	for _, n := range nodes {
		if n.Agent != nil {
			z[n.Zone] = true
		}
	}
	return slices.Sorted(maps.Keys(z))
}

// setAgent writes the desired assignment on an agent pod, or clears it when
// want is nil. It patches only when something differs.
func (r *Reconciler) setAgent(ctx context.Context, pod *corev1.Pod, want *AgentWant) error {
	if pod == nil {
		return nil
	}
	labelsWant := map[string]string{}
	annWant := map[string]string{}
	if want != nil {
		raw, err := json.Marshal(want.Gateway)
		if err != nil {
			return fmt.Errorf("encode gateway: %w", err)
		}
		labelsWant[v1.LabelGateway] = "true"
		labelsWant[v1.LabelPool] = want.Gateway.Pool
		annWant[v1.AnnotationGateway] = string(raw)
		if !want.DrainStarted.IsZero() {
			annWant[v1.AnnotationDrainStarted] = want.DrainStarted.UTC().Format(time.RFC3339)
		}
	}
	labelsPatch := diff(pod.Labels, labelsWant, v1.LabelGateway, v1.LabelPool)
	annPatch := diff(pod.Annotations, annWant, v1.AnnotationGateway, v1.AnnotationDrainStarted)
	if len(labelsPatch) == 0 && len(annPatch) == 0 {
		return nil
	}
	meta := map[string]any{}
	if len(labelsPatch) > 0 {
		meta["labels"] = labelsPatch
	}
	if len(annPatch) > 0 {
		meta["annotations"] = annPatch
	}
	body, err := json.Marshal(map[string]any{"metadata": meta})
	if err != nil {
		return fmt.Errorf("encode patch: %w", err)
	}
	if err := r.Client.Patch(ctx, pod, client.RawPatch(types.MergePatchType, body)); err != nil {
		return fmt.Errorf("update agent pod %s: %w", pod.Name, err)
	}
	return nil
}

// diff returns a merge patch for the given keys: the wanted value, or null
// to remove a key that should not be there.
func diff(have, want map[string]string, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		w, wok := want[k]
		h, hok := have[k]
		switch {
		case wok && (!hok || h != w):
			out[k] = w
		case !wok && hok:
			out[k] = nil
		}
	}
	return out
}

func (r *Reconciler) updateStatus(ctx context.Context, pool *v1.EgressPool, slots []v1.SlotStatus, zones []string) error {
	st := Status(pool.Generation, slots, zones, pool.Status.Conditions)
	r.transitions(pool, slots)
	if equality.Semantic.DeepEqual(ignoreTimes(pool.Status), ignoreTimes(st)) {
		return nil
	}
	before := pool.DeepCopy()
	pool.Status = st
	if err := r.Client.Status().Patch(ctx, pool, client.MergeFrom(before)); err != nil {
		return fmt.Errorf("update status of pool %s: %w", pool.Name, err)
	}
	return nil
}

// cloudDown reports a failed cloud read on the readiness probe and on every
// pool, where kubectl and doctor show it, and returns err for a retry.
func (r *Reconciler) cloudDown(ctx context.Context, pools []v1.EgressPool, err error) error {
	r.Health.Set(err)
	errs := []error{err}
	for i := range pools {
		pool := &pools[i]
		before := pool.DeepCopy()
		meta.SetStatusCondition(&pool.Status.Conditions, metav1.Condition{
			Type: v1.ConditionCloudAccess, Status: metav1.ConditionFalse, Reason: "CloudCallFailed",
			Message: err.Error(), ObservedGeneration: pool.Generation,
		})
		if equality.Semantic.DeepEqual(ignoreTimes(before.Status), ignoreTimes(pool.Status)) {
			continue
		}
		if perr := r.Client.Status().Patch(ctx, pool, client.MergeFrom(before)); perr != nil {
			errs = append(errs, fmt.Errorf("update status of pool %s: %w", pool.Name, perr))
		}
	}
	return errors.Join(errs...)
}

// ignoreTimes drops condition transition times, which SetStatusCondition
// keeps unless the status flips.
func ignoreTimes(st v1.EgressPoolStatus) v1.EgressPoolStatus {
	st = *st.DeepCopy()
	for i := range st.Conditions {
		st.Conditions[i].LastTransitionTime = metav1.Time{}
	}
	return st
}

// transitions emits an event for each slot whose state changed.
func (r *Reconciler) transitions(pool *v1.EgressPool, slots []v1.SlotStatus) {
	old := map[string]v1.SlotState{}
	for _, s := range pool.Status.Slots {
		old[s.ID] = s.State
	}
	for _, s := range slots {
		if old[s.ID] == s.State {
			continue
		}
		kind := corev1.EventTypeNormal
		switch s.State {
		case v1.SlotQuarantined, v1.SlotUnschedulable, v1.SlotForeign:
			kind = corev1.EventTypeWarning
		}
		note := fmt.Sprintf("slot %s (%s) is %s", s.ID, s.Zone, s.State)
		if s.Node != "" {
			note += " on node " + s.Node
		}
		if s.Reason != "" {
			note += ": " + s.Reason
		}
		r.Recorder.Eventf(pool, nil, kind, "Slot"+string(s.State), "Reconcile", "%s", note)
	}
}

func (r *Reconciler) event(pools map[string]*v1.EgressPool, plan Plan, slot, kind, reason, action, format string, args ...any) {
	if p := pools[poolOf(plan, slot)]; p != nil {
		r.Recorder.Eventf(p, nil, kind, reason, action, format, args...)
	}
}

func poolOf(plan Plan, slot string) string {
	for _, name := range slices.Sorted(maps.Keys(plan.Pools)) {
		for _, s := range plan.Pools[name] {
			if s.ID == slot {
				return name
			}
		}
	}
	return ""
}

// reportStrays warns, once per change, about slots no pool claims and slots
// tagged for another cluster, so a tagging mistake is visible.
func (r *Reconciler) reportStrays(pools map[string]*v1.EgressPool, unmatched []string, strays []cloud.Stray) {
	var parts []string
	if len(unmatched) > 0 {
		parts = append(parts, fmt.Sprintf("slots of this cluster that no EgressPool claims: %s", strings.Join(unmatched, ", ")))
	}
	if len(strays) > 0 {
		var s []string
		for _, st := range strays {
			c := st.Cluster
			if c == "" {
				c = "no cluster tag"
			} else {
				c = "cluster tag " + c
			}
			s = append(s, fmt.Sprintf("%s (%s, %s)", st.ID, st.Zone, c))
		}
		parts = append(parts, fmt.Sprintf("egress-tagged slots for other clusters, ignored (this cluster is %q): %s", r.ClusterName, strings.Join(s, ", ")))
	}
	msg := strings.Join(parts, "; ")
	r.mu.Lock()
	same := msg == r.strays
	r.strays = msg
	r.mu.Unlock()
	if same || msg == "" {
		return
	}
	for _, name := range slices.Sorted(maps.Keys(pools)) {
		r.Recorder.Eventf(pools[name], nil, corev1.EventTypeWarning, "UnclaimedSlots", "Discover", "%s", msg)
	}
}

func (r *Reconciler) avoided(now time.Time) map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]string{}
	for n, a := range r.avoid {
		if now.Before(a.until) {
			out[n] = a.reason
		} else {
			delete(r.avoid, n)
		}
	}
	return out
}

func (r *Reconciler) avoidNode(node, reason string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.avoid == nil {
		r.avoid = map[string]avoided{}
	}
	r.avoid[node] = avoided{reason: reason, until: now.Add(avoidFor)}
}

// cloudError adds the identity in use, because most cloud failures at
// install time are a workload identity trust policy that names a different
// ServiceAccount.
func (r *Reconciler) cloudError(op string, err error) error {
	cloudErrors.WithLabelValues(strings.Fields(op)[0]).Inc()
	err = fmt.Errorf("%s: %w (the controller authenticates as system:serviceaccount:%s:%s; the cloud role must trust that subject and carry the Natterjack policy)",
		op, err, r.Namespace, r.ServiceAccount)
	if r.IdentityHint != "" {
		err = fmt.Errorf("%w (%s)", err, r.IdentityHint)
	}
	return err
}

// Health reports the last cloud error to the readiness probe.
type Health struct {
	mu  sync.Mutex
	err error
}

// Set records the latest cloud result.
func (h *Health) Set(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.err = err
}

// Check is a healthz.Checker: not ready while the cloud API fails.
func (h *Health) Check(*http.Request) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.err
}
