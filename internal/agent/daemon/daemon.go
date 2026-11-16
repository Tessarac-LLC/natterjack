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

// Package daemon runs the agent on one node: it reads the cluster, applies
// the data path, probes gateways and, on a gateway node, answers probes,
// tests the slot and reports the gateway ready.
package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
	"github.com/Tessarac-LLC/natterjack/internal/agent"
	"github.com/Tessarac-LLC/natterjack/internal/agent/dataplane"
	"github.com/Tessarac-LLC/natterjack/internal/retry"
)

// Dataplane is the node's kernel state.
type Dataplane interface {
	Apply(want *agent.Desired) (dataplane.Status, error)
	DialGateway(ctx context.Context, network, addr string) (net.Conn, error)
	// WireGuardKey is the node's WireGuard public key.
	WireGuardKey() string
}

// SelfTester checks that traffic dialed through dial leaves from want.
type SelfTester func(ctx context.Context, dial agent.Dialer, url string, want netip.Addr) error

// Defaults when an EgressPool leaves probing unset.
const (
	defaultProbeInterval  = 100 * time.Millisecond
	defaultProbeThreshold = 3
	// selfTestFailures is how many consecutive self-test failures take a
	// serving gateway out of service. One failure is often the test service.
	selfTestFailures = 3
	selfTestTimeout  = 10 * time.Second
	// selfTestSettle is how many self-tests in a row, selfTestSettleEvery
	// apart, a slot must pass before its gateway takes new flows. A freshly
	// attached interface can pass once while the cloud is still settling
	// its attachment and then drop the next flow.
	selfTestSettle      = 3
	selfTestSettleEvery = time.Second
	// gatewayHold is how long a gateway stays in use while its agent
	// restarts; longer than the controller's grace for the same restart.
	gatewayHold = 90 * time.Second
)

// Agent reconciles one node. Every change, whatever its source, leads to the
// same full computation, so there is one work item.
type Agent struct {
	// Client reads this node's pods, all nodes, namespaces, policies and
	// pools from the cache.
	Client client.Client
	// Agents reads the agent pods: gateways, and every node's WireGuard key.
	Agents client.Reader
	// AgentSelector selects agent pods; only they can be gateways.
	AgentSelector labels.Selector
	Dataplane     Dataplane
	Marks         *agent.Marks
	Prober        *agent.Prober
	// Node, Namespace and Pod identify this agent.
	Node, Namespace, Pod string
	// Excluded destinations are never steered.
	Excluded []netip.Prefix
	// SelfTestURL answers with the caller's public IPv4 address.
	SelfTestURL      string
	SelfTestInterval time.Duration
	SelfTest         SelfTester
	// Resync re-asserts the kernel state when nothing changes.
	Resync time.Duration
	Log    logr.Logger
	// StateDir keeps the gateway assignment being served across restarts;
	// empty keeps nothing.
	StateDir string
	// Inherited is the assignment the previous agent on this node served.
	// This agent serves it until the controller writes an assignment on
	// this pod, or until InheritUntil, so a restart does not move the slot.
	Inherited    string
	InheritUntil time.Time

	wake     chan event.GenericEvent
	ready    atomic.Bool
	mu       sync.Mutex
	test     selfTest
	problems string
	// down and crossZone are what reportPaths last logged.
	down      map[netip.Addr]bool
	crossZone []string
	savedRole string
	roleSaved bool
	hold      agent.Hold
}

// selfTest is the self-test of the slot being served.
type selfTest struct {
	key      string // slot and public IP under test; empty when idle
	cancel   context.CancelFunc
	done     chan struct{}
	passed   bool // has passed selfTestSettle times in a row since the key was set
	passes   int  // consecutive passes
	failures int  // consecutive failures
	err      error
}

// Ready reports whether the data path has been applied once; until then the
// pod is not ready.
func (a *Agent) Ready(*http.Request) error {
	if !a.ready.Load() {
		return fmt.Errorf("data path not applied yet")
	}
	return nil
}

// SetupWithManager watches everything the computation reads. agents is the
// cache behind a.Agents.
func (a *Agent) SetupWithManager(mgr ctrl.Manager, agents cache.Cache) error {
	a.wake = make(chan event.GenericEvent, 1)
	all := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: a.Node}}}
	})
	probes := make(chan event.GenericEvent, 1)
	go func() {
		for range a.Prober.Changed() {
			select {
			case probes <- event.GenericEvent{Object: &corev1.Node{}}:
			default:
			}
		}
	}()
	err := ctrl.NewControllerManagedBy(mgr).
		Named("agent").
		Watches(&corev1.Node{}, all).
		Watches(&corev1.Pod{}, all).
		Watches(&corev1.Namespace{}, all).
		Watches(&v1.EgressPolicy{}, all).
		Watches(&v1.ClusterEgressPolicy{}, all).
		Watches(&v1.EgressPool{}, all).
		WatchesRawSource(source.Kind[client.Object](agents, &corev1.Pod{}, all)).
		WatchesRawSource(source.Channel(probes, all)).
		WatchesRawSource(source.Channel(a.wake, all)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1, RateLimiter: retry.Limiter(a.Resync)}).
		Complete(a)
	if err != nil {
		return fmt.Errorf("set up agent: %w", err)
	}
	return nil
}

// Reconcile computes and applies the node's data path.
func (a *Agent) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	s, pools, err := a.snapshot(ctx)
	if err != nil {
		return reconcile.Result{}, err
	}
	// Publish the key first: gateways of an encrypted pool accept this
	// node's traffic only once they know it.
	a.setCondition(ctx, s.Self, v1.ConditionWireGuardKey, true, corev1.ConditionTrue, "Published", a.Dataplane.WireGuardKey())
	s.Self = a.inherit(s.Self)
	a.hold.For = gatewayHold
	requeue := a.Resync
	if left := a.hold.Apply(s, time.Now()); left > 0 && (requeue == 0 || left < requeue) {
		requeue = left
	}
	d, problems := agent.Compute(s, a.Marks)
	a.report(problems)
	problemCount.Set(float64(len(problems)))
	gatewaysDown.Set(float64(len(s.Down)))
	a.reportPaths(s.Down, d.CrossZone)

	st, err := a.Dataplane.Apply(&d)
	if err != nil {
		applyFailures.Inc()
		a.setCondition(ctx, s.Self, v1.ConditionDataplaneReady, true, corev1.ConditionFalse, "ApplyFailed", err.Error())
		a.setCondition(ctx, s.Self, v1.ConditionGatewayReady, d.Gateway != nil, corev1.ConditionFalse, "ApplyFailed", err.Error())
		return reconcile.Result{}, fmt.Errorf("apply data path: %w", err)
	}
	a.ready.Store(true)
	a.saveRole(s.Self, &d)
	for _, m := range []dataplane.Mode{dataplane.ModeNFTables, dataplane.ModeEBPF} {
		v := 0.0
		if st.Mode == m {
			v = 1
		}
		steeringMode.WithLabelValues(string(m)).Set(v)
	}
	divertedPackets.Store(st.Diverted)
	a.setCondition(ctx, s.Self, v1.ConditionDataplaneReady, true, corev1.ConditionTrue, "Applied", "the node's data path is applied")
	a.Prober.Update(a.targets(s, &d, pools))
	a.serve(d.Gateway, st)

	status, reason, msg := a.gatewayCondition(d.Gateway, st)
	a.setCondition(ctx, s.Self, v1.ConditionGatewayReady, d.Gateway != nil, status, reason, msg)
	return reconcile.Result{RequeueAfter: requeue}, nil
}

// inherit returns self carrying the inherited assignment while this pod has
// none of its own. The controller keeps the slot on this node while the
// agent restarts and writes the assignment on the new pod once it is up.
func (a *Agent) inherit(self *corev1.Pod) *corev1.Pod {
	if a.Inherited == "" || self == nil {
		return self
	}
	if self.Annotations[v1.AnnotationGateway] != "" || self.Annotations[v1.AnnotationDrainStarted] != "" || !time.Now().Before(a.InheritUntil) {
		a.Inherited = ""
		return self
	}
	var g v1.Gateway
	if err := json.Unmarshal([]byte(a.Inherited), &g); err != nil {
		a.Log.Error(err, "ignoring the saved gateway assignment")
		a.Inherited = ""
		return self
	}
	p := self.DeepCopy()
	if p.Labels == nil {
		p.Labels = map[string]string{}
	}
	if p.Annotations == nil {
		p.Annotations = map[string]string{}
	}
	p.Labels[v1.LabelGateway] = "true"
	p.Labels[v1.LabelPool] = g.Pool
	p.Annotations[v1.AnnotationGateway] = a.Inherited
	return p
}

// saveRole records the assignment just applied, for the next agent.
func (a *Agent) saveRole(self *corev1.Pod, d *agent.Desired) {
	role := ""
	if d.Gateway != nil && self != nil {
		role = self.Annotations[v1.AnnotationGateway]
	}
	if a.StateDir == "" || (a.roleSaved && role == a.savedRole) {
		return
	}
	if err := dataplane.SaveRole(a.StateDir, role); err != nil {
		a.Log.Error(err, "the next agent on this node may not keep serving the slot")
		return
	}
	a.savedRole, a.roleSaved = role, true
}

// Close stops probing and self-testing. The kernel state stays, the probe
// responder with it: traffic keeps flowing while the agent restarts.
func (a *Agent) Close() {
	a.Prober.Stop()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopSelfTest()
}

func (a *Agent) snapshot(ctx context.Context) (*agent.Snapshot, []v1.EgressPool, error) {
	s := &agent.Snapshot{Excluded: a.Excluded, Down: a.Prober.Down(), Node: &corev1.Node{}}
	if err := a.Client.Get(ctx, client.ObjectKey{Name: a.Node}, s.Node); err != nil {
		return nil, nil, fmt.Errorf("read node %s: %w", a.Node, err)
	}
	self := &corev1.Pod{}
	switch err := a.Client.Get(ctx, client.ObjectKey{Namespace: a.Namespace, Name: a.Pod}, self); {
	case err == nil:
		s.Self = self
	case !apierrors.IsNotFound(err):
		return nil, nil, fmt.Errorf("read own pod: %w", err)
	}

	var (
		nodes  corev1.NodeList
		pods   corev1.PodList
		nss    corev1.NamespaceList
		pols   v1.EgressPolicyList
		cpols  v1.ClusterEgressPolicyList
		pools  v1.EgressPoolList
		agents corev1.PodList
	)
	for _, l := range []struct {
		list client.ObjectList
		what string
	}{{&nodes, "nodes"}, {&pods, "pods"}, {&nss, "namespaces"}, {&pols, "egress policies"}, {&cpols, "cluster egress policies"}, {&pools, "egress pools"}} {
		if err := a.Client.List(ctx, l.list); err != nil {
			return nil, nil, fmt.Errorf("list %s: %w", l.what, err)
		}
	}
	if err := a.Agents.List(ctx, &agents, client.InNamespace(a.Namespace), client.MatchingLabelsSelector{Selector: a.AgentSelector}); err != nil {
		return nil, nil, fmt.Errorf("list agent pods: %w", err)
	}
	s.Nodes = nodes.Items
	for i := range pods.Items {
		if pods.Items[i].Spec.NodeName == a.Node {
			s.Pods = append(s.Pods, pods.Items[i])
		}
	}
	for i := range agents.Items {
		p := &agents.Items[i]
		if !a.AgentSelector.Matches(labels.Set(p.Labels)) {
			continue
		}
		s.Agents = append(s.Agents, *p)
		if p.Labels[v1.LabelGateway] == "true" {
			s.Gateways = append(s.Gateways, *p)
		}
	}
	if s.Self != nil && !a.AgentSelector.Matches(labels.Set(s.Self.Labels)) {
		return nil, nil, fmt.Errorf("own pod %s/%s does not match the agent selector %s", a.Namespace, a.Pod, a.AgentSelector)
	}
	s.Namespaces = nss.Items
	s.Policies = pols.Items
	s.ClusterPolicies = cpols.Items
	return s, pools.Items, nil
}

// targets probes every gateway with a mark, draining ones too: their
// established flows are flushed if they fail.
func (a *Agent) targets(s *agent.Snapshot, d *agent.Desired, pools []v1.EgressPool) map[netip.Addr]agent.ProbeTarget {
	byName := map[string]*v1.EgressPool{}
	for i := range pools {
		byName[pools[i].Name] = &pools[i]
	}
	ipOf := map[string]netip.Addr{}
	for i := range s.Nodes {
		if ip, ok := agent.NodeIP(&s.Nodes[i]); ok {
			ipOf[s.Nodes[i].Name] = ip
		}
	}
	poolOf := map[netip.Addr]string{}
	for i := range s.Gateways {
		if ip, ok := ipOf[s.Gateways[i].Spec.NodeName]; ok {
			poolOf[ip] = s.Gateways[i].Labels[v1.LabelPool]
		}
	}
	out := map[netip.Addr]agent.ProbeTarget{}
	for mark, ip := range d.Gateways {
		t := agent.ProbeTarget{Mark: mark, Interval: defaultProbeInterval, Threshold: defaultProbeThreshold}
		if p := byName[poolOf[ip]]; p != nil {
			if p.Spec.Probe.IntervalMilliseconds > 0 {
				t.Interval = time.Duration(p.Spec.Probe.IntervalMilliseconds) * time.Millisecond
			}
			if p.Spec.Probe.FailureThreshold > 0 {
				t.Threshold = int(p.Spec.Probe.FailureThreshold)
			}
		}
		out[ip] = t
	}
	return out
}

// serve answers probes while the slot carries traffic, and self-tests it.
func (a *Agent) serve(role *agent.GatewayRole, st dataplane.Status) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if role == nil {
		a.stopSelfTest()
		return
	}
	if st.Serving {
		a.startSelfTest(role)
	} else {
		a.stopSelfTest()
	}
	if st.Serving {
		gatewayServing.Set(1)
	} else {
		gatewayServing.Set(0)
	}
}

// gatewayCondition is the readiness the agent reports for its slot.
func (a *Agent) gatewayCondition(role *agent.GatewayRole, st dataplane.Status) (corev1.ConditionStatus, string, string) {
	if role == nil {
		return corev1.ConditionFalse, "NotAssigned", "this node serves no slot"
	}
	if !st.Serving {
		return corev1.ConditionFalse, "NotServing", st.Reason
	}
	a.mu.Lock()
	passed, failures, err := a.test.passed, a.test.failures, a.test.err
	a.mu.Unlock()
	switch {
	case failures >= selfTestFailures || (!passed && err != nil):
		return corev1.ConditionFalse, "SelfTestFailed", err.Error()
	case !passed:
		return corev1.ConditionFalse, v1.ReasonSelfTestPending, fmt.Sprintf("waiting for %d self-tests in a row through the slot", selfTestSettle)
	case role.Draining:
		return corev1.ConditionFalse, "Draining", "established flows continue; new flows go to other gateways"
	}
	return corev1.ConditionTrue, "Serving", v1.GatewayReadyMessage(role.SlotID)
}

// setCondition patches one of the agent's pod conditions when it changes.
// Unless create is set, a condition the pod does not carry is left out, so
// agents that never served a slot have no gateway condition.
func (a *Agent) setCondition(ctx context.Context, self *corev1.Pod, typ corev1.PodConditionType, create bool, status corev1.ConditionStatus, reason, msg string) {
	if self == nil {
		return
	}
	var cur *corev1.PodCondition
	for i := range self.Status.Conditions {
		if self.Status.Conditions[i].Type == typ {
			cur = &self.Status.Conditions[i]
		}
	}
	if cur == nil && !create {
		return
	}
	if cur != nil && cur.Status == status && cur.Reason == reason && cur.Message == msg {
		return
	}
	want := corev1.PodCondition{Type: typ, Status: status, Reason: reason, Message: msg, LastTransitionTime: metav1.Now()}
	if cur != nil && cur.Status == status {
		want.LastTransitionTime = cur.LastTransitionTime
	}
	raw, err := json.Marshal(map[string]any{"status": map[string]any{"conditions": []corev1.PodCondition{want}}})
	if err != nil {
		a.Log.Error(err, "encode condition", "condition", typ)
		return
	}
	if err := a.Client.Status().Patch(ctx, self, client.RawPatch(types.StrategicMergePatchType, raw)); err != nil {
		a.Log.Error(err, "report condition", "condition", typ, "status", status, "reason", reason)
		return
	}
	a.Log.Info("condition", "condition", typ, "status", status, "reason", reason, "message", msg)
}

// startSelfTest tests the slot now and every interval, until the slot or
// its public IP changes. Called with a.mu held.
func (a *Agent) startSelfTest(role *agent.GatewayRole) {
	key := role.SlotID + "/" + role.Public.String()
	if a.test.key == key {
		return
	}
	a.stopSelfTest()
	ctx, cancel := context.WithCancel(context.Background())
	a.test = selfTest{key: key, cancel: cancel, done: make(chan struct{})}
	go a.selfTestLoop(ctx, key, role.Public, a.test.done)
}

// stopSelfTest is called with a.mu held.
func (a *Agent) stopSelfTest() {
	if a.test.cancel == nil {
		return
	}
	a.test.cancel()
	done := a.test.done
	a.test = selfTest{}
	a.mu.Unlock()
	<-done
	a.mu.Lock()
}

func (a *Agent) selfTestLoop(ctx context.Context, key string, public netip.Addr, done chan struct{}) {
	defer close(done)
	for {
		tctx, cancel := context.WithTimeout(ctx, selfTestTimeout)
		err := a.SelfTest(tctx, a.Dataplane.DialGateway, a.SelfTestURL, public)
		cancel()
		if ctx.Err() != nil {
			return
		}
		a.mu.Lock()
		if a.test.key != key {
			a.mu.Unlock()
			return
		}
		before := a.test.passed && a.test.failures < selfTestFailures
		if err == nil {
			a.test.passes++
			a.test.failures, a.test.err = 0, nil
			if a.test.passes >= selfTestSettle {
				a.test.passed = true
			}
		} else {
			selfTestFailuresTotal.Inc()
			a.test.passes = 0
			a.test.failures++
			a.test.err = err
			a.Log.Error(err, "self-test through the slot failed", "consecutive", a.test.failures)
		}
		after := a.test.passed && a.test.failures < selfTestFailures
		first := a.test.failures == 1 && !a.test.passed
		every := a.SelfTestInterval
		if !a.test.passed && every > selfTestSettleEvery {
			every = selfTestSettleEvery
		}
		a.mu.Unlock()
		if before != after || first {
			select {
			case a.wake <- event.GenericEvent{Object: &corev1.Node{}}:
			default:
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// report logs the problems when they change.
// reportPaths logs when this node starts or stops seeing a gateway as down,
// and when a pool's new flows start or stop leaving through other zones.
func (a *Agent) reportPaths(down map[netip.Addr]bool, crossZone []string) {
	a.mu.Lock()
	was, wasCross := a.down, a.crossZone
	a.down, a.crossZone = maps.Clone(down), slices.Clone(crossZone)
	a.mu.Unlock()
	for _, ip := range slices.SortedFunc(maps.Keys(down), netip.Addr.Compare) {
		if !was[ip] {
			a.Log.Info("gateway unreachable from this node; new flows avoid it", "gateway", ip.String())
		}
	}
	for _, pool := range crossZone {
		if !slices.Contains(wasCross, pool) {
			a.Log.Info("no live gateway in this node's zone; new flows use other zones", "pool", pool)
		}
	}
	for _, ip := range slices.SortedFunc(maps.Keys(was), netip.Addr.Compare) {
		if !down[ip] {
			a.Log.Info("gateway reachable again", "gateway", ip.String())
		}
	}
	for _, pool := range wasCross {
		if !slices.Contains(crossZone, pool) {
			a.Log.Info("a gateway in this node's zone is live again; new flows stay in the zone", "pool", pool)
		}
	}
}

func (a *Agent) report(problems []string) {
	slices.Sort(problems)
	joined := strings.Join(problems, "\n")
	a.mu.Lock()
	changed := joined != a.problems
	a.problems = joined
	a.mu.Unlock()
	if changed {
		for _, p := range problems {
			a.Log.Info("problem", "detail", p)
		}
	}
}
