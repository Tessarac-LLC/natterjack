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
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
	"github.com/Tessarac-LLC/natterjack/internal/agent"
	"github.com/Tessarac-LLC/natterjack/internal/agent/dataplane"
)

const ns = "natterjack"

var (
	k8s        client.Client
	restCfg    *rest.Config
	testScheme *runtime.Scheme
)

func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		println("KUBEBUILDER_ASSETS is not set; run `make test`")
		os.Exit(1)
	}
	env := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "..", "config", "crd")}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		panic(err)
	}
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := v1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	restCfg, testScheme = cfg, scheme
	if k8s, err = client.New(cfg, client.Options{Scheme: scheme}); err != nil {
		panic(err)
	}
	if err := k8s.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		panic(err)
	}
	code := m.Run()
	if err := env.Stop(); err != nil {
		panic(err)
	}
	os.Exit(code)
}

// fakeDataplane records what the agent applies.
type fakeDataplane struct {
	mu      sync.Mutex
	applied []agent.Desired
	status  dataplane.Status
	fail    error
	conns   []net.PacketConn
}

func (f *fakeDataplane) Apply(want *agent.Desired) (dataplane.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, *want)
	return f.status, f.fail
}

func (f *fakeDataplane) ListenProbe(ctx context.Context) (net.PacketConn, error) {
	c, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err == nil {
		f.mu.Lock()
		f.conns = append(f.conns, c)
		f.mu.Unlock()
	}
	return c, err
}

func (*fakeDataplane) DialGateway(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not used")
}

func (f *fakeDataplane) last() agent.Desired {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied[len(f.applied)-1]
}

func create(t *testing.T, obj client.Object) {
	t.Helper()
	if err := k8s.Create(t.Context(), obj); err != nil {
		t.Fatal(err)
	}
}

func node(t *testing.T, name, addr string) {
	t.Helper()
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{corev1.LabelTopologyZone: "zone-a"}}}
	create(t, n)
	n.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: addr}}
	if err := k8s.Status().Update(t.Context(), n); err != nil {
		t.Fatal(err)
	}
}

var agentLabels = map[string]string{"app.kubernetes.io/name": "natterjack-agent", "app.kubernetes.io/component": "agent"}

func agentPod(t *testing.T, nodeName string, gw *v1.Gateway) *corev1.Pod {
	t.Helper()
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "agent-" + nodeName, Labels: map[string]string{}, Annotations: map[string]string{}},
		Spec:       corev1.PodSpec{NodeName: nodeName, HostNetwork: true, Containers: []corev1.Container{{Name: "agent", Image: "agent"}}},
	}
	for k, v := range agentLabels {
		p.Labels[k] = v
	}
	if gw != nil {
		raw, err := json.Marshal(gw)
		if err != nil {
			t.Fatal(err)
		}
		p.Labels[v1.LabelGateway], p.Labels[v1.LabelPool] = "true", gw.Pool
		p.Annotations[v1.AnnotationGateway] = string(raw)
	}
	create(t, p)
	return p
}

func condition(t *testing.T, name string) *corev1.PodCondition {
	t.Helper()
	p := &corev1.Pod{}
	if err := k8s.Get(t.Context(), client.ObjectKey{Namespace: ns, Name: name}, p); err != nil {
		t.Fatal(err)
	}
	for i := range p.Status.Conditions {
		if p.Status.Conditions[i].Type == v1.ConditionGatewayReady {
			return &p.Status.Conditions[i]
		}
	}
	return nil
}

// selfTests hands out the result of each self-test as the test sends it.
type selfTests chan error

func (s selfTests) run(ctx context.Context, _ agent.Dialer, _ string, _ netip.Addr) error {
	select {
	case err := <-s:
		return err
	case <-ctx.Done():
		return ctx.Err() //nolint:wrapcheck // test double
	}
}

func TestGatewayLifecycle(t *testing.T) {
	node(t, "src-1", "10.0.1.50")
	node(t, "gw-1", "10.0.1.10")
	create(t, &v1.EgressPool{ObjectMeta: metav1.ObjectMeta{Name: "web"}, Spec: v1.EgressPoolSpec{Probe: v1.Probe{IntervalMilliseconds: 40, FailureThreshold: 5}}})
	gw := v1.Gateway{Pool: "web", SlotID: "eni-1", MAC: "02:00:00:00:00:01", PrivateIP: "10.0.9.20", SubnetCIDR: "10.0.9.0/24", PublicIP: "203.0.113.9", Tunnel: v1.TunnelGeneve}
	self := agentPod(t, "gw-1", &gw)
	// A pod outside the agent selector cannot pose as a gateway.
	impostor := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "impostor", Labels: map[string]string{v1.LabelGateway: "true", v1.LabelPool: "web"}},
		Spec:       corev1.PodSpec{NodeName: "src-1", Containers: []corev1.Container{{Name: "x", Image: "x"}}},
	}
	create(t, impostor)

	marks, err := agent.NewMarks(0x00ff0000)
	if err != nil {
		t.Fatal(err)
	}
	// No tunnel here: every probe goes unanswered, so the gateway is soon
	// down from this node, at the pool's probe settings.
	prober := agent.NewProber(func(context.Context, uint32, netip.AddrPort) (net.Conn, error) {
		return nil, errors.New("no tunnel in this test")
	}, netip.MustParseAddrPort("169.254.73.2:6086"))
	tests := make(selfTests)
	dp := &fakeDataplane{status: dataplane.Status{Serving: true}}
	a := &Agent{
		Client: k8s, Gateways: k8s, AgentSelector: labels.SelectorFromSet(agentLabels),
		Dataplane: dp, Marks: marks, Prober: prober,
		Node: "gw-1", Namespace: ns, Pod: self.Name,
		Excluded: agent.DefaultExcluded, SelfTestURL: "https://checkip.example", SelfTestInterval: 20 * time.Millisecond,
		SelfTest: tests.run, Resync: time.Minute, Log: logr.Discard(),
		wake: make(chan event.GenericEvent, 1),
	}
	defer a.Close()
	reconcileOnce := func() {
		t.Helper()
		if _, err := a.Reconcile(t.Context(), reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
	}
	want := func(status corev1.ConditionStatus, reason, msg string) {
		t.Helper()
		c := condition(t, self.Name)
		if c == nil || c.Status != status || c.Reason != reason || (msg != "" && c.Message != msg) {
			t.Fatalf("gateway readiness %+v; want %s %s %q", c, status, reason, msg)
		}
	}

	reconcileOnce()
	d := dp.last()
	if d.Gateway == nil || d.Gateway.SlotID != "eni-1" || d.Gateway.Public != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("gateway role %+v", d.Gateway)
	}
	if len(d.Gateways) != 1 || d.Gateways[0x00010000] != netip.MustParseAddr("10.0.1.10") {
		t.Fatalf("gateways %v; want only the agent gateway, not the impostor", d.Gateways)
	}
	want(corev1.ConditionFalse, "SelfTestPending", "")

	// The first self-test passes: the gateway is ready, for this slot only.
	tests <- nil
	<-a.wake
	reconcileOnce()
	want(corev1.ConditionTrue, "Serving", v1.GatewayReadyMessage("eni-1"))

	// It answers probes while serving.
	c, err := (&net.Dialer{}).DialContext(t.Context(), "udp4", dp.conns[0].LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("NJP100000001")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if b := make([]byte, 32); func() bool { n, err := c.Read(b); return err != nil || n != 12 }() {
		t.Fatal("a serving gateway did not answer a probe")
	}

	// One failed self-test is not enough to leave service; three are.
	boom := errors.New("checkip unreachable")
	tests <- boom
	tests <- boom
	reconcileOnce()
	want(corev1.ConditionTrue, "Serving", "")
	tests <- boom
	<-a.wake
	reconcileOnce()
	want(corev1.ConditionFalse, "SelfTestFailed", boom.Error())
	tests <- nil
	<-a.wake
	reconcileOnce()
	want(corev1.ConditionTrue, "Serving", "")

	// Probes through the (absent) tunnel fail, at the pool's settings.
	deadline := time.Now().Add(2 * time.Second)
	for !prober.Down()[netip.MustParseAddr("10.0.1.10")] {
		if time.Now().After(deadline) {
			t.Fatal("unanswered probes never marked the gateway down")
		}
		time.Sleep(10 * time.Millisecond)
	}
	reconcileOnce()
	if d := dp.last(); len(d.Failed) != 1 {
		t.Fatalf("failed marks %v; flows pinned to a down gateway must be flushed", d.Failed)
	}

	// Draining: not ready for new flows.
	self = &corev1.Pod{}
	if err := k8s.Get(t.Context(), client.ObjectKey{Namespace: ns, Name: "agent-gw-1"}, self); err != nil {
		t.Fatal(err)
	}
	self.Annotations[v1.AnnotationDrainStarted] = time.Now().UTC().Format(time.RFC3339)
	if err := k8s.Update(t.Context(), self); err != nil {
		t.Fatal(err)
	}
	reconcileOnce()
	want(corev1.ConditionFalse, "Draining", "")

	// Unassigned: the condition says so and probes go unanswered.
	if err := k8s.Get(t.Context(), client.ObjectKey{Namespace: ns, Name: "agent-gw-1"}, self); err != nil {
		t.Fatal(err)
	}
	delete(self.Annotations, v1.AnnotationGateway)
	delete(self.Annotations, v1.AnnotationDrainStarted)
	delete(self.Labels, v1.LabelGateway)
	delete(self.Labels, v1.LabelPool)
	if err := k8s.Update(t.Context(), self); err != nil {
		t.Fatal(err)
	}
	reconcileOnce()
	want(corev1.ConditionFalse, "NotAssigned", "")
	if dp.last().Gateway != nil || a.responder != nil {
		t.Fatal("an unassigned agent kept its gateway role or probe responder")
	}

	// A failed apply is reported and retried.
	dp.fail = errors.New("nftables: operation not permitted")
	if _, err := a.Reconcile(t.Context(), reconcile.Request{}); err == nil {
		t.Fatal("apply failure not returned for retry")
	}
	want(corev1.ConditionFalse, "ApplyFailed", "")
}

func TestNonGatewayLeavesItsPodAlone(t *testing.T) {
	node(t, "plain-1", "10.0.1.60")
	self := agentPod(t, "plain-1", nil)
	marks, err := agent.NewMarks(0x00ff0000)
	if err != nil {
		t.Fatal(err)
	}
	dp := &fakeDataplane{}
	a := &Agent{
		Client: k8s, Gateways: k8s, AgentSelector: labels.SelectorFromSet(agentLabels),
		Dataplane: dp, Marks: marks, Prober: agent.NewProber(func(context.Context, uint32, netip.AddrPort) (net.Conn, error) {
			return nil, errors.New("no tunnel in this test")
		}, netip.AddrPort{}),
		Node: "plain-1", Namespace: ns, Pod: self.Name, Resync: time.Minute, Log: logr.Discard(),
	}
	defer a.Close()
	if _, err := a.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if c := condition(t, self.Name); c != nil {
		t.Fatalf("an agent that never served wrote %+v", c)
	}
	if err := a.Ready(nil); err != nil {
		t.Fatal(err)
	}
}
