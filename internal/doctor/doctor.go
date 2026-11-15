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

// Package doctor checks a Natterjack installation and reports, before any
// traffic moves, whether it is ready to carry egress traffic. It only reads.
package doctor

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/version"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
)

// MinKubernetes is the oldest Kubernetes minor version Natterjack supports:
// the first where ValidatingAdmissionPolicy and the pod-name claim of bound
// ServiceAccount tokens are both GA.
const MinKubernetes = 34

// LeaseName is the controller's leader election Lease.
const LeaseName = "natterjack-controller"

// Severity of a finding. Any Fail makes the report a no-go.
type Severity string

// Severities.
const (
	OK   Severity = "ok"
	Warn Severity = "warn"
	Fail Severity = "fail"
)

// Finding is the result of one check.
type Finding struct {
	Check    string   `json:"check"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

// Report is the outcome of a doctor run.
type Report struct {
	Namespace string    `json:"namespace,omitempty"`
	Release   string    `json:"release,omitempty"`
	Findings  []Finding `json:"findings"`
	// Go is true when nothing failed.
	Go bool `json:"go"`
}

// Options selects the installation to check and how to reach it.
type Options struct {
	Client client.Reader
	// ServerVersion returns the API server's version.
	ServerVersion func() (*version.Info, error)
	// Namespace and Release narrow the search when more than one
	// installation exists. Empty means any.
	Namespace string
	Release   string
	// Now is the current time; zero means time.Now.
	Now time.Time
}

type run struct {
	Options
	report    Report
	partOf    labels.Selector
	release   labels.Set
	installed map[string]bool
}

// Run performs every check and returns the report. It fails only when it
// cannot run at all; everything it finds wrong is in the report.
func Run(ctx context.Context, o Options) Report {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	r := &run{Options: o, partOf: labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": "natterjack"}), installed: map[string]bool{}}
	r.kubernetes()
	if r.locate(ctx) {
		r.controller(ctx)
		r.agents(ctx)
		r.admission(ctx)
	}
	r.pools(ctx)
	r.policies(ctx)
	r.report.Go = !slices.ContainsFunc(r.report.Findings, func(f Finding) bool { return f.Severity == Fail })
	return r.report
}

func (r *run) add(check string, sev Severity, format string, args ...any) {
	r.report.Findings = append(r.report.Findings, Finding{Check: check, Severity: sev, Message: fmt.Sprintf(format, args...)})
}

func (r *run) kubernetes() {
	if r.ServerVersion == nil {
		return
	}
	v, err := r.ServerVersion()
	if err != nil {
		r.add("kubernetes", Fail, "cannot read the API server version: %v", err)
		return
	}
	minor, err := strconv.Atoi(strings.TrimRight(v.Minor, "+"))
	if err != nil || v.Major != "1" {
		r.add("kubernetes", Warn, "cannot parse the API server version %q", v.GitVersion)
		return
	}
	if minor < MinKubernetes {
		r.add("kubernetes", Fail, "Kubernetes %s is older than 1.%d, which Natterjack needs for ValidatingAdmissionPolicy and pod-bound ServiceAccount tokens", v.GitVersion, MinKubernetes)
		return
	}
	r.add("kubernetes", OK, "Kubernetes %s", v.GitVersion)
}

// locate finds the installation from its workloads and reports whether one
// was found.
func (r *run) locate(ctx context.Context) bool {
	var deps appsv1.DeploymentList
	var sets appsv1.DaemonSetList
	opts := []client.ListOption{client.MatchingLabelsSelector{Selector: r.partOf}}
	if r.Namespace != "" {
		opts = append(opts, client.InNamespace(r.Namespace))
	}
	if err := r.Client.List(ctx, &deps, opts...); err != nil {
		r.add("install", Fail, "cannot list deployments: %v", err)
		return false
	}
	if err := r.Client.List(ctx, &sets, opts...); err != nil {
		r.add("install", Fail, "cannot list daemonsets: %v", err)
		return false
	}
	found := map[string]bool{}
	note := func(o metav1.Object) {
		rel := o.GetLabels()["app.kubernetes.io/instance"]
		if r.Release == "" || rel == r.Release {
			found[o.GetNamespace()+"/"+rel] = true
		}
	}
	for i := range deps.Items {
		note(&deps.Items[i])
	}
	for i := range sets.Items {
		note(&sets.Items[i])
	}
	switch len(found) {
	case 0:
		r.add("install", Fail, "no Natterjack release found%s; install the chart, or pass --namespace and --release", r.scope())
		return false
	case 1:
	default:
		r.add("install", Fail, "found %d releases (%s); pass --namespace and --release to choose one",
			len(found), strings.Join(slices.Sorted(maps.Keys(found)), ", "))
		return false
	}
	for k := range found {
		r.report.Namespace, r.report.Release, _ = strings.Cut(k, "/")
	}
	// One selector: a second label option on a List replaces the first.
	r.release = labels.Set{"app.kubernetes.io/part-of": "natterjack", "app.kubernetes.io/instance": r.report.Release}
	r.add("install", OK, "release %s in namespace %s", r.report.Release, r.report.Namespace)
	return true
}

func (r *run) scope() string {
	var s []string
	if r.Namespace != "" {
		s = append(s, "in namespace "+r.Namespace)
	}
	if r.Release != "" {
		s = append(s, "named "+r.Release)
	}
	if len(s) == 0 {
		return ""
	}
	return " " + strings.Join(s, " ")
}

func (r *run) component(name string) client.ListOption {
	set := labels.Merge(r.release, labels.Set{"app.kubernetes.io/name": "natterjack-" + name})
	return client.MatchingLabels(set)
}

func (r *run) pods(ctx context.Context, name string) ([]corev1.Pod, error) {
	var pods corev1.PodList
	if err := r.Client.List(ctx, &pods, client.InNamespace(r.report.Namespace), r.component(name)); err != nil {
		return nil, err
	}
	slices.SortFunc(pods.Items, func(a, b corev1.Pod) int { return cmp.Compare(a.Name, b.Name) })
	return pods.Items, nil
}

func (r *run) controller(ctx context.Context) {
	var deps appsv1.DeploymentList
	if err := r.Client.List(ctx, &deps, client.InNamespace(r.report.Namespace), r.component("controller")); err != nil {
		r.add("controller", Fail, "cannot list the controller deployment: %v", err)
		return
	}
	if len(deps.Items) == 0 {
		r.add("controller", Warn, "this release installs no controller; another release must run one, or no slot is ever attached")
		return
	}
	r.installed["controller"] = true
	pods, err := r.pods(ctx, "controller")
	if err != nil {
		r.add("controller", Fail, "cannot list controller pods: %v", err)
		return
	}
	ready := 0
	for i := range pods {
		if podReady(&pods[i]) {
			ready++
			continue
		}
		r.add("controller", Warn, "pod %s is not ready: %s", pods[i].Name, notReady(&pods[i],
			"a controller is not ready while it cannot read the cloud; see the CloudAccess condition of each pool"))
	}
	want := int32(1)
	if deps.Items[0].Spec.Replicas != nil {
		want = *deps.Items[0].Spec.Replicas
	}
	if ready == 0 {
		r.add("controller", Fail, "no controller replica is ready (0 of %d)", want)
	} else {
		r.add("controller", OK, "%d of %d replicas ready", ready, want)
	}

	var lease coordinationv1.Lease
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: r.report.Namespace, Name: LeaseName}, &lease); err != nil {
		r.add("controller leader", Fail, "no leader election Lease %s/%s: %v", r.report.Namespace, LeaseName, err)
		return
	}
	holder := ""
	if lease.Spec.HolderIdentity != nil {
		holder = *lease.Spec.HolderIdentity
	}
	expired := lease.Spec.RenewTime == nil || lease.Spec.LeaseDurationSeconds == nil ||
		r.Now.After(lease.Spec.RenewTime.Add(time.Duration(*lease.Spec.LeaseDurationSeconds)*time.Second))
	pod, _, _ := strings.Cut(holder, "_")
	running := slices.ContainsFunc(pods, func(p corev1.Pod) bool { return p.Name == pod && p.Status.Phase == corev1.PodRunning })
	switch {
	case holder == "" || expired:
		r.add("controller leader", Fail, "no controller holds the leader Lease, so no slot is attached or moved")
	case !running:
		r.add("controller leader", Fail, "the leader Lease is held by %s, which is not a running controller pod of this release", pod)
	default:
		r.add("controller leader", OK, "%s leads", pod)
	}
}

func (r *run) agents(ctx context.Context) {
	var sets appsv1.DaemonSetList
	if err := r.Client.List(ctx, &sets, client.InNamespace(r.report.Namespace), r.component("agent")); err != nil {
		r.add("agents", Fail, "cannot list the agent daemonset: %v", err)
		return
	}
	if len(sets.Items) == 0 {
		r.add("agents", Fail, "this release installs no agent; no node steers traffic and no slot can serve")
		return
	}
	r.installed["agent"] = true
	pods, err := r.pods(ctx, "agent")
	if err != nil {
		r.add("agents", Fail, "cannot list agent pods: %v", err)
		return
	}
	var nodes corev1.NodeList
	if err := r.Client.List(ctx, &nodes); err != nil {
		r.add("agents", Fail, "cannot list nodes: %v", err)
		return
	}
	byNode := map[string]*corev1.Pod{}
	for i := range pods {
		if pods[i].Spec.NodeName != "" && pods[i].DeletionTimestamp == nil {
			byNode[pods[i].Spec.NodeName] = &pods[i]
		}
	}
	selector := labels.SelectorFromSet(sets.Items[0].Spec.Template.Spec.NodeSelector)
	healthy, total := 0, 0
	for _, n := range nodes.Items {
		if !selector.Matches(labels.Set(n.Labels)) {
			continue
		}
		total++
		p := byNode[n.Name]
		if p == nil {
			r.add("agents", Fail, "node %s has no agent pod, so its traffic is not steered and it cannot serve a slot", n.Name)
			continue
		}
		if !podReady(p) {
			r.add("agents", Fail, "node %s: agent %s is not ready: %s", n.Name, p.Name, notReady(p, "the data path is not applied yet"))
			continue
		}
		c := podCondition(p, v1.ConditionDataplaneReady)
		switch {
		case c == nil:
			r.add("agents", Warn, "node %s: agent %s has not reported its data path", n.Name, p.Name)
		case c.Status != corev1.ConditionTrue:
			r.add("agents", Fail, "node %s: data path not applied: %s", n.Name, c.Message)
		default:
			healthy++
		}
	}
	if total > 0 && healthy == total {
		r.add("agents", OK, "data path applied on all %d nodes", total)
	} else if total == 0 {
		r.add("agents", Fail, "no node matches the agent's node selector %s", selector)
	}

	gateways, ready := 0, 0
	for i := range pods {
		p := &pods[i]
		if p.Labels[v1.LabelGateway] != "true" {
			continue
		}
		gateways++
		var gw v1.Gateway
		if err := json.Unmarshal([]byte(p.Annotations[v1.AnnotationGateway]), &gw); err == nil && v1.GatewayReady(p, gw.SlotID) {
			ready++
			continue
		}
		msg := "no readiness reported yet"
		if c := podCondition(p, v1.ConditionGatewayReady); c != nil {
			msg = c.Reason + ": " + c.Message
		}
		r.add("gateways", Warn, "node %s holds slot %s but does not serve it: %s", p.Spec.NodeName, cmp.Or(gw.SlotID, "(unreadable assignment)"), msg)
	}
	if gateways > 0 {
		sev := OK
		if ready == 0 {
			sev = Fail
		}
		r.add("gateways", sev, "%d of %d gateways serve their slot", ready, gateways)
	}
}

func (r *run) admission(ctx context.Context) {
	var policies admissionv1.ValidatingAdmissionPolicyList
	var bindings admissionv1.ValidatingAdmissionPolicyBindingList
	if err := r.Client.List(ctx, &policies, client.MatchingLabels(r.release)); err != nil {
		r.add("admission", Fail, "cannot list admission policies: %v", err)
		return
	}
	if err := r.Client.List(ctx, &bindings, client.MatchingLabels(r.release)); err != nil {
		r.add("admission", Fail, "cannot list admission policy bindings: %v", err)
		return
	}
	bound := map[string]bool{}
	for _, b := range bindings.Items {
		if slices.Contains(b.Spec.ValidationActions, admissionv1.Deny) {
			bound[b.Spec.PolicyName] = true
		}
	}
	for _, component := range []string{"agent", "controller"} {
		if !r.installed[component] {
			continue
		}
		i := slices.IndexFunc(policies.Items, func(p admissionv1.ValidatingAdmissionPolicy) bool {
			return p.Labels["app.kubernetes.io/component"] == component
		})
		switch {
		case i < 0:
			r.add("admission", Fail, "the %s admission policy is missing, so a stolen %s token is not confined; reinstall the chart", component, component)
		case !bound[policies.Items[i].Name]:
			r.add("admission", Fail, "the %s admission policy %s has no denying binding; reinstall the chart", component, policies.Items[i].Name)
		default:
			r.add("admission", OK, "%s policy %s enforced", component, policies.Items[i].Name)
		}
	}
}

func (r *run) pools(ctx context.Context) {
	var pools v1.EgressPoolList
	if err := r.Client.List(ctx, &pools); err != nil {
		if meta.IsNoMatchError(err) {
			r.add("pools", Fail, "the Natterjack CRDs are not installed")
		} else {
			r.add("pools", Fail, "cannot list egress pools: %v", err)
		}
		return
	}
	if len(pools.Items) == 0 {
		r.add("pools", Fail, "no EgressPool exists; create one so the controller attaches slots")
		return
	}
	slices.SortFunc(pools.Items, func(a, b v1.EgressPool) int { return cmp.Compare(a.Name, b.Name) })
	for i := range pools.Items {
		r.pool(&pools.Items[i])
	}
}

func (r *run) pool(p *v1.EgressPool) {
	check := "pool " + p.Name
	conds := p.Status.Conditions
	if cloud := meta.FindStatusCondition(conds, v1.ConditionCloudAccess); cloud != nil && cloud.Status == metav1.ConditionFalse {
		r.add(check, Fail, "the controller cannot read the cloud: %s", cloud.Message)
		return
	}
	ready := meta.FindStatusCondition(conds, v1.ConditionReady)
	if ready == nil || p.Status.ObservedGeneration < p.Generation {
		r.add(check, Fail, "not yet reconciled by the controller (generation %d, observed %d)", p.Generation, p.Status.ObservedGeneration)
		return
	}
	if ready.Status != metav1.ConditionTrue {
		r.add(check, Fail, "%s", ready.Message)
	} else {
		r.add(check, OK, "%s; public IPs %s", ready.Message, cmp.Or(strings.Join(p.Status.PublicIPs, ", "), "none"))
	}
	for _, t := range []string{v1.ConditionDegraded, v1.ConditionCrossZoneEgress, v1.ConditionSlotsQuarantined, v1.ConditionSlotsUnschedulable, v1.ConditionForeignSlots} {
		if c := meta.FindStatusCondition(conds, t); c != nil && c.Status == metav1.ConditionTrue {
			r.add(check, Warn, "%s: %s", t, c.Message)
		}
	}
	for _, s := range p.Status.Slots {
		switch s.State {
		case v1.SlotQuarantined, v1.SlotUnschedulable, v1.SlotForeign:
			r.add(check, Warn, "slot %s in %s is %s: %s", s.ID, s.Zone, s.State, s.Reason)
		}
	}
}

func (r *run) policies(ctx context.Context) {
	var ns v1.EgressPolicyList
	var cl v1.ClusterEgressPolicyList
	if err := r.Client.List(ctx, &ns); err != nil {
		if !meta.IsNoMatchError(err) {
			r.add("policies", Fail, "cannot list egress policies: %v", err)
		}
		return
	}
	if err := r.Client.List(ctx, &cl); err != nil {
		r.add("policies", Fail, "cannot list cluster egress policies: %v", err)
		return
	}
	accepted := 0
	check := func(kind, name string, st v1.PolicyStatus) {
		c := meta.FindStatusCondition(st.Conditions, v1.ConditionAccepted)
		switch {
		case c == nil:
			r.add("policies", Warn, "%s %s is not yet processed", kind, name)
		case c.Status != metav1.ConditionTrue:
			r.add("policies", Fail, "%s %s is not in force: %s", kind, name, c.Message)
		default:
			accepted++
		}
	}
	for _, p := range ns.Items {
		check("EgressPolicy", p.Namespace+"/"+p.Name, p.Status)
	}
	for _, p := range cl.Items {
		check("ClusterEgressPolicy", p.Name, p.Status)
	}
	if len(ns.Items)+len(cl.Items) == 0 {
		r.add("policies", OK, "no policy yet; traffic moves only once a policy selects workloads")
	} else if accepted > 0 {
		r.add("policies", OK, "%d of %d policies in force", accepted, len(ns.Items)+len(cl.Items))
	}
}

func podReady(p *corev1.Pod) bool {
	if p.Status.Phase != corev1.PodRunning || p.DeletionTimestamp != nil {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// notReady explains why a pod is not ready, from its containers, or falls
// back to the given reason.
func notReady(p *corev1.Pod, fallback string) string {
	for _, s := range p.Status.ContainerStatuses {
		if w := s.State.Waiting; w != nil {
			return strings.TrimSuffix(w.Reason+": "+w.Message, ": ")
		}
		if t := s.State.Terminated; t != nil {
			return strings.TrimSuffix(fmt.Sprintf("%s (exit %d): %s", t.Reason, t.ExitCode, t.Message), ": ")
		}
	}
	if p.Status.Phase != corev1.PodRunning {
		return "phase " + string(p.Status.Phase)
	}
	return fallback
}

func podCondition(p *corev1.Pod, t corev1.PodConditionType) *corev1.PodCondition {
	for i := range p.Status.Conditions {
		if p.Status.Conditions[i].Type == t {
			return &p.Status.Conditions[i]
		}
	}
	return nil
}
