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

// Command agent runs on every Linux node. It steers selected traffic to
// gateways and, on a node the controller assigned a slot, serves as one. It
// holds no cloud credentials.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
	"github.com/Tessarac-LLC/natterjack/internal/agent"
	"github.com/Tessarac-LLC/natterjack/internal/agent/daemon"
	"github.com/Tessarac-LLC/natterjack/internal/agent/dataplane"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "natterjack agent:", err)
		os.Exit(1)
	}
}

func run() error {
	def := dataplane.DefaultConfig()
	var (
		nodeName      = flag.String("node-name", os.Getenv("NODE_NAME"), "name of this node")
		namespace     = flag.String("namespace", os.Getenv("POD_NAMESPACE"), "namespace of the agent pods")
		podName       = flag.String("pod-name", os.Getenv("POD_NAME"), "name of this agent's pod")
		agentSelector = flag.String("agent-selector", "app.kubernetes.io/name=natterjack-agent,app.kubernetes.io/component=agent", "label selector of the agent pods")
		excluded      = flag.String("excluded-cidrs", "", "comma-separated destinations never steered, in addition to private, shared, link-local and reserved ranges")
		markMask      = flag.String("mark-mask", fmt.Sprintf("%#08x", def.MarkMask), "packet mark bits the agent owns; one contiguous run of at least 4 bits")
		tableBase     = flag.Int("route-table-base", def.TableBase, "first policy routing table the agent owns")
		rulePriority  = flag.Int("rule-priority", def.RulePriority, "priority of the agent's policy routing rules")
		tunnelPort    = flag.Uint("tunnel-port", uint(def.TunnelPort), "GENEVE UDP port between nodes")
		probePort     = flag.Uint("probe-port", uint(def.ProbePort), "UDP port gateways answer probes on, inside their namespace")
		link          = flag.String("gateway-link", def.Link.String(), "link-local /30 between the host and gateway namespaces")
		stateDir      = flag.String("state-dir", def.StateDir, "directory that survives agent restarts and is emptied by a reboot (a tmpfs under /run)")
		mss           = flag.Uint("mss", uint(def.MSS), "TCP MSS ceiling for flows leaving a slot")
		selfTestURL   = flag.String("self-test-url", "https://checkip.amazonaws.com", "URL that answers with the caller's public IPv4 address")
		selfTestEvery = flag.Duration("self-test-interval", 30*time.Second, "how often a gateway tests its slot")
		resync        = flag.Duration("resync", 30*time.Second, "how often the data path is re-applied when nothing changes")
		metricsAddr   = flag.String("metrics-bind-address", ":9751", "HTTPS address for metrics, which require an authorized Kubernetes identity; 0 disables")
		probeAddr     = flag.String("health-probe-bind-address", ":9752", "address for liveness and readiness probes")
	)
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("agent")

	if *nodeName == "" || *namespace == "" || *podName == "" {
		return errors.New("--node-name, --namespace and --pod-name (or NODE_NAME, POD_NAMESPACE and POD_NAME) are required")
	}
	sel, err := labels.Parse(*agentSelector)
	if err != nil || sel.Empty() {
		return fmt.Errorf("--agent-selector %q must be a non-empty label selector", *agentSelector)
	}
	cfg := def
	mask, err := strconv.ParseUint(*markMask, 0, 32)
	if err != nil {
		return fmt.Errorf("--mark-mask %q: %w", *markMask, err)
	}
	if cfg.Link, err = netip.ParsePrefix(*link); err != nil {
		return fmt.Errorf("--gateway-link: %w", err)
	}
	if *tunnelPort > 65535 || *probePort > 65535 || *mss > 65535 {
		return errors.New("--tunnel-port, --probe-port and --mss must fit in 16 bits")
	}
	cfg.MarkMask, cfg.TableBase, cfg.RulePriority, cfg.StateDir = uint32(mask), *tableBase, *rulePriority, *stateDir
	cfg.TunnelPort, cfg.ProbePort, cfg.MSS = uint16(*tunnelPort), uint16(*probePort), uint16(*mss)
	exclude := append([]netip.Prefix(nil), agent.DefaultExcluded...)
	for _, s := range strings.Split(*excluded, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			return fmt.Errorf("--excluded-cidrs: %q is not an IPv4 CIDR", s)
		}
		exclude = append(exclude, p.Masked())
	}
	if *selfTestEvery < time.Second || *resync < time.Second {
		return errors.New("--self-test-interval and --resync must be at least a second")
	}

	marks, err := agent.NewMarks(cfg.MarkMask)
	if err != nil {
		return err //nolint:wrapcheck // the message names the flag value
	}
	dp, err := dataplane.New(cfg, log.WithName("dataplane"))
	if err != nil {
		return fmt.Errorf("data path: %w", err)
	}
	// Flows established before a restart carry their gateway's mark; keep
	// every mark where it was.
	saved, err := dataplane.LoadMarks(cfg.StateDir)
	if err != nil {
		return err //nolint:wrapcheck // names the file
	}
	marks.Restore(saved)
	dp.SetMarks(saved)

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return fmt.Errorf("register core types: %w", err)
	}
	if err := v1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("register natterjack types: %w", err)
	}
	restCfg := ctrl.GetConfigOrDie()
	direct, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	daemonSet, err := ownDaemonSet(direct, *namespace, *podName)
	if err != nil {
		return err
	}
	byObject := map[client.Object]cache.ByObject{
		// Every agent caches only its own node's pods.
		&corev1.Pod{}: {Field: fields.OneTermEqualSelector("spec.nodeName", *nodeName)},
	}
	if daemonSet != "" {
		byObject[&appsv1.DaemonSet{}] = cache.ByObject{
			Namespaces: map[string]cache.Config{*namespace: {}},
			Field:      fields.OneTermEqualSelector("metadata.name", daemonSet),
		}
	}
	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme: scheme,
		Cache: cache.Options{
			ByObject:         byObject,
			DefaultTransform: cache.TransformStripManagedFields(),
		},
		Metrics: metricsserver.Options{
			BindAddress:    *metricsAddr,
			SecureServing:  true,
			FilterProvider: filters.WithAuthenticationAndAuthorization,
		},
		HealthProbeBindAddress: *probeAddr,
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}
	// Gateway agent pods come from a second cache: a pod cache holds one
	// selector per namespace, and the first is taken by this node's pods.
	gateways, err := cache.New(restCfg, cache.Options{
		Scheme:            scheme,
		Mapper:            mgr.GetRESTMapper(),
		DefaultNamespaces: map[string]cache.Config{*namespace: {}},
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Pod{}: {Label: labels.SelectorFromSet(labels.Set{v1.LabelGateway: "true"})},
		},
		DefaultTransform: cache.TransformStripManagedFields(),
	})
	if err != nil {
		return fmt.Errorf("create gateway cache: %w", err)
	}
	if err := mgr.Add(gateways); err != nil {
		return fmt.Errorf("start gateway cache: %w", err)
	}

	a := &daemon.Agent{
		Client:           mgr.GetClient(),
		Gateways:         gateways,
		AgentSelector:    sel,
		Dataplane:        dp,
		Marks:            marks,
		Prober:           agent.NewProber(dataplane.DialProbe, netip.AddrPortFrom(cfg.GatewayAddr(), cfg.ProbePort)),
		Node:             *nodeName,
		Namespace:        *namespace,
		Pod:              *podName,
		Excluded:         exclude,
		SelfTestURL:      *selfTestURL,
		SelfTestInterval: *selfTestEvery,
		SelfTest:         agent.SelfTest,
		Resync:           *resync,
		Log:              log,
	}
	if err := a.SetupWithManager(mgr, gateways); err != nil {
		return err //nolint:wrapcheck // already wrapped
	}
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("add liveness check: %w", err)
	}
	if err := mgr.AddReadyzCheck("dataplane", a.Ready); err != nil {
		return fmt.Errorf("add readiness check: %w", err)
	}

	removal := &daemon.RemovalWatch{}
	if daemonSet != "" {
		if err := removal.Watch(context.Background(), mgr.GetCache(), daemonSet); err != nil {
			return err //nolint:wrapcheck // already wrapped
		}
	}

	ctx := ctrl.SetupSignalHandler()
	runErr := mgr.Start(ctx)
	a.Close()
	if runErr != nil {
		return fmt.Errorf("run manager: %w", runErr)
	}
	if !removal.Removed() && !daemonSetGone(direct, *namespace, daemonSet, log) {
		// An upgrade, a node drain or a crash: the data path stays and
		// traffic keeps flowing until the agent is back.
		return nil
	}
	log.Info("agent DaemonSet removed; removing the data path")
	if err := dp.Teardown(); err != nil {
		return fmt.Errorf("remove the data path: %w", err)
	}
	return nil
}

// ownDaemonSet names the DaemonSet that runs this pod, or "" when none does.
func ownDaemonSet(c client.Reader, namespace, podName string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pod := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: podName}, pod); err != nil {
		return "", fmt.Errorf("read own pod %s/%s: %w", namespace, podName, err)
	}
	if owner := metav1.GetControllerOf(pod); owner != nil && owner.Kind == "DaemonSet" {
		return owner.Name, nil
	}
	return "", nil
}

// daemonSetGone asks the API server, at shutdown, whether the agent's
// DaemonSet is gone or being deleted, for a removal the watch missed. When
// the answer is unknown the data path stays.
func daemonSetGone(c client.Reader, namespace, name string, log logr.Logger) bool {
	if name == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ds := &appsv1.DaemonSet{}
	err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, ds)
	switch {
	case apierrors.IsNotFound(err), err == nil && ds.DeletionTimestamp != nil:
		return true
	case err != nil:
		log.Error(err, "cannot read the agent DaemonSet at shutdown; leaving the data path in place")
	}
	return false
}
