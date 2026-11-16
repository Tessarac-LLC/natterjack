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

// Command controller assigns egress slots to gateway nodes. It is the only
// Natterjack component with cloud credentials.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
	awsprovider "github.com/Tessarac-LLC/natterjack/internal/cloud/aws"
	"github.com/Tessarac-LLC/natterjack/internal/controller"
	"github.com/Tessarac-LLC/natterjack/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "natterjack controller:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		clusterName    = flag.String("cluster-name", "", "value of the natterjack.io/cluster tag on this cluster's slots (required)")
		namespace      = flag.String("namespace", os.Getenv("POD_NAMESPACE"), "namespace of the controller and agent pods")
		serviceAccount = flag.String("service-account", os.Getenv("SERVICE_ACCOUNT"), "ServiceAccount the controller runs as, named in cloud credential errors")
		agentSelector  = flag.String("agent-selector", "app.kubernetes.io/name=natterjack-agent,app.kubernetes.io/component=agent", "label selector of the agent pods")
		metricsAddr    = flag.String("metrics-bind-address", ":8443", "HTTPS address for metrics, which require an authorized Kubernetes identity")
		probeAddr      = flag.String("health-probe-bind-address", ":8081", "address for liveness and readiness probes")
		leaderElect    = flag.Bool("leader-elect", true, "elect a leader so only one replica acts")
		resync         = flag.Duration("resync", 30*time.Second, "how often to re-read the cloud when nothing in the cluster changes")
		showVersion    = flag.Bool("version", false, "print the release and exit")
	)
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	if *showVersion {
		fmt.Println(version.Version)
		return nil
	}
	ctrlmetrics.Registry.MustRegister(version.BuildInfo("controller"))
	ctrl.Log.Info("starting natterjack controller", "version", version.Version)

	if *clusterName == "" {
		return errors.New("--cluster-name is required")
	}
	if *namespace == "" {
		return errors.New("--namespace or POD_NAMESPACE is required")
	}
	sel, err := labels.Parse(*agentSelector)
	if err != nil || sel.Empty() {
		return fmt.Errorf("--agent-selector %q must be a non-empty label selector", *agentSelector)
	}

	ctx := ctrl.SetupSignalHandler()
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("load AWS configuration: %w", err)
	}
	if awsCfg.Region == "" {
		return errors.New("no AWS region configured; set AWS_REGION")
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return fmt.Errorf("register core types: %w", err)
	}
	if err := v1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("register natterjack types: %w", err)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Cache: cache.Options{ByObject: map[client.Object]cache.ByObject{
			// Only agent pods are read, so only they are cached.
			&corev1.Pod{}: {Namespaces: map[string]cache.Config{*namespace: {}}, Label: sel},
		}},
		Metrics: metricsserver.Options{
			BindAddress:    *metricsAddr,
			SecureServing:  true,
			FilterProvider: filters.WithAuthenticationAndAuthorization,
		},
		HealthProbeBindAddress:        *probeAddr,
		LeaderElection:                *leaderElect,
		LeaderElectionID:              "natterjack-controller",
		LeaderElectionNamespace:       *namespace,
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	health := &controller.Health{}
	r := &controller.Reconciler{
		Client:         mgr.GetClient(),
		Provider:       awsprovider.New(ec2.NewFromConfig(awsCfg), *clusterName),
		Recorder:       mgr.GetEventRecorder("natterjack-controller"),
		ClusterName:    *clusterName,
		Namespace:      *namespace,
		AgentSelector:  sel,
		ServiceAccount: *serviceAccount,
		Resync:         *resync,
		Health:         health,
		Now:            time.Now,
	}
	if err := r.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("slot controller: %w", err)
	}
	if err := (&controller.PolicyReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("policy controller: %w", err)
	}
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("add liveness check: %w", err)
	}
	if err := mgr.AddReadyzCheck("cloud", health.Check); err != nil {
		return fmt.Errorf("add readiness check: %w", err)
	}
	identity := &controller.IdentityWatch{
		Retrieve: func(ctx context.Context) error {
			if _, err := awsCfg.Credentials.Retrieve(ctx); err != nil {
				return credentialsError(err)
			}
			return nil
		},
		Every:         15 * time.Second,
		StepDownAfter: 2 * time.Minute,
		Elected:       mgr.Elected(),
		Now:           time.Now,
		Log:           ctrl.Log.WithName("identity"),
	}
	if err := mgr.Add(identity); err != nil {
		return fmt.Errorf("add identity watch: %w", err)
	}
	if err := mgr.AddReadyzCheck("identity", identity.Check); err != nil {
		return fmt.Errorf("add identity readiness check: %w", err)
	}
	return start(ctx, mgr)
}

// credentialsError says when the pod was given no workload identity at all,
// which happens to a pod created before its EKS Pod Identity association or
// IRSA annotation: the credentials are injected when the pod is admitted.
func credentialsError(err error) error {
	for _, v := range []string{"AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ACCESS_KEY_ID"} {
		if os.Getenv(v) != "" {
			return err
		}
	}
	return fmt.Errorf("%w (this pod has no workload identity: if the Pod Identity association or IRSA annotation was created after the pod, restart the controller with kubectl rollout restart)", err)
}

func start(ctx context.Context, mgr ctrl.Manager) error {
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("run manager: %w", err)
	}
	return nil
}
