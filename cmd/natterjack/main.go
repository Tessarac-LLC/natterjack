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

// Command natterjack is the Natterjack command-line tool. "natterjack
// doctor" checks an installation and prints a go or no-go report before any
// traffic moves; the chart's helm test runs the same checks in the cluster.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
	"github.com/Tessarac-LLC/natterjack/internal/doctor"
	"github.com/Tessarac-LLC/natterjack/internal/version"
)

const usage = `Usage: natterjack <command> [flags]

Commands:
  doctor    check an installation and print a go or no-go report
  version   print the version

Run "natterjack <command> -h" for a command's flags.
`

// Exit codes: 0 go, 1 no-go, 2 the command could not run.
const (
	exitGo    = 0
	exitNoGo  = 1
	exitUsage = 2
)

// say, sayln and sayf print to a terminal. A failed write there has
// nowhere to be reported, and the exit status still says go or no-go.
func say(w io.Writer, a ...any)                 { _, _ = fmt.Fprint(w, a...) }
func sayln(w io.Writer, a ...any)               { _, _ = fmt.Fprintln(w, a...) }
func sayf(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		say(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "doctor":
		return doctorCmd(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		sayln(stdout, version.Version)
		return exitGo
	case "-h", "--help", "help":
		say(stdout, usage)
		return exitGo
	}
	sayf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return exitUsage
}

func doctorCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		kubeconfig = fs.String("kubeconfig", "", "kubeconfig file; defaults to $KUBECONFIG, ~/.kube/config, then the in-cluster ServiceAccount")
		kubectx    = fs.String("context", "", "kubeconfig context; defaults to the current context")
		namespace  = fs.String("namespace", "", "namespace of the release; found automatically when only one release exists")
		release    = fs.String("release", "", "Helm release name; found automatically when only one release exists")
		output     = fs.String("o", "text", "output format: text or json")
		timeout    = fs.Duration("timeout", 30*time.Second, "time allowed for all checks")
	)
	fs.StringVar(namespace, "n", "", "shorthand for --namespace")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *output != "text" && *output != "json" {
		sayf(stderr, "unknown output format %q; use text or json\n", *output)
		return exitUsage
	}

	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = *kubeconfig
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: *kubectx}).ClientConfig()
	if err != nil {
		sayf(stderr, "cannot load a Kubernetes configuration: %v\n", err)
		return exitUsage
	}
	cfg.UserAgent = "natterjack-doctor/" + version.Version
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		sayln(stderr, err)
		return exitUsage
	}
	if err := v1.AddToScheme(scheme); err != nil {
		sayln(stderr, err)
		return exitUsage
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		sayf(stderr, "cannot reach the API server: %v\n", err)
		return exitUsage
	}
	disc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		sayf(stderr, "cannot reach the API server: %v\n", err)
		return exitUsage
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	report := doctor.Run(ctx, doctor.Options{
		Client: c, ServerVersion: disc.ServerVersion, Namespace: *namespace, Release: *release,
	})
	if *output == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(report)
	} else {
		err = doctor.Print(stdout, report)
	}
	if err != nil {
		sayln(stderr, err)
		return exitUsage
	}
	if !report.Go {
		return exitNoGo
	}
	return exitGo
}
