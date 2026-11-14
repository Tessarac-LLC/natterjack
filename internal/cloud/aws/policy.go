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

package aws

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
)

// policyTemplate is the controller's complete IAM policy. CLUSTER_NAME is
// replaced with the cluster's name.
//
//go:embed policy.json
var policyTemplate string

// clusterName matches EKS cluster names, which is also the safe subset for
// the kubernetes.io/cluster/<name> tag.
var clusterName = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z_-]{0,99}$`)

// Policy returns the least-privilege IAM policy for a controller managing
// the given cluster. The controller can read EC2 networking state, and can
// attach or detach only ENIs tagged for egress in this cluster, and only on
// instances that belong to this cluster.
func Policy(cluster string) (string, error) {
	if !clusterName.MatchString(cluster) {
		return "", fmt.Errorf("cluster name %q is not a valid EKS cluster name", cluster)
	}
	return strings.ReplaceAll(policyTemplate, "CLUSTER_NAME", cluster), nil
}
