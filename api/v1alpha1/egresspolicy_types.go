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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EgressPolicySpec selects pods in the policy's namespace whose internet
// traffic leaves through a pool.
// +kubebuilder:validation:XValidation:rule="has(self.podSelector) || (has(self.serviceAccountNames) && size(self.serviceAccountNames) > 0)",message="set podSelector or serviceAccountNames; use an empty podSelector to select every pod"
type EgressPolicySpec struct {
	// PoolName is the EgressPool traffic leaves through.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	PoolName string `json:"poolName"`

	// PodSelector selects pods in this namespace. An empty selector selects
	// every pod in the namespace.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`

	// ServiceAccountNames selects pods running as these ServiceAccounts.
	// When set with PodSelector, a pod must match both.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=253
	ServiceAccountNames []string `json:"serviceAccountNames,omitempty"`

	// ExcludedCIDRs are destinations that are never steered, in addition to
	// the cluster, VPC and private ranges that are always excluded.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MaxLength=18
	// +kubebuilder:validation:items:XValidation:rule="isCIDR(self) && cidr(self).ip().family() == 4",message="every entry must be an IPv4 CIDR"
	ExcludedCIDRs []string `json:"excludedCIDRs,omitempty"`
}

// PolicyStatus is the observed state of an EgressPolicy or ClusterEgressPolicy.
type PolicyStatus struct {
	// ObservedGeneration is the generation the status reflects.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Conditions: Accepted (the pool exists and the policy is in force).
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ConditionAccepted is set on policies once their pool exists and they are in force.
const ConditionAccepted = "Accepted"

// EgressPolicy sends the internet traffic of selected pods in its namespace
// through an EgressPool.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=egp,categories=natterjack
// +kubebuilder:printcolumn:name="Pool",type=string,JSONPath=`.spec.poolName`
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type EgressPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec EgressPolicySpec `json:"spec"`
	// +optional
	Status PolicyStatus `json:"status,omitempty"`
}

// EgressPolicyList is a list of EgressPolicy.
//
// +kubebuilder:object:root=true
type EgressPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EgressPolicy `json:"items"`
}

// ClusterEgressPolicySpec selects pods across namespaces, and optionally the
// nodes' own traffic.
// +kubebuilder:validation:XValidation:rule="has(self.namespaceSelector) || self.nodeTraffic",message="set namespaceSelector, nodeTraffic, or both"
type ClusterEgressPolicySpec struct {
	// PoolName is the EgressPool traffic leaves through.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	PoolName string `json:"poolName"`

	// NamespaceSelector selects namespaces. An empty selector selects every
	// namespace. Unset selects no pods.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// PodSelector further restricts pods in the selected namespaces.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`

	// NodeTraffic steers the nodes' own internet traffic (kubelet, image
	// pulls, host-network pods) through the pool.
	// +optional
	NodeTraffic bool `json:"nodeTraffic,omitempty"`

	// ExcludedCIDRs are destinations that are never steered, in addition to
	// the cluster, VPC and private ranges that are always excluded.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MaxLength=18
	// +kubebuilder:validation:items:XValidation:rule="isCIDR(self) && cidr(self).ip().family() == 4",message="every entry must be an IPv4 CIDR"
	ExcludedCIDRs []string `json:"excludedCIDRs,omitempty"`
}

// ClusterEgressPolicy sends the internet traffic of pods across namespaces,
// and optionally of the nodes themselves, through an EgressPool. When a pod is
// selected by both, its namespace's EgressPolicy wins.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=cegp,categories=natterjack
// +kubebuilder:printcolumn:name="Pool",type=string,JSONPath=`.spec.poolName`
// +kubebuilder:printcolumn:name="Nodes",type=boolean,JSONPath=`.spec.nodeTraffic`
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type ClusterEgressPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ClusterEgressPolicySpec `json:"spec"`
	// +optional
	Status PolicyStatus `json:"status,omitempty"`
}

// ClusterEgressPolicyList is a list of ClusterEgressPolicy.
//
// +kubebuilder:object:root=true
type ClusterEgressPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterEgressPolicy `json:"items"`
}
