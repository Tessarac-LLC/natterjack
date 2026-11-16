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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Labels and tags read by Natterjack. The controller never writes cloud tags.
const (
	// TagEgress marks a cloud resource as an egress slot. Its value must be "true".
	TagEgress = Group + "/egress"
	// TagCluster names the cluster a slot belongs to.
	TagCluster = Group + "/cluster"
	// TagPool optionally names the EgressPool a slot belongs to. Slots without
	// it belong to the pool whose discovery has no pool tag requirement.
	TagPool = Group + "/pool"
	// LabelGateway is set by the controller on the agent pod of a gateway node.
	LabelGateway = Group + "/gateway"
	// LabelPool is set by the controller on the agent pod of a gateway node.
	LabelPool = Group + "/pool"
	// ConditionGatewayReady is the pod condition a gateway agent sets once its
	// slot carries traffic and its self-test passes. GatewayReady reads it.
	ConditionGatewayReady corev1.PodConditionType = Group + "/gateway-ready"
	// ReasonSelfTestPending is the gateway-ready reason while a gateway that
	// carries its slot waits for its first self-test through it.
	ReasonSelfTestPending = "SelfTestPending"
	// ConditionDataplaneReady is the pod condition every agent sets: true once
	// its node's data path is applied, false with the error while it is not.
	ConditionDataplaneReady corev1.PodConditionType = Group + "/dataplane-ready"
	// ConditionWireGuardKey is the pod condition in which every agent
	// publishes its node's WireGuard public key, in its message. Only the
	// agent on a node can write it: an agent may change only its own pod's
	// status.
	ConditionWireGuardKey corev1.PodConditionType = Group + "/wireguard-key"
)

// TunnelType selects the encapsulation between source nodes and gateways.
// +kubebuilder:validation:Enum=Geneve;WireGuard
type TunnelType string

const (
	// TunnelGeneve is unencrypted GENEVE inside the VPC (default).
	TunnelGeneve TunnelType = "Geneve"
	// TunnelWireGuard encrypts traffic between nodes and gateways.
	TunnelWireGuard TunnelType = "WireGuard"
)

// SafetyChecks selects what happens to a slot that fails a safety check.
// +kubebuilder:validation:Enum=Enforce;Warn
type SafetyChecks string

const (
	// SafetyChecksEnforce quarantines a failing slot and detaches it if in
	// use (default).
	SafetyChecksEnforce SafetyChecks = "Enforce"
	// SafetyChecksWarn uses a failing slot and reports the failure. It is for
	// break-glass use only. A slot attached outside the cluster is never used.
	SafetyChecksWarn SafetyChecks = "Warn"
)

// EgressPoolSpec defines a set of egress slots and how gateways are run for them.
// +kubebuilder:validation:XValidation:rule="!has(self.maxGatewaysPerZone) || self.maxGatewaysPerZone >= 1",message="maxGatewaysPerZone must be at least 1"
type EgressPoolSpec struct {
	// Discovery selects the cloud slots that belong to this pool.
	// +optional
	Discovery Discovery `json:"discovery,omitempty"`

	// GatewayNodeSelector restricts which nodes may run a gateway. Empty means
	// any Linux node that tolerates nothing extra.
	// +optional
	GatewayNodeSelector map[string]string `json:"gatewayNodeSelector,omitempty"`

	// GatewayTolerations lets gateways run on tainted nodes. The agent
	// DaemonSet needs the same tolerations, set in the Helm values.
	// +optional
	// +listType=atomic
	GatewayTolerations []corev1.Toleration `json:"gatewayTolerations,omitempty"`

	// MaxGatewaysPerZone caps the gateways per zone. Healthy slots beyond the
	// cap stay unattached as spares. Unset means one gateway per healthy slot.
	// +optional
	MaxGatewaysPerZone *int32 `json:"maxGatewaysPerZone,omitempty"`

	// Tunnel selects the encapsulation from source nodes to gateways.
	// +optional
	// +kubebuilder:default=Geneve
	Tunnel TunnelType `json:"tunnel,omitempty"`

	// Probe sets how fast source nodes detect a failed gateway.
	// +optional
	Probe Probe `json:"probe,omitempty"`

	// DrainSeconds is how long established flows keep using a gateway that is
	// being removed in a planned disruption before its slot moves.
	// +optional
	// +kubebuilder:default=60
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	DrainSeconds int32 `json:"drainSeconds,omitempty"`

	// SafetyChecks selects whether a slot that fails a safety check is
	// quarantined (Enforce) or used with a warning (Warn).
	// +optional
	// +kubebuilder:default=Enforce
	SafetyChecks SafetyChecks `json:"safetyChecks,omitempty"`
}

// Discovery selects slots by tag. The cluster tag is always required and its
// value is the cluster name configured on the controller.
type Discovery struct {
	// ExtraTags must all be present, with these values, on a slot.
	// +optional
	// +kubebuilder:validation:MaxProperties=16
	ExtraTags map[string]string `json:"extraTags,omitempty"`
}

// Probe sets gateway liveness probing from every source node.
type Probe struct {
	// IntervalMilliseconds between probes to each gateway.
	// +optional
	// +kubebuilder:default=100
	// +kubebuilder:validation:Minimum=20
	// +kubebuilder:validation:Maximum=10000
	IntervalMilliseconds int32 `json:"intervalMilliseconds,omitempty"`

	// FailureThreshold is the number of consecutive missed probes after which
	// a gateway is treated as down.
	// +optional
	// +kubebuilder:default=3
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	FailureThreshold int32 `json:"failureThreshold,omitempty"`
}

// SlotState is the controller's view of one slot.
// +kubebuilder:validation:Enum=Pending;Attaching;Active;Draining;Spare;Quarantined;Unschedulable;Foreign
type SlotState string

const (
	// SlotPending is discovered and valid, not yet assigned.
	SlotPending SlotState = "Pending"
	// SlotAttaching is being attached to its node.
	SlotAttaching SlotState = "Attaching"
	// SlotActive is attached and its gateway is ready.
	SlotActive SlotState = "Active"
	// SlotDraining is being moved off a node in a planned disruption.
	SlotDraining SlotState = "Draining"
	// SlotSpare is healthy and held back by maxGatewaysPerZone.
	SlotSpare SlotState = "Spare"
	// SlotQuarantined failed a safety check and is never used until fixed.
	SlotQuarantined SlotState = "Quarantined"
	// SlotUnschedulable has no eligible node in its zone.
	SlotUnschedulable SlotState = "Unschedulable"
	// SlotForeign is attached to an instance outside this cluster.
	SlotForeign SlotState = "Foreign"
)

// SlotStatus reports one slot.
type SlotStatus struct {
	// ID is the cloud identifier of the slot (on AWS, the ENI ID).
	ID string `json:"id"`
	// Zone is the availability zone of the slot.
	Zone string `json:"zone"`
	// PublicIP is the public IPv4 address traffic leaves from.
	// +optional
	PublicIP string `json:"publicIP,omitempty"`
	// State of the slot.
	State SlotState `json:"state"`
	// Node the slot is attached or assigned to.
	// +optional
	Node string `json:"node,omitempty"`
	// Reason explains the state when it is not Active, in plain language.
	// +optional
	Reason string `json:"reason,omitempty"`
}

// ZoneStatus summarizes one zone.
type ZoneStatus struct {
	// Zone name.
	Zone string `json:"zone"`
	// Slots discovered in the zone.
	Slots int32 `json:"slots"`
	// ReadyGateways serving traffic in the zone.
	ReadyGateways int32 `json:"readyGateways"`
}

// Condition types on EgressPool.
const (
	ConditionReady              = "Ready"
	ConditionDegraded           = "Degraded"
	ConditionCrossZoneEgress    = "CrossZoneEgress"
	ConditionSlotsQuarantined   = "SlotsQuarantined"
	ConditionSlotsUnschedulable = "SlotsUnschedulable"
	ConditionForeignSlots       = "ForeignSlots"
	// ConditionCloudAccess is false, with the failing call and the identity in
	// use, while the controller cannot read the cloud.
	ConditionCloudAccess = "CloudAccess"
)

// EgressPoolStatus is the observed state of an EgressPool.
type EgressPoolStatus struct {
	// ObservedGeneration is the generation the status reflects.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// PublicIPs are the addresses traffic from this pool can leave from, for
	// partner allowlists. It includes spares and quarantined slots that have
	// an address, because they can become active.
	// +optional
	// +listType=set
	PublicIPs []string `json:"publicIPs,omitempty"`
	// Zones summarizes each zone.
	// +optional
	// +listType=map
	// +listMapKey=zone
	Zones []ZoneStatus `json:"zones,omitempty"`
	// Slots lists every discovered slot.
	// +optional
	// +listType=map
	// +listMapKey=id
	Slots []SlotStatus `json:"slots,omitempty"`
	// Conditions: Ready, Degraded, CrossZoneEgress, SlotsQuarantined,
	// SlotsUnschedulable, ForeignSlots, CloudAccess.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// EgressPool is a set of egress slots and the gateways that use them.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=ep,categories=natterjack
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Public IPs",type=string,JSONPath=`.status.publicIPs`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type EgressPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec EgressPoolSpec `json:"spec,omitempty"`
	// +optional
	Status EgressPoolStatus `json:"status,omitempty"`
}

// EgressPoolList is a list of EgressPool.
//
// +kubebuilder:object:root=true
type EgressPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EgressPool `json:"items"`
}
