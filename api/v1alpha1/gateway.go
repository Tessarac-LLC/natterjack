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

// The controller tells an agent it is a gateway through its own pod: the
// LabelGateway and LabelPool labels select it into the gateway Service, and
// these annotations carry the assignment. The agent holds no cloud
// credentials and acts only on what the controller writes here.
const (
	// AnnotationGateway holds the JSON-encoded Gateway assignment.
	AnnotationGateway = Group + "/gateway"
	// AnnotationDrainStarted is set, as an RFC 3339 time, when the gateway
	// must stop taking new flows because its slot is about to move.
	AnnotationDrainStarted = Group + "/drain-started"
)

// Gateway is the slot an agent serves as a gateway.
type Gateway struct {
	// Pool the slot belongs to.
	Pool string `json:"pool"`
	// SlotID is the cloud identifier of the slot.
	SlotID string `json:"slotID"`
	// MAC address of the slot interface, used to find it on the node.
	MAC string `json:"mac"`
	// PrivateIP of the slot inside the VPC.
	PrivateIP string `json:"privateIP"`
	// PublicIP traffic leaves from.
	PublicIP string `json:"publicIP"`
	// Tunnel between source nodes and this gateway.
	Tunnel TunnelType `json:"tunnel"`
}
