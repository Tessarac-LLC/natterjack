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

// Package cloud is the boundary between the controller and a cloud API. The
// controller only discovers slots and moves their attachment; it never
// creates, edits or deletes cloud resources or tags.
package cloud

import (
	"context"
	"errors"
)

// Slot is one egress slot as the cloud reports it.
type Slot struct {
	// ID is the cloud identifier (on AWS, the ENI ID).
	ID string
	// Zone is the availability zone.
	Zone string
	// PublicIP traffic leaves from. Empty if none is associated.
	PublicIP string
	// PrivateIP of the slot inside the VPC.
	PrivateIP string
	// MAC address, used by the agent to find the interface once attached.
	MAC string
	// SubnetID the slot lives in.
	SubnetID string
	// SubnetCIDR of that subnet. The agent addresses the slot with it and
	// routes through the subnet's router.
	SubnetCIDR string
	// Instance the slot is attached to; empty when unattached.
	Instance string
	// InstanceInCluster reports whether Instance belongs to this cluster.
	InstanceInCluster bool
	// RoutedSources are the only sources a route table may send through the
	// slot: on AWS, its VPC's IPv4 blocks, sorted.
	RoutedSources []string
	// RouteTarget is true when a route table sends traffic to this slot, so
	// node traffic depends on it before agents steer anything.
	RouteTarget bool
	// Tags on the slot, used to match it to a pool.
	Tags map[string]string
	// Problems are failed safety checks, in plain language. A slot with any
	// problem is quarantined and never attached.
	Problems []string
}

// Usable reports whether the slot passed every safety check.
func (s Slot) Usable() bool { return len(s.Problems) == 0 }

// Instance is a node's machine as the cloud reports it.
type Instance struct {
	ID   string
	Zone string
}

// Stray is a slot tagged for egress whose cluster tag names another cluster
// or is missing. It is never touched; it is reported so a typo is visible.
type Stray struct {
	ID      string
	Zone    string
	Cluster string
}

// Discovery selects slots.
type Discovery struct {
	// ClusterName must match the slot's cluster tag.
	ClusterName string
	// ExtraTags must all match.
	ExtraTags map[string]string
}

// Provider is implemented once per cloud.
type Provider interface {
	// Slots returns every slot matching d, with safety checks evaluated.
	Slots(ctx context.Context, d Discovery) ([]Slot, error)
	// InstanceForProviderID maps a Kubernetes node's spec.providerID to its instance.
	InstanceForProviderID(providerID string) (Instance, error)
	// Attach attaches the slot to the instance. Attaching a slot to the
	// instance it is already attached to succeeds without change.
	Attach(ctx context.Context, slotID, instanceID string) error
	// Detach detaches the slot from whatever it is attached to and waits until
	// it is free. Detaching an unattached slot succeeds without change. Force
	// is for an instance that no longer responds.
	Detach(ctx context.Context, slotID string, force bool) error
	// Strays lists slots tagged for egress that belong to no cluster or to a
	// cluster other than clusterName.
	Strays(ctx context.Context, clusterName string) ([]Stray, error)
}

var (
	// ErrAttachedElsewhere is returned by Attach when the slot is attached to
	// another instance. The caller must detach it first.
	ErrAttachedElsewhere = errors.New("slot is attached to another instance")
	// ErrNotFound is returned when a slot or instance does not exist.
	ErrNotFound = errors.New("not found")
	// ErrNoFreeDeviceIndex is returned when the instance has no room for
	// another network interface.
	ErrNoFreeDeviceIndex = errors.New("instance has no free network interface slot")
)
