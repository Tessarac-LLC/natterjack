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

// Package aws implements cloud.Provider with Elastic Network Interfaces: a
// slot is a secondary ENI with an Elastic IP, moved between instances with
// AttachNetworkInterface and DetachNetworkInterface.
package aws

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
	"github.com/Tessarac-LLC/natterjack/internal/cloud"
)

// TagNoManage tells the VPC CNI to leave an ENI alone. Without it the CNI may
// assign pod IPs to the slot ENI.
const TagNoManage = "node.k8s.amazonaws.com/no_manage"

// EC2 is the subset of the EC2 API the provider uses. Every call is either a
// read or an attachment change, matching the shipped IAM policy.
type EC2 interface {
	DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error)
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	AttachNetworkInterface(context.Context, *ec2.AttachNetworkInterfaceInput, ...func(*ec2.Options)) (*ec2.AttachNetworkInterfaceOutput, error)
	DetachNetworkInterface(context.Context, *ec2.DetachNetworkInterfaceInput, ...func(*ec2.Options)) (*ec2.DetachNetworkInterfaceOutput, error)
}

// Provider is the AWS cloud.Provider.
type Provider struct {
	ec2 EC2
	// clusterName identifies this cluster's instances by their EKS or
	// Kubernetes cluster tag.
	clusterName string
	// pollInterval and detachTimeout bound the wait for a detach to finish.
	pollInterval  time.Duration
	detachTimeout time.Duration
}

// New returns a provider for the cluster.
func New(client EC2, clusterName string) *Provider {
	return &Provider{ec2: client, clusterName: clusterName, pollInterval: 2 * time.Second, detachTimeout: 2 * time.Minute}
}

var _ cloud.Provider = (*Provider)(nil)

// Slots implements cloud.Provider.
func (p *Provider) Slots(ctx context.Context, d cloud.Discovery) ([]cloud.Slot, error) {
	if d.ClusterName == "" {
		return nil, errors.New("discovery needs a cluster name")
	}
	filters := []types.Filter{
		{Name: aws.String("tag:" + v1.TagEgress), Values: []string{"true"}},
		{Name: aws.String("tag:" + v1.TagCluster), Values: []string{d.ClusterName}},
	}
	keys := make([]string, 0, len(d.ExtraTags))
	for k := range d.ExtraTags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		filters = append(filters, types.Filter{Name: aws.String("tag:" + k), Values: []string{d.ExtraTags[k]}})
	}

	var enis []types.NetworkInterface
	pager := ec2.NewDescribeNetworkInterfacesPaginator(p.ec2, &ec2.DescribeNetworkInterfacesInput{Filters: filters})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe network interfaces: %w", err)
		}
		enis = append(enis, page.NetworkInterfaces...)
	}
	if len(enis) == 0 {
		return nil, nil
	}

	ins, err := p.inboundRules(ctx, enis)
	if err != nil {
		return nil, err
	}
	igw, routeTargets, err := p.routes(ctx, enis)
	if err != nil {
		return nil, err
	}
	inCluster, err := p.clusterInstances(ctx, enis)
	if err != nil {
		return nil, err
	}
	cidrs, err := p.subnetCIDRs(ctx, enis)
	if err != nil {
		return nil, err
	}

	slots := make([]cloud.Slot, 0, len(enis))
	for i := range enis {
		e := &enis[i]
		s := cloud.Slot{
			ID:          aws.ToString(e.NetworkInterfaceId),
			Zone:        aws.ToString(e.AvailabilityZone),
			PrivateIP:   aws.ToString(e.PrivateIpAddress),
			MAC:         aws.ToString(e.MacAddress),
			SubnetID:    aws.ToString(e.SubnetId),
			SubnetCIDR:  cidrs[aws.ToString(e.SubnetId)],
			RouteTarget: routeTargets[aws.ToString(e.NetworkInterfaceId)],
			Tags:        make(map[string]string, len(e.TagSet)),
		}
		for _, t := range e.TagSet {
			s.Tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
		if e.Association != nil {
			s.PublicIP = aws.ToString(e.Association.PublicIp)
		}
		if e.Attachment != nil && e.Attachment.Status != types.AttachmentStatusDetached {
			s.Instance = aws.ToString(e.Attachment.InstanceId)
			s.InstanceInCluster = inCluster[s.Instance]
		}
		s.Problems = problems(e, ins, igw, cidrs)
		slots = append(slots, s)
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i].ID < slots[j].ID })
	return slots, nil
}

// problems returns every failed safety check for an ENI (design section 7.4).
func problems(e *types.NetworkInterface, inbound, igw map[string]bool, cidrs map[string]string) []string {
	var out []string
	if e.InterfaceType != "" && e.InterfaceType != types.NetworkInterfaceTypeInterface {
		out = append(out, fmt.Sprintf("interface type is %q; only a plain ENI can be a slot", e.InterfaceType))
	}
	if aws.ToBool(e.RequesterManaged) {
		out = append(out, "the ENI is managed by an AWS service")
	}
	if e.Association == nil || aws.ToString(e.Association.PublicIp) == "" {
		out = append(out, "no Elastic IP is associated with the ENI")
	}
	if e.SourceDestCheck == nil || *e.SourceDestCheck {
		out = append(out, "source/destination check is enabled; it must be disabled for a gateway")
	}
	if !hasTag(e.TagSet, TagNoManage, "true") {
		out = append(out, fmt.Sprintf("tag %s=true is missing, so the VPC CNI could use the ENI for pods", TagNoManage))
	}
	if len(e.Groups) == 0 {
		out = append(out, "the ENI has no security group")
	}
	for _, g := range e.Groups {
		if inbound[aws.ToString(g.GroupId)] {
			out = append(out, fmt.Sprintf("security group %s allows inbound traffic; a slot's security groups must have no inbound rules", aws.ToString(g.GroupId)))
		}
	}
	if cidrs[aws.ToString(e.SubnetId)] == "" {
		out = append(out, fmt.Sprintf("subnet %s has no IPv4 CIDR block", aws.ToString(e.SubnetId)))
	}
	if !igw[aws.ToString(e.SubnetId)] {
		out = append(out, fmt.Sprintf("subnet %s has no 0.0.0.0/0 route to an internet gateway", aws.ToString(e.SubnetId)))
	}
	return out
}

func hasTag(tags []types.Tag, key, value string) bool {
	return slices.ContainsFunc(tags, func(t types.Tag) bool {
		return aws.ToString(t.Key) == key && aws.ToString(t.Value) == value
	})
}

// inboundRules reports, per security group, whether it has any inbound rule.
func (p *Provider) inboundRules(ctx context.Context, enis []types.NetworkInterface) (map[string]bool, error) {
	var ids []string
	for i := range enis {
		for _, g := range enis[i].Groups {
			ids = append(ids, aws.ToString(g.GroupId))
		}
	}
	ids = unique(ids)
	out := map[string]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	pager := ec2.NewDescribeSecurityGroupsPaginator(p.ec2, &ec2.DescribeSecurityGroupsInput{GroupIds: ids})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe security groups: %w", err)
		}
		for _, g := range page.SecurityGroups {
			out[aws.ToString(g.GroupId)] = len(g.IpPermissions) > 0
		}
	}
	for _, id := range ids {
		if _, ok := out[id]; !ok {
			// A group we cannot see is treated as unsafe.
			out[id] = true
		}
	}
	return out, nil
}

// routes reports which subnets route 0.0.0.0/0 to an internet gateway, and
// which ENIs are the target of any route.
func (p *Provider) routes(ctx context.Context, enis []types.NetworkInterface) (igw, targets map[string]bool, err error) {
	var vpcs []string
	for i := range enis {
		vpcs = append(vpcs, aws.ToString(enis[i].VpcId))
	}
	vpcs = unique(vpcs)
	var tables []types.RouteTable
	pager := ec2.NewDescribeRouteTablesPaginator(p.ec2, &ec2.DescribeRouteTablesInput{
		Filters: []types.Filter{{Name: aws.String("vpc-id"), Values: vpcs}},
	})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("describe route tables: %w", err)
		}
		tables = append(tables, page.RouteTables...)
	}

	explicit := map[string]*types.RouteTable{}  // subnet -> table
	mainTable := map[string]*types.RouteTable{} // vpc -> main table
	targets = map[string]bool{}
	for i := range tables {
		t := &tables[i]
		for _, a := range t.Associations {
			if aws.ToBool(a.Main) {
				mainTable[aws.ToString(t.VpcId)] = t
			} else if a.SubnetId != nil {
				explicit[aws.ToString(a.SubnetId)] = t
			}
		}
		for _, r := range t.Routes {
			if r.NetworkInterfaceId != nil && r.State != types.RouteStateBlackhole {
				targets[aws.ToString(r.NetworkInterfaceId)] = true
			}
		}
	}

	igw = map[string]bool{}
	for i := range enis {
		subnet := aws.ToString(enis[i].SubnetId)
		t := explicit[subnet]
		if t == nil {
			t = mainTable[aws.ToString(enis[i].VpcId)]
		}
		igw[subnet] = t != nil && defaultRouteToIGW(t)
	}
	return igw, targets, nil
}

func defaultRouteToIGW(t *types.RouteTable) bool {
	return slices.ContainsFunc(t.Routes, func(r types.Route) bool {
		return aws.ToString(r.DestinationCidrBlock) == "0.0.0.0/0" &&
			strings.HasPrefix(aws.ToString(r.GatewayId), "igw-") &&
			r.State != types.RouteStateBlackhole
	})
}

// clusterInstances reports, per attached instance, whether it belongs to this cluster.
func (p *Provider) clusterInstances(ctx context.Context, enis []types.NetworkInterface) (map[string]bool, error) {
	var ids []string
	for i := range enis {
		if a := enis[i].Attachment; a != nil && a.InstanceId != nil {
			ids = append(ids, aws.ToString(a.InstanceId))
		}
	}
	ids = unique(ids)
	out := map[string]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	pager := ec2.NewDescribeInstancesPaginator(p.ec2, &ec2.DescribeInstancesInput{InstanceIds: ids})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isNotFound(err) {
				// Terminated instances drop out of DescribeInstances; their
				// ENIs are reported as attached elsewhere until AWS detaches them.
				return out, nil
			}
			return nil, fmt.Errorf("describe instances: %w", err)
		}
		for _, r := range page.Reservations {
			for _, in := range r.Instances {
				out[aws.ToString(in.InstanceId)] = p.inCluster(in.Tags)
			}
		}
	}
	return out, nil
}

// inCluster recognizes EKS nodes by the tag EKS adds to every node instance,
// and other Kubernetes nodes by the cloud-provider cluster tag.
func (p *Provider) inCluster(tags []types.Tag) bool {
	for _, t := range tags {
		k, v := aws.ToString(t.Key), aws.ToString(t.Value)
		if k == "aws:eks:cluster-name" && v == p.clusterName {
			return true
		}
		if k == "kubernetes.io/cluster/"+p.clusterName && (v == "owned" || v == "shared") {
			return true
		}
	}
	return false
}

// providerID is aws:///<zone>/<instance-id>.
var providerID = regexp.MustCompile(`^aws:///([a-z0-9-]+)/(i-[0-9a-f]+)$`)

// Strays implements cloud.Provider.
func (p *Provider) Strays(ctx context.Context, clusterName string) ([]cloud.Stray, error) {
	var out []cloud.Stray
	pager := ec2.NewDescribeNetworkInterfacesPaginator(p.ec2, &ec2.DescribeNetworkInterfacesInput{
		Filters: []types.Filter{{Name: aws.String("tag:" + v1.TagEgress), Values: []string{"true"}}},
	})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe network interfaces: %w", err)
		}
		for i := range page.NetworkInterfaces {
			e := &page.NetworkInterfaces[i]
			cluster := ""
			for _, t := range e.TagSet {
				if aws.ToString(t.Key) == v1.TagCluster {
					cluster = aws.ToString(t.Value)
				}
			}
			if cluster != clusterName {
				out = append(out, cloud.Stray{ID: aws.ToString(e.NetworkInterfaceId), Zone: aws.ToString(e.AvailabilityZone), Cluster: cluster})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// InstanceForProviderID implements cloud.Provider.
func (p *Provider) InstanceForProviderID(id string) (cloud.Instance, error) {
	m := providerID.FindStringSubmatch(id)
	if m == nil {
		return cloud.Instance{}, fmt.Errorf("provider ID %q is not an AWS instance", id)
	}
	return cloud.Instance{Zone: m[1], ID: m[2]}, nil
}

// Attach implements cloud.Provider.
func (p *Provider) Attach(ctx context.Context, slotID, instanceID string) error {
	eni, err := p.eni(ctx, slotID)
	if err != nil {
		return err
	}
	if a := eni.Attachment; a != nil && a.Status != types.AttachmentStatusDetached {
		if aws.ToString(a.InstanceId) == instanceID {
			return nil
		}
		return fmt.Errorf("%s is on %s: %w", slotID, aws.ToString(a.InstanceId), cloud.ErrAttachedElsewhere)
	}
	inst, err := p.instance(ctx, instanceID)
	if err != nil {
		return err
	}
	if zone := aws.ToString(inst.Placement.AvailabilityZone); zone != aws.ToString(eni.AvailabilityZone) {
		return fmt.Errorf("%s is in %s and %s is in %s", slotID, aws.ToString(eni.AvailabilityZone), instanceID, zone)
	}
	idx, err := freeDeviceIndex(inst)
	if err != nil {
		return err
	}
	_, err = p.ec2.AttachNetworkInterface(ctx, &ec2.AttachNetworkInterfaceInput{
		NetworkInterfaceId: aws.String(slotID),
		InstanceId:         aws.String(instanceID),
		DeviceIndex:        aws.Int32(idx),
	})
	if err != nil {
		return fmt.Errorf("attach %s to %s: %w", slotID, instanceID, err)
	}
	return nil
}

// freeDeviceIndex returns the lowest unused device index above 0 on network card 0.
func freeDeviceIndex(inst *types.Instance) (int32, error) {
	used := map[int32]bool{}
	for _, n := range inst.NetworkInterfaces {
		if a := n.Attachment; a != nil && aws.ToInt32(a.NetworkCardIndex) == 0 {
			used[aws.ToInt32(a.DeviceIndex)] = true
		}
	}
	// The per-type ENI limit is enforced by EC2; 64 is above every instance type.
	for i := int32(1); i < 64; i++ {
		if !used[i] {
			return i, nil
		}
	}
	return 0, fmt.Errorf("%s: %w", aws.ToString(inst.InstanceId), cloud.ErrNoFreeDeviceIndex)
}

// Detach implements cloud.Provider.
func (p *Provider) Detach(ctx context.Context, slotID string, force bool) error {
	eni, err := p.eni(ctx, slotID)
	if err != nil {
		return err
	}
	a := eni.Attachment
	if a == nil || a.Status == types.AttachmentStatusDetached {
		return nil
	}
	if a.Status != types.AttachmentStatusDetaching {
		_, err = p.ec2.DetachNetworkInterface(ctx, &ec2.DetachNetworkInterfaceInput{AttachmentId: a.AttachmentId, Force: aws.Bool(force)})
		if err != nil && !isNotFound(err) {
			return fmt.Errorf("detach %s: %w", slotID, err)
		}
	}
	deadline := time.Now().Add(p.detachTimeout)
	for {
		eni, err = p.eni(ctx, slotID)
		if err != nil {
			return err
		}
		if eni.Status == types.NetworkInterfaceStatusAvailable {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("detach %s: still %s after %s", slotID, eni.Status, p.detachTimeout)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("detach %s: %w", slotID, ctx.Err())
		case <-time.After(p.pollInterval):
		}
	}
}

func (p *Provider) eni(ctx context.Context, id string) (*types.NetworkInterface, error) {
	out, err := p.ec2.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{NetworkInterfaceIds: []string{id}})
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("%s: %w", id, cloud.ErrNotFound)
		}
		return nil, fmt.Errorf("describe %s: %w", id, err)
	}
	if len(out.NetworkInterfaces) != 1 {
		return nil, fmt.Errorf("%s: %w", id, cloud.ErrNotFound)
	}
	return &out.NetworkInterfaces[0], nil
}

func (p *Provider) instance(ctx context.Context, id string) (*types.Instance, error) {
	out, err := p.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{id}})
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("%s: %w", id, cloud.ErrNotFound)
		}
		return nil, fmt.Errorf("describe %s: %w", id, err)
	}
	for _, r := range out.Reservations {
		for i := range r.Instances {
			return &r.Instances[i], nil
		}
	}
	return nil, fmt.Errorf("%s: %w", id, cloud.ErrNotFound)
}

func isNotFound(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	return strings.HasSuffix(api.ErrorCode(), ".NotFound") || api.ErrorCode() == "InvalidAttachmentID.NotFound"
}

// subnetCIDRs maps each slot's subnet to its IPv4 CIDR block.
func (p *Provider) subnetCIDRs(ctx context.Context, enis []types.NetworkInterface) (map[string]string, error) {
	var ids []string
	for i := range enis {
		ids = append(ids, aws.ToString(enis[i].SubnetId))
	}
	out := map[string]string{}
	pager := ec2.NewDescribeSubnetsPaginator(p.ec2, &ec2.DescribeSubnetsInput{SubnetIds: unique(ids)})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe subnets: %w", err)
		}
		for _, sn := range page.Subnets {
			out[aws.ToString(sn.SubnetId)] = aws.ToString(sn.CidrBlock)
		}
	}
	return out, nil
}

func unique(in []string) []string {
	slices.Sort(in)
	return slices.Compact(in)
}
