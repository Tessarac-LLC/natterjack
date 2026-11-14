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
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
	"github.com/Tessarac-LLC/natterjack/internal/cloud"
)

// fakeEC2 is an in-memory EC2 with just enough behavior for the provider.
type fakeEC2 struct {
	enis      map[string]*types.NetworkInterface
	sgs       map[string]types.SecurityGroup
	tables    []types.RouteTable
	instances map[string]types.Instance

	lastFilters []types.Filter
	attaches    []ec2.AttachNetworkInterfaceInput
	detaches    []string
	forced      []bool
	// detachPolls is how many describes a detaching ENI stays "detaching".
	detachPolls int
	polls       int
}

func notFound(code string) error { return &smithy.GenericAPIError{Code: code, Message: "not found"} }

func (f *fakeEC2) DescribeNetworkInterfaces(_ context.Context, in *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	out := &ec2.DescribeNetworkInterfacesOutput{}
	if len(in.NetworkInterfaceIds) > 0 {
		for _, id := range in.NetworkInterfaceIds {
			e, ok := f.enis[id]
			if !ok {
				return nil, notFound("InvalidNetworkInterfaceID.NotFound")
			}
			if e.Status == types.NetworkInterfaceStatusDetaching {
				f.polls++
				if f.polls > f.detachPolls {
					e.Status = types.NetworkInterfaceStatusAvailable
					e.Attachment = nil
				}
			}
			out.NetworkInterfaces = append(out.NetworkInterfaces, *e)
		}
		return out, nil
	}
	f.lastFilters = in.Filters
	ids := make([]string, 0, len(f.enis))
	for id := range f.enis {
		ids = append(ids, id)
	}
	slices.Sort(ids)
next:
	for _, id := range ids {
		e := f.enis[id]
		for _, flt := range in.Filters {
			key, ok := strings.CutPrefix(aws.ToString(flt.Name), "tag:")
			if !ok || !hasTag(e.TagSet, key, flt.Values[0]) {
				continue next
			}
		}
		out.NetworkInterfaces = append(out.NetworkInterfaces, *e)
	}
	return out, nil
}

func (f *fakeEC2) DescribeSecurityGroups(_ context.Context, in *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	out := &ec2.DescribeSecurityGroupsOutput{}
	for _, id := range in.GroupIds {
		if g, ok := f.sgs[id]; ok {
			out.SecurityGroups = append(out.SecurityGroups, g)
		}
	}
	return out, nil
}

func (f *fakeEC2) DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	return &ec2.DescribeRouteTablesOutput{RouteTables: f.tables}, nil
}

// DescribeSubnets gives every subnet a /24, except IPv6-only ones.
func (f *fakeEC2) DescribeSubnets(_ context.Context, in *ec2.DescribeSubnetsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	out := &ec2.DescribeSubnetsOutput{}
	for _, id := range in.SubnetIds {
		sn := types.Subnet{SubnetId: aws.String(id)}
		if !strings.Contains(id, "ipv6only") {
			sn.CidrBlock = aws.String("10.0.1.0/24")
		}
		out.Subnets = append(out.Subnets, sn)
	}
	return out, nil
}

func (f *fakeEC2) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	r := types.Reservation{}
	for _, id := range in.InstanceIds {
		i, ok := f.instances[id]
		if !ok {
			return nil, notFound("InvalidInstanceID.NotFound")
		}
		r.Instances = append(r.Instances, i)
	}
	return &ec2.DescribeInstancesOutput{Reservations: []types.Reservation{r}}, nil
}

func (f *fakeEC2) AttachNetworkInterface(_ context.Context, in *ec2.AttachNetworkInterfaceInput, _ ...func(*ec2.Options)) (*ec2.AttachNetworkInterfaceOutput, error) {
	f.attaches = append(f.attaches, *in)
	e := f.enis[aws.ToString(in.NetworkInterfaceId)]
	e.Status = types.NetworkInterfaceStatusInUse
	e.Attachment = &types.NetworkInterfaceAttachment{
		AttachmentId: aws.String("eni-attach-" + aws.ToString(in.InstanceId)),
		InstanceId:   in.InstanceId,
		DeviceIndex:  in.DeviceIndex,
		Status:       types.AttachmentStatusAttached,
	}
	return &ec2.AttachNetworkInterfaceOutput{AttachmentId: e.Attachment.AttachmentId}, nil
}

func (f *fakeEC2) DetachNetworkInterface(_ context.Context, in *ec2.DetachNetworkInterfaceInput, _ ...func(*ec2.Options)) (*ec2.DetachNetworkInterfaceOutput, error) {
	f.detaches = append(f.detaches, aws.ToString(in.AttachmentId))
	f.forced = append(f.forced, aws.ToBool(in.Force))
	for _, e := range f.enis {
		if e.Attachment != nil && aws.ToString(e.Attachment.AttachmentId) == aws.ToString(in.AttachmentId) {
			e.Status = types.NetworkInterfaceStatusDetaching
			e.Attachment.Status = types.AttachmentStatusDetaching
		}
	}
	return &ec2.DetachNetworkInterfaceOutput{}, nil
}

const cluster = "prod"

func tag(k, v string) types.Tag { return types.Tag{Key: aws.String(k), Value: aws.String(v)} }

// goodENI passes every safety check.
func goodENI(id, zone string) *types.NetworkInterface {
	return &types.NetworkInterface{
		NetworkInterfaceId: aws.String(id),
		AvailabilityZone:   aws.String(zone),
		SubnetId:           aws.String("subnet-public-" + zone),
		VpcId:              aws.String("vpc-1"),
		PrivateIpAddress:   aws.String("10.0.0.10"),
		MacAddress:         aws.String("02:00:00:00:00:01"),
		InterfaceType:      types.NetworkInterfaceTypeInterface,
		Status:             types.NetworkInterfaceStatusAvailable,
		SourceDestCheck:    aws.Bool(false),
		Association:        &types.NetworkInterfaceAssociation{PublicIp: aws.String("203.0.113.10")},
		Groups:             []types.GroupIdentifier{{GroupId: aws.String("sg-egress")}},
		TagSet: []types.Tag{
			tag(v1.TagEgress, "true"), tag(v1.TagCluster, cluster), tag(TagNoManage, "true"),
		},
	}
}

func newFake(enis ...*types.NetworkInterface) *fakeEC2 {
	f := &fakeEC2{
		enis: map[string]*types.NetworkInterface{},
		sgs: map[string]types.SecurityGroup{
			"sg-egress": {GroupId: aws.String("sg-egress")},
			"sg-open": {GroupId: aws.String("sg-open"), IpPermissions: []types.IpPermission{{
				IpProtocol: aws.String("tcp"), FromPort: aws.Int32(22), ToPort: aws.Int32(22),
				IpRanges: []types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
			}}},
		},
		tables: []types.RouteTable{
			{
				VpcId:        aws.String("vpc-1"),
				Associations: []types.RouteTableAssociation{{SubnetId: aws.String("subnet-public-us-east-2a")}, {SubnetId: aws.String("subnet-public-us-east-2b")}},
				Routes:       []types.Route{{DestinationCidrBlock: aws.String("0.0.0.0/0"), GatewayId: aws.String("igw-1")}},
			},
			{
				VpcId:        aws.String("vpc-1"),
				Associations: []types.RouteTableAssociation{{SubnetId: aws.String("subnet-private-us-east-2a")}},
				Routes:       []types.Route{{DestinationCidrBlock: aws.String("0.0.0.0/0"), NetworkInterfaceId: aws.String("eni-a")}},
			},
			{
				VpcId:        aws.String("vpc-1"),
				Associations: []types.RouteTableAssociation{{Main: aws.Bool(true)}},
				Routes:       []types.Route{{DestinationCidrBlock: aws.String("10.0.0.0/16"), GatewayId: aws.String("local")}},
			},
		},
		instances: map[string]types.Instance{
			"i-0a": instance("i-0a", "us-east-2a", tag("aws:eks:cluster-name", cluster)),
			"i-0b": instance("i-0b", "us-east-2b", tag("kubernetes.io/cluster/"+cluster, "owned")),
			"i-0f": instance("i-0f", "us-east-2a", tag("aws:eks:cluster-name", "someone-else")),
		},
	}
	for _, e := range enis {
		f.enis[aws.ToString(e.NetworkInterfaceId)] = e
	}
	return f
}

func instance(id, zone string, tags ...types.Tag) types.Instance {
	return types.Instance{
		InstanceId: aws.String(id),
		Placement:  &types.Placement{AvailabilityZone: aws.String(zone)},
		Tags:       tags,
		NetworkInterfaces: []types.InstanceNetworkInterface{{
			Attachment: &types.InstanceNetworkInterfaceAttachment{DeviceIndex: aws.Int32(0), NetworkCardIndex: aws.Int32(0)},
		}},
	}
}

func newProvider(f *fakeEC2) *Provider {
	p := New(f, cluster)
	p.pollInterval = time.Millisecond
	p.detachTimeout = time.Second
	return p
}

func slots(t *testing.T, f *fakeEC2) map[string]cloud.Slot {
	t.Helper()
	got, err := newProvider(f).Slots(context.Background(), cloud.Discovery{ClusterName: cluster})
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]cloud.Slot{}
	for _, s := range got {
		m[s.ID] = s
	}
	return m
}

func TestDiscoveryFiltersByTags(t *testing.T) {
	other := goodENI("eni-other", "us-east-2a")
	other.TagSet[1] = tag(v1.TagCluster, "staging")
	untagged := goodENI("eni-untagged", "us-east-2a")
	untagged.TagSet = untagged.TagSet[1:]
	pooled := goodENI("eni-pooled", "us-east-2a")
	pooled.TagSet = append(pooled.TagSet, tag(v1.TagPool, "partners"))
	f := newFake(goodENI("eni-a", "us-east-2a"), other, untagged, pooled)

	got, err := newProvider(f).Slots(context.Background(), cloud.Discovery{ClusterName: cluster, ExtraTags: map[string]string{v1.TagPool: "partners"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "eni-pooled" {
		t.Fatalf("want only eni-pooled, got %+v", got)
	}
	names := []string{}
	for _, flt := range f.lastFilters {
		names = append(names, aws.ToString(flt.Name)+"="+flt.Values[0])
	}
	want := []string{"tag:natterjack.io/egress=true", "tag:natterjack.io/cluster=prod", "tag:natterjack.io/pool=partners"}
	if !slices.Equal(names, want) {
		t.Fatalf("filters %v, want %v", names, want)
	}

	if _, err := newProvider(f).Slots(context.Background(), cloud.Discovery{}); err == nil {
		t.Fatal("discovery without a cluster name must fail rather than match every cluster")
	}
}

func TestHealthySlot(t *testing.T) {
	s := slots(t, newFake(goodENI("eni-a", "us-east-2a")))["eni-a"]
	if !s.Usable() {
		t.Fatalf("problems on a correct slot: %v", s.Problems)
	}
	if s.PublicIP != "203.0.113.10" || s.Zone != "us-east-2a" || s.MAC == "" || !s.RouteTarget || s.SubnetCIDR != "10.0.1.0/24" {
		t.Fatalf("slot fields not reported: %+v", s)
	}
}

func TestSafetyChecks(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*types.NetworkInterface)
		want   string
	}{
		{"no elastic ip", func(e *types.NetworkInterface) { e.Association = nil }, "no Elastic IP"},
		{"source dest check on", func(e *types.NetworkInterface) { e.SourceDestCheck = aws.Bool(true) }, "source/destination check is enabled"},
		{"source dest check unknown", func(e *types.NetworkInterface) { e.SourceDestCheck = nil }, "source/destination check is enabled"},
		{"vpc cni may manage it", func(e *types.NetworkInterface) { e.TagSet = e.TagSet[:2] }, TagNoManage},
		{"inbound rule", func(e *types.NetworkInterface) {
			e.Groups = append(e.Groups, types.GroupIdentifier{GroupId: aws.String("sg-open")})
		}, "sg-open allows inbound"},
		{"invisible group", func(e *types.NetworkInterface) {
			e.Groups = []types.GroupIdentifier{{GroupId: aws.String("sg-missing")}}
		}, "sg-missing allows inbound"},
		{"no group", func(e *types.NetworkInterface) { e.Groups = nil }, "no security group"},
		{"private subnet", func(e *types.NetworkInterface) { e.SubnetId = aws.String("subnet-private-us-east-2a") }, "no 0.0.0.0/0 route to an internet gateway"},
		{"ipv6-only subnet", func(e *types.NetworkInterface) { e.SubnetId = aws.String("subnet-ipv6only") }, "has no IPv4 CIDR block"},
		{"main table without igw", func(e *types.NetworkInterface) { e.SubnetId = aws.String("subnet-unassociated") }, "no 0.0.0.0/0 route to an internet gateway"},
		{"service managed", func(e *types.NetworkInterface) { e.RequesterManaged = aws.Bool(true) }, "managed by an AWS service"},
		{"load balancer interface", func(e *types.NetworkInterface) { e.InterfaceType = types.NetworkInterfaceTypeNetworkLoadBalancer }, "only a plain ENI"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := goodENI("eni-a", "us-east-2a")
			c.mutate(e)
			s := slots(t, newFake(e))["eni-a"]
			if s.Usable() {
				t.Fatal("slot is usable; want quarantined")
			}
			if !slices.ContainsFunc(s.Problems, func(p string) bool { return strings.Contains(p, c.want) }) {
				t.Fatalf("problems %q do not mention %q", s.Problems, c.want)
			}
		})
	}
}

func TestMainRouteTableWithIGW(t *testing.T) {
	f := newFake(goodENI("eni-a", "us-east-2a"))
	f.enis["eni-a"].SubnetId = aws.String("subnet-unassociated")
	f.tables[2].Routes = append(f.tables[2].Routes, types.Route{DestinationCidrBlock: aws.String("0.0.0.0/0"), GatewayId: aws.String("igw-1")})
	if s := slots(t, f)["eni-a"]; !s.Usable() {
		t.Fatalf("subnet using the main table with an IGW route must pass: %v", s.Problems)
	}
	f.tables[2].Routes[1].State = types.RouteStateBlackhole
	if s := slots(t, f)["eni-a"]; s.Usable() {
		t.Fatal("a blackholed IGW route must not count")
	}
}

func TestAttachedInstanceOwnership(t *testing.T) {
	attached := func(id, inst string) *types.NetworkInterface {
		e := goodENI(id, "us-east-2a")
		e.Status = types.NetworkInterfaceStatusInUse
		e.Attachment = &types.NetworkInterfaceAttachment{InstanceId: aws.String(inst), AttachmentId: aws.String("att-" + id), Status: types.AttachmentStatusAttached}
		return e
	}
	got := slots(t, newFake(attached("eni-eks", "i-0a"), attached("eni-k8s", "i-0b"), attached("eni-foreign", "i-0f")))
	if s := got["eni-eks"]; s.Instance != "i-0a" || !s.InstanceInCluster {
		t.Fatalf("EKS node not recognized: %+v", s)
	}
	if s := got["eni-k8s"]; !s.InstanceInCluster {
		t.Fatalf("kubernetes.io/cluster tag not recognized: %+v", s)
	}
	if s := got["eni-foreign"]; s.Instance != "i-0f" || s.InstanceInCluster {
		t.Fatalf("instance of another cluster reported as ours: %+v", s)
	}
}

func TestInstanceForProviderID(t *testing.T) {
	p := newProvider(newFake())
	got, err := p.InstanceForProviderID("aws:///us-east-2a/i-0123456789abcdef0")
	if err != nil || got.ID != "i-0123456789abcdef0" || got.Zone != "us-east-2a" {
		t.Fatalf("got %+v, %v", got, err)
	}
	for _, bad := range []string{"", "gce://p/z/n", "aws:///us-east-2a/", "aws:///us-east-2a/i-0123;rm"} {
		if _, err := p.InstanceForProviderID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAttach(t *testing.T) {
	f := newFake(goodENI("eni-a", "us-east-2a"))
	inst := f.instances["i-0a"]
	inst.NetworkInterfaces = append(inst.NetworkInterfaces, types.InstanceNetworkInterface{
		Attachment: &types.InstanceNetworkInterfaceAttachment{DeviceIndex: aws.Int32(1), NetworkCardIndex: aws.Int32(0)},
	})
	f.instances["i-0a"] = inst
	p := newProvider(f)

	if err := p.Attach(context.Background(), "eni-a", "i-0a"); err != nil {
		t.Fatal(err)
	}
	if len(f.attaches) != 1 || aws.ToInt32(f.attaches[0].DeviceIndex) != 2 {
		t.Fatalf("want one attach at device index 2, got %+v", f.attaches)
	}
	if err := p.Attach(context.Background(), "eni-a", "i-0a"); err != nil || len(f.attaches) != 1 {
		t.Fatalf("re-attaching to the same instance must be a no-op: %v, %d calls", err, len(f.attaches))
	}
	if err := p.Attach(context.Background(), "eni-a", "i-0f"); !errors.Is(err, cloud.ErrAttachedElsewhere) {
		t.Fatalf("want ErrAttachedElsewhere, got %v", err)
	}
}

func TestAttachRefusesOtherZone(t *testing.T) {
	f := newFake(goodENI("eni-b", "us-east-2b"))
	err := newProvider(f).Attach(context.Background(), "eni-b", "i-0a")
	if err == nil || !strings.Contains(err.Error(), "us-east-2a") || len(f.attaches) != 0 {
		t.Fatalf("cross-zone attach must be refused before calling EC2: %v", err)
	}
}

func TestAttachMissing(t *testing.T) {
	f := newFake(goodENI("eni-a", "us-east-2a"))
	p := newProvider(f)
	if err := p.Attach(context.Background(), "eni-gone", "i-0a"); !errors.Is(err, cloud.ErrNotFound) {
		t.Fatalf("missing ENI: %v", err)
	}
	if err := p.Attach(context.Background(), "eni-a", "i-gone"); !errors.Is(err, cloud.ErrNotFound) {
		t.Fatalf("missing instance: %v", err)
	}
}

func TestDetachWaitsUntilAvailable(t *testing.T) {
	f := newFake(goodENI("eni-a", "us-east-2a"))
	p := newProvider(f)
	if err := p.Attach(context.Background(), "eni-a", "i-0a"); err != nil {
		t.Fatal(err)
	}
	f.detachPolls = 3
	if err := p.Detach(context.Background(), "eni-a", false); err != nil {
		t.Fatal(err)
	}
	if len(f.detaches) != 1 || f.enis["eni-a"].Status != types.NetworkInterfaceStatusAvailable {
		t.Fatalf("detach did not complete: %d calls, status %s", len(f.detaches), f.enis["eni-a"].Status)
	}
	if err := p.Detach(context.Background(), "eni-a", false); err != nil || len(f.detaches) != 1 {
		t.Fatalf("detaching a free ENI must be a no-op: %v, %d calls", err, len(f.detaches))
	}
}

func TestDetachTimesOut(t *testing.T) {
	f := newFake(goodENI("eni-a", "us-east-2a"))
	p := newProvider(f)
	p.detachTimeout = 20 * time.Millisecond
	if err := p.Attach(context.Background(), "eni-a", "i-0a"); err != nil {
		t.Fatal(err)
	}
	f.detachPolls = 1 << 30
	if err := p.Detach(context.Background(), "eni-a", false); err == nil || !strings.Contains(err.Error(), "still") {
		t.Fatalf("want a timeout error, got %v", err)
	}
}

func TestForcedDetach(t *testing.T) {
	f := newFake(goodENI("eni-a", "us-east-2a"))
	p := newProvider(f)
	if err := p.Attach(context.Background(), "eni-a", "i-0a"); err != nil {
		t.Fatal(err)
	}
	if err := p.Detach(context.Background(), "eni-a", true); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.forced, []bool{true}) {
		t.Fatalf("force not passed to EC2: %v", f.forced)
	}
}

func TestSlotTags(t *testing.T) {
	e := goodENI("eni-a", "us-east-2a")
	e.TagSet = append(e.TagSet, tag(v1.TagPool, "partners"))
	s := slots(t, newFake(e))["eni-a"]
	if s.Tags[v1.TagPool] != "partners" || s.Tags[v1.TagCluster] != cluster {
		t.Fatalf("tags not reported: %v", s.Tags)
	}
}

func TestStrays(t *testing.T) {
	typo := goodENI("eni-typo", "us-east-2a")
	typo.TagSet[1] = tag(v1.TagCluster, "prdo")
	missing := goodENI("eni-missing", "us-east-2b")
	missing.TagSet = []types.Tag{tag(v1.TagEgress, "true")}
	f := newFake(goodENI("eni-ours", "us-east-2a"), typo, missing)
	got, err := newProvider(f).Strays(context.Background(), cluster)
	if err != nil {
		t.Fatal(err)
	}
	want := []cloud.Stray{{ID: "eni-missing", Zone: "us-east-2b"}, {ID: "eni-typo", Zone: "us-east-2a", Cluster: "prdo"}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
