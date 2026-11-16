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

package main

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config describes the fake VPC: its subnets, security groups, slots and
// the instances behind the cluster's nodes.
type Config struct {
	Cluster        string          `json:"cluster"`
	VPC            string          `json:"vpc"`
	Subnets        []Subnet        `json:"subnets"`
	SecurityGroups []SecurityGroup `json:"securityGroups"`
	Slots          []Slot          `json:"slots"`
	Instances      []Instance      `json:"instances"`
	// NodePublicIP is the address node traffic that no gateway carries
	// leaves from, as a NAT gateway would give it.
	NodePublicIP string `json:"nodePublicIP"`
}

// Subnet is a subnet and the router at its first address.
type Subnet struct {
	ID   string `json:"id"`
	Zone string `json:"zone"`
	CIDR string `json:"cidr"`
	// NoInternet gives the subnet a route table without an internet gateway.
	NoInternet bool `json:"noInternet,omitempty"`
}

// SecurityGroup is a security group. Inbound gives it an inbound rule from
// anywhere; InboundFromVPC one from the VPC's own blocks, as a bootstrap
// route needs.
type SecurityGroup struct {
	ID             string `json:"id"`
	Inbound        bool   `json:"inbound,omitempty"`
	InboundFromVPC bool   `json:"inboundFromVPC,omitempty"`
}

// Slot is an ENI. Its fields default to a slot that passes every safety check.
type Slot struct {
	ID        string `json:"id"`
	Subnet    string `json:"subnet"`
	PrivateIP string `json:"privateIP"`
	// PublicIP is the Elastic IP; empty for none.
	PublicIP         string            `json:"publicIP,omitempty"`
	MAC              string            `json:"mac"`
	Groups           []string          `json:"groups"`
	SourceDestCheck  bool              `json:"sourceDestCheck,omitempty"`
	InterfaceType    string            `json:"interfaceType,omitempty"`
	RequesterManaged bool              `json:"requesterManaged,omitempty"`
	Tags             map[string]string `json:"tags"`
	// RouteTarget makes a route table send traffic to the slot.
	RouteTarget bool `json:"routeTarget,omitempty"`
}

// Instance is a node's machine. Node is the kind node container's hostname.
type Instance struct {
	ID   string            `json:"id"`
	Zone string            `json:"zone"`
	Node string            `json:"node"`
	Tags map[string]string `json:"tags"`
	// MaxInterfaces, when set, is the instance type's interface limit,
	// counting the primary interface.
	MaxInterfaces int `json:"maxInterfaces,omitempty"`
}

// Links moves a slot's interface between the fake VPC and a node.
type Links interface {
	Attach(s *Slot, in *Instance) error
	Detach(s *Slot) error
}

// attachment is a slot's current attachment.
type attachment struct {
	ID       string `json:"id"`
	Instance string `json:"instance"`
	Device   int    `json:"deviceIndex"`
	// Status is attached or detaching.
	Status string `json:"status"`
}

// fault makes the next Count calls of an action fail with Code.
type fault struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

// EC2 serves the EC2 Query API calls the provider makes, plus /_fake/ for
// the test to read the state and inject faults.
type EC2 struct {
	cfg   Config
	links Links
	// DetachDelay is how long a detach stays in the detaching state.
	DetachDelay time.Duration

	mu       sync.Mutex
	attached map[string]*attachment // slot ID -> attachment
	faults   map[string]*fault      // action -> fault
	calls    map[string]int         // action -> count
	seq      int
}

// NewEC2 returns the fake for cfg.
func NewEC2(cfg Config, links Links) (*EC2, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &EC2{
		cfg: cfg, links: links, DetachDelay: time.Second,
		attached: map[string]*attachment{}, faults: map[string]*fault{}, calls: map[string]int{},
	}, nil
}

func (c *Config) validate() error {
	subnets := map[string]bool{}
	for _, s := range c.Subnets {
		subnets[s.ID] = true
	}
	groups := map[string]bool{}
	for _, g := range c.SecurityGroups {
		groups[g.ID] = true
	}
	for _, s := range c.Slots {
		if !subnets[s.Subnet] {
			return fmt.Errorf("slot %s: unknown subnet %q", s.ID, s.Subnet)
		}
		for _, g := range s.Groups {
			if !groups[g] {
				return fmt.Errorf("slot %s: unknown security group %q", s.ID, g)
			}
		}
	}
	return nil
}

// apiError is an EC2 error response.
type apiError struct {
	status int
	code   string
	msg    string
}

func (e *apiError) Error() string { return e.code + ": " + e.msg }

func notFound(code, id string) error {
	return &apiError{http.StatusBadRequest, code, fmt.Sprintf("The ID '%s' does not exist", id)}
}

func invalid(msg string) error {
	return &apiError{http.StatusBadRequest, "InvalidParameterValue", msg}
}

const xmlns = "http://ec2.amazonaws.com/doc/2016-11-15/"

func (f *EC2) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/_fake/") {
		f.admin(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, invalid(err.Error()))
		return
	}
	action := r.Form.Get("Action")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[action]++
	if ft := f.faults[action]; ft != nil && ft.Count > 0 {
		ft.Count--
		status := http.StatusBadRequest
		if ft.Code == "InternalError" || ft.Code == "Unavailable" {
			status = http.StatusServiceUnavailable
		}
		writeError(w, &apiError{status, ft.Code, "injected fault"})
		return
	}
	body, err := f.handle(action, r.Form)
	if err != nil {
		writeError(w, err)
		return
	}
	f.seq++
	w.Header().Set("Content-Type", "text/xml;charset=UTF-8")
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		ae = &apiError{http.StatusInternalServerError, "InternalError", err.Error()}
	}
	type errXML struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	w.Header().Set("Content-Type", "text/xml;charset=UTF-8")
	w.WriteHeader(ae.status)
	_ = xml.NewEncoder(w).Encode(struct {
		XMLName   xml.Name `xml:"Response"`
		Errors    []errXML `xml:"Errors>Error"`
		RequestID string   `xml:"RequestID"`
	}{Errors: []errXML{{ae.code, ae.msg}}, RequestID: "fake"})
}

func (f *EC2) handle(action string, form map[string][]string) (any, error) {
	q := query(form)
	switch action {
	case "DescribeNetworkInterfaces":
		return f.describeENIs(q)
	case "DescribeSecurityGroups":
		return f.describeGroups(q)
	case "DescribeRouteTables":
		return f.describeRouteTables(q)
	case "DescribeInstances":
		return f.describeInstances(q)
	case "DescribeSubnets":
		return f.describeSubnets(q)
	case "DescribeVpcs":
		return f.describeVPCs(q)
	case "AttachNetworkInterface":
		return f.attach(q)
	case "DetachNetworkInterface":
		return f.detach(q)
	}
	return nil, &apiError{http.StatusBadRequest, "InvalidAction", fmt.Sprintf("The action %s is not valid for this web service", action)}
}

// query reads EC2 Query list parameters such as NetworkInterfaceId.1 and
// Filter.1.Value.2.
type query map[string][]string

func (q query) get(k string) string {
	if v := q[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func (q query) list(prefix string) []string {
	var out []string
	for i := 1; ; i++ {
		v := q.get(prefix + "." + strconv.Itoa(i))
		if v == "" {
			return out
		}
		out = append(out, v)
	}
}

func (q query) filters() map[string][]string {
	out := map[string][]string{}
	for i := 1; ; i++ {
		p := "Filter." + strconv.Itoa(i)
		name := q.get(p + ".Name")
		if name == "" {
			return out
		}
		out[name] = q.list(p + ".Value")
	}
}

type tagXML struct {
	Key   string `xml:"key"`
	Value string `xml:"value"`
}

func tagsXML(m map[string]string) []tagXML {
	out := make([]tagXML, 0, len(m))
	for _, k := range slices.Sorted(maps.Keys(m)) {
		out = append(out, tagXML{k, m[k]})
	}
	return out
}

type groupXML struct {
	ID string `xml:"groupId"`
}

type attachmentXML struct {
	ID          string `xml:"attachmentId"`
	Instance    string `xml:"instanceId,omitempty"`
	DeviceIndex int    `xml:"deviceIndex"`
	CardIndex   int    `xml:"networkCardIndex"`
	Status      string `xml:"status"`
}

type eniXML struct {
	ID               string     `xml:"networkInterfaceId"`
	Zone             string     `xml:"availabilityZone"`
	Subnet           string     `xml:"subnetId"`
	VPC              string     `xml:"vpcId"`
	PrivateIP        string     `xml:"privateIpAddress"`
	MAC              string     `xml:"macAddress"`
	Status           string     `xml:"status"`
	Type             string     `xml:"interfaceType"`
	RequesterManaged bool       `xml:"requesterManaged"`
	SourceDestCheck  bool       `xml:"sourceDestCheck"`
	Groups           []groupXML `xml:"groupSet>item"`
	Tags             []tagXML   `xml:"tagSet>item"`
	Association      *struct {
		PublicIP string `xml:"publicIp"`
	} `xml:"association"`
	Attachment *attachmentXML `xml:"attachment"`
}

func (f *EC2) subnet(id string) *Subnet {
	for i := range f.cfg.Subnets {
		if f.cfg.Subnets[i].ID == id {
			return &f.cfg.Subnets[i]
		}
	}
	return nil
}

func (f *EC2) slot(id string) *Slot {
	for i := range f.cfg.Slots {
		if f.cfg.Slots[i].ID == id {
			return &f.cfg.Slots[i]
		}
	}
	return nil
}

func (f *EC2) instance(id string) *Instance {
	for i := range f.cfg.Instances {
		if f.cfg.Instances[i].ID == id {
			return &f.cfg.Instances[i]
		}
	}
	return nil
}

func (f *EC2) eniXML(s *Slot) eniXML {
	e := eniXML{
		ID: s.ID, Zone: f.subnet(s.Subnet).Zone, Subnet: s.Subnet, VPC: f.cfg.VPC,
		PrivateIP: s.PrivateIP, MAC: s.MAC, Status: "available", Type: s.InterfaceType,
		RequesterManaged: s.RequesterManaged, SourceDestCheck: s.SourceDestCheck, Tags: tagsXML(s.Tags),
	}
	if e.Type == "" {
		e.Type = "interface"
	}
	for _, g := range s.Groups {
		e.Groups = append(e.Groups, groupXML{g})
	}
	if s.PublicIP != "" {
		e.Association = &struct {
			PublicIP string `xml:"publicIp"`
		}{s.PublicIP}
	}
	if a := f.attached[s.ID]; a != nil {
		e.Status = "in-use"
		e.Attachment = &attachmentXML{ID: a.ID, Instance: a.Instance, DeviceIndex: a.Device, Status: a.Status}
	}
	return e
}

func (f *EC2) describeENIs(q query) (any, error) {
	ids := q.list("NetworkInterfaceId")
	filters := q.filters()
	var out []eniXML
	for _, id := range ids {
		if f.slot(id) == nil {
			return nil, notFound("InvalidNetworkInterfaceID.NotFound", id)
		}
	}
	for i := range f.cfg.Slots {
		s := &f.cfg.Slots[i]
		if len(ids) > 0 && !slices.Contains(ids, s.ID) {
			continue
		}
		ok, err := f.matches(s, filters)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, f.eniXML(s))
		}
	}
	return struct {
		XMLName   xml.Name `xml:"DescribeNetworkInterfacesResponse"`
		Xmlns     string   `xml:"xmlns,attr"`
		RequestID string   `xml:"requestId"`
		Items     []eniXML `xml:"networkInterfaceSet>item"`
	}{Xmlns: xmlns, RequestID: f.requestID(), Items: out}, nil
}

func (f *EC2) matches(s *Slot, filters map[string][]string) (bool, error) {
	for name, values := range filters {
		switch {
		case strings.HasPrefix(name, "tag:"):
			v, ok := s.Tags[strings.TrimPrefix(name, "tag:")]
			if !ok || !slices.Contains(values, v) {
				return false, nil
			}
		case name == "vpc-id":
			if !slices.Contains(values, f.cfg.VPC) {
				return false, nil
			}
		default:
			return false, invalid(fmt.Sprintf("The filter '%s' is invalid", name))
		}
	}
	return true, nil
}

func (f *EC2) describeGroups(q query) (any, error) {
	type rangeXML struct {
		CIDR string `xml:"cidrIp"`
	}
	type permXML struct {
		Protocol string     `xml:"ipProtocol"`
		Ranges   []rangeXML `xml:"ipRanges>item"`
	}
	type sgXML struct {
		ID    string    `xml:"groupId"`
		VPC   string    `xml:"vpcId"`
		Perms []permXML `xml:"ipPermissions>item"`
	}
	var out []sgXML
	for _, id := range q.list("GroupId") {
		i := slices.IndexFunc(f.cfg.SecurityGroups, func(g SecurityGroup) bool { return g.ID == id })
		if i < 0 {
			return nil, notFound("InvalidGroup.NotFound", id)
		}
		g := sgXML{ID: id, VPC: f.cfg.VPC}
		if f.cfg.SecurityGroups[i].Inbound {
			g.Perms = append(g.Perms, permXML{"tcp", []rangeXML{{"0.0.0.0/0"}}})
		}
		if f.cfg.SecurityGroups[i].InboundFromVPC {
			p := permXML{Protocol: "-1"}
			for _, sn := range f.cfg.Subnets {
				p.Ranges = append(p.Ranges, rangeXML{sn.CIDR})
			}
			g.Perms = append(g.Perms, p)
		}
		out = append(out, g)
	}
	return struct {
		XMLName   xml.Name `xml:"DescribeSecurityGroupsResponse"`
		Xmlns     string   `xml:"xmlns,attr"`
		RequestID string   `xml:"requestId"`
		Items     []sgXML  `xml:"securityGroupInfo>item"`
	}{Xmlns: xmlns, RequestID: f.requestID(), Items: out}, nil
}

func (f *EC2) describeRouteTables(q query) (any, error) {
	type assocXML struct {
		ID     string `xml:"routeTableAssociationId"`
		Main   bool   `xml:"main"`
		Subnet string `xml:"subnetId,omitempty"`
	}
	type routeXML struct {
		Dest    string `xml:"destinationCidrBlock"`
		Gateway string `xml:"gatewayId,omitempty"`
		ENI     string `xml:"networkInterfaceId,omitempty"`
		State   string `xml:"state"`
	}
	type rtXML struct {
		ID     string     `xml:"routeTableId"`
		VPC    string     `xml:"vpcId"`
		Assocs []assocXML `xml:"associationSet>item"`
		Routes []routeXML `xml:"routeSet>item"`
	}
	for name, values := range q.filters() {
		if name != "vpc-id" {
			return nil, invalid(fmt.Sprintf("The filter '%s' is invalid", name))
		}
		if !slices.Contains(values, f.cfg.VPC) {
			return struct {
				XMLName   xml.Name `xml:"DescribeRouteTablesResponse"`
				RequestID string   `xml:"requestId"`
			}{RequestID: f.requestID()}, nil
		}
	}
	// The main table routes to the internet gateway; a subnet without
	// internet gets its own table without that route. Route targets sit
	// in the main table as routes to on-premises ranges.
	main := rtXML{
		ID: "rtb-main", VPC: f.cfg.VPC,
		Assocs: []assocXML{{ID: "rtbassoc-main", Main: true}},
		Routes: []routeXML{{Dest: "0.0.0.0/0", Gateway: "igw-fake", State: "active"}},
	}
	for i, s := range f.cfg.Slots {
		if s.RouteTarget {
			main.Routes = append(main.Routes, routeXML{Dest: fmt.Sprintf("192.168.%d.0/24", i), ENI: s.ID, State: "active"})
		}
	}
	tables := []rtXML{main}
	for _, sn := range f.cfg.Subnets {
		if sn.NoInternet {
			tables = append(tables, rtXML{
				ID: "rtb-" + sn.ID, VPC: f.cfg.VPC,
				Assocs: []assocXML{{ID: "rtbassoc-" + sn.ID, Subnet: sn.ID}},
				Routes: []routeXML{{Dest: "10.0.0.0/8", Gateway: "local", State: "active"}},
			})
		}
	}
	return struct {
		XMLName   xml.Name `xml:"DescribeRouteTablesResponse"`
		Xmlns     string   `xml:"xmlns,attr"`
		RequestID string   `xml:"requestId"`
		Items     []rtXML  `xml:"routeTableSet>item"`
	}{Xmlns: xmlns, RequestID: f.requestID(), Items: tables}, nil
}

type instanceENIXML struct {
	ID         string        `xml:"networkInterfaceId"`
	Attachment attachmentXML `xml:"attachment"`
}

type instanceXML struct {
	ID        string `xml:"instanceId"`
	Placement struct {
		Zone string `xml:"availabilityZone"`
	} `xml:"placement"`
	Tags []tagXML         `xml:"tagSet>item"`
	ENIs []instanceENIXML `xml:"networkInterfaceSet>item"`
}

func (f *EC2) instanceXML(in *Instance) instanceXML {
	x := instanceXML{ID: in.ID, Tags: tagsXML(in.Tags)}
	x.Placement.Zone = in.Zone
	x.ENIs = []instanceENIXML{{ID: "eni-primary-" + in.ID, Attachment: attachmentXML{ID: "eni-attach-primary-" + in.ID, Status: "attached"}}}
	for _, id := range slices.Sorted(maps.Keys(f.attached)) {
		if a := f.attached[id]; a.Instance == in.ID {
			x.ENIs = append(x.ENIs, instanceENIXML{ID: id, Attachment: attachmentXML{ID: a.ID, DeviceIndex: a.Device, Status: a.Status}})
		}
	}
	return x
}

func (f *EC2) describeInstances(q query) (any, error) {
	type resXML struct {
		ID        string        `xml:"reservationId"`
		Instances []instanceXML `xml:"instancesSet>item"`
	}
	ids := q.list("InstanceId")
	var out []resXML
	for _, id := range ids {
		in := f.instance(id)
		if in == nil {
			return nil, notFound("InvalidInstanceID.NotFound", id)
		}
		out = append(out, resXML{ID: "r-" + id, Instances: []instanceXML{f.instanceXML(in)}})
	}
	if len(ids) == 0 {
		for i := range f.cfg.Instances {
			in := &f.cfg.Instances[i]
			out = append(out, resXML{ID: "r-" + in.ID, Instances: []instanceXML{f.instanceXML(in)}})
		}
	}
	return struct {
		XMLName   xml.Name `xml:"DescribeInstancesResponse"`
		Xmlns     string   `xml:"xmlns,attr"`
		RequestID string   `xml:"requestId"`
		Items     []resXML `xml:"reservationSet>item"`
	}{Xmlns: xmlns, RequestID: f.requestID(), Items: out}, nil
}

func (f *EC2) describeSubnets(q query) (any, error) {
	type subnetXML struct {
		ID   string `xml:"subnetId"`
		VPC  string `xml:"vpcId"`
		CIDR string `xml:"cidrBlock"`
		Zone string `xml:"availabilityZone"`
	}
	var out []subnetXML
	for _, id := range q.list("SubnetId") {
		sn := f.subnet(id)
		if sn == nil {
			return nil, notFound("InvalidSubnetID.NotFound", id)
		}
		out = append(out, subnetXML{sn.ID, f.cfg.VPC, sn.CIDR, sn.Zone})
	}
	return struct {
		XMLName   xml.Name    `xml:"DescribeSubnetsResponse"`
		Xmlns     string      `xml:"xmlns,attr"`
		RequestID string      `xml:"requestId"`
		Items     []subnetXML `xml:"subnetSet>item"`
	}{Xmlns: xmlns, RequestID: f.requestID(), Items: out}, nil
}

// describeVPCs gives the fake VPC its subnets' blocks.
func (f *EC2) describeVPCs(q query) (any, error) {
	type stateXML struct {
		State string `xml:"state"`
	}
	type assocXML struct {
		CIDR  string   `xml:"cidrBlock"`
		State stateXML `xml:"cidrBlockState"`
	}
	type vpcXML struct {
		ID     string     `xml:"vpcId"`
		Blocks []assocXML `xml:"cidrBlockAssociationSet>item"`
	}
	var out []vpcXML
	for _, id := range q.list("VpcId") {
		if id != f.cfg.VPC {
			return nil, notFound("InvalidVpcID.NotFound", id)
		}
		v := vpcXML{ID: id}
		for _, sn := range f.cfg.Subnets {
			v.Blocks = append(v.Blocks, assocXML{sn.CIDR, stateXML{"associated"}})
		}
		out = append(out, v)
	}
	return struct {
		XMLName   xml.Name `xml:"DescribeVpcsResponse"`
		Xmlns     string   `xml:"xmlns,attr"`
		RequestID string   `xml:"requestId"`
		Items     []vpcXML `xml:"vpcSet>item"`
	}{Xmlns: xmlns, RequestID: f.requestID(), Items: out}, nil
}

func (f *EC2) attach(q query) (any, error) {
	s := f.slot(q.get("NetworkInterfaceId"))
	if s == nil {
		return nil, notFound("InvalidNetworkInterfaceID.NotFound", q.get("NetworkInterfaceId"))
	}
	in := f.instance(q.get("InstanceId"))
	if in == nil {
		return nil, notFound("InvalidInstanceID.NotFound", q.get("InstanceId"))
	}
	device, err := strconv.Atoi(q.get("DeviceIndex"))
	if err != nil || device < 1 {
		return nil, invalid("DeviceIndex must be a positive integer")
	}
	if a := f.attached[s.ID]; a != nil {
		return nil, &apiError{
			http.StatusBadRequest, "InvalidParameterValue",
			fmt.Sprintf("Interface: [%s] in use.", s.ID),
		}
	}
	if zone := f.subnet(s.Subnet).Zone; zone != in.Zone {
		return nil, &apiError{
			http.StatusBadRequest, "InvalidParameterCombination",
			fmt.Sprintf("You may not attach a network interface to an instance if they are not in the same availability zone (%s, %s)", zone, in.Zone),
		}
	}
	for _, a := range f.attached {
		if a.Instance == in.ID && a.Device == device {
			return nil, invalid(fmt.Sprintf("Instance '%s' already has an interface attached at device index '%d'.", in.ID, device))
		}
	}
	if in.MaxInterfaces > 0 {
		count := 1
		for _, a := range f.attached {
			if a.Instance == in.ID {
				count++
			}
		}
		if count >= in.MaxInterfaces {
			return nil, &apiError{
				http.StatusBadRequest, "AttachmentLimitExceeded",
				fmt.Sprintf("Interface count %d exceeds the limit for this instance type", count+1),
			}
		}
	}
	if err := f.links.Attach(s, in); err != nil {
		return nil, &apiError{http.StatusInternalServerError, "InternalError", err.Error()}
	}
	a := &attachment{ID: fmt.Sprintf("eni-attach-%04d", f.seq), Instance: in.ID, Device: device, Status: "attached"}
	f.attached[s.ID] = a
	return struct {
		XMLName      xml.Name `xml:"AttachNetworkInterfaceResponse"`
		Xmlns        string   `xml:"xmlns,attr"`
		RequestID    string   `xml:"requestId"`
		AttachmentID string   `xml:"attachmentId"`
		CardIndex    int      `xml:"networkCardIndex"`
	}{Xmlns: xmlns, RequestID: f.requestID(), AttachmentID: a.ID}, nil
}

func (f *EC2) detach(q query) (any, error) {
	id := q.get("AttachmentId")
	var slotID string
	for sid, a := range f.attached {
		if a.ID == id {
			slotID = sid
		}
	}
	if slotID == "" {
		return nil, notFound("InvalidAttachmentID.NotFound", id)
	}
	a := f.attached[slotID]
	if a.Status != "detaching" {
		a.Status = "detaching"
		time.AfterFunc(f.DetachDelay, func() { f.finishDetach(slotID, a) })
	}
	return struct {
		XMLName   xml.Name `xml:"DetachNetworkInterfaceResponse"`
		Xmlns     string   `xml:"xmlns,attr"`
		RequestID string   `xml:"requestId"`
		Return    bool     `xml:"return"`
	}{Xmlns: xmlns, RequestID: f.requestID(), Return: true}, nil
}

func (f *EC2) finishDetach(slotID string, a *attachment) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.attached[slotID] != a {
		return
	}
	if err := f.links.Detach(f.slot(slotID)); err != nil {
		// The slot stays detaching; the provider times out and retries.
		fmt.Printf("detach %s: %v\n", slotID, err)
		time.AfterFunc(f.DetachDelay, func() { f.finishDetach(slotID, a) })
		return
	}
	delete(f.attached, slotID)
}

func (f *EC2) requestID() string { return fmt.Sprintf("fake-%06d", f.seq) }

// State is what /_fake/state returns.
type State struct {
	Attached map[string]*attachment `json:"attached"`
	Calls    map[string]int         `json:"calls"`
}

// admin serves GET /_fake/state and POST /_fake/fault?action=&code=&count=.
func (f *EC2) admin(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/_fake/state" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(State{Attached: f.attached, Calls: f.calls})
	case r.URL.Path == "/_fake/fault" && r.Method == http.MethodPost:
		n, err := strconv.Atoi(r.URL.Query().Get("count"))
		if err != nil || r.URL.Query().Get("action") == "" || r.URL.Query().Get("code") == "" {
			http.Error(w, "want action, code and count", http.StatusBadRequest)
			return
		}
		f.faults[r.URL.Query().Get("action")] = &fault{Code: r.URL.Query().Get("code"), Count: n}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}
