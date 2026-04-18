package fortigate

import (
	"context"
	"encoding/json"
	"net/url"
)

type dnsStringList []string

func (h *dnsStringList) UnmarshalJSON(data []byte) error {
	var objects []struct {
		Hostname string `json:"hostname"`
		Domain   string `json:"domain"`
		Name     string `json:"name"`
	}
	if err := json.Unmarshal(data, &objects); err == nil {
		out := make([]string, 0, len(objects))
		for _, obj := range objects {
			switch {
			case obj.Hostname != "":
				out = append(out, obj.Hostname)
			case obj.Domain != "":
				out = append(out, obj.Domain)
			case obj.Name != "":
				out = append(out, obj.Name)
			}
		}
		*h = out
		return nil
	}
	var strings []string
	if err := json.Unmarshal(data, &strings); err == nil {
		*h = strings
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*h = nil
		return nil
	}
	*h = []string{s}
	return nil
}

type apiZone struct {
	Name        string      `json:"name"`
	Interface   []namedItem `json:"interface"`
	Intrazone   string      `json:"intrazone"`
	Description string      `json:"description"`
}

type apiDNSSettings struct {
	Primary               string        `json:"primary"`
	Secondary             string        `json:"secondary"`
	IP6Primary            string        `json:"ip6-primary"`
	IP6Secondary          string        `json:"ip6-secondary"`
	Protocol              string        `json:"protocol"`
	ServerHostnames       dnsStringList `json:"server-hostname"`
	Domains               dnsStringList `json:"domain"`
	SourceIP              string        `json:"source-ip"`
	Interface             string        `json:"interface"`
	InterfaceSelectMethod string        `json:"interface-select-method"`
}

type apiDNSServer struct {
	Name             string `json:"name"`
	Mode             string `json:"mode"`
	DNSFilterProfile string `json:"dnsfilter-profile"`
}

type apiDHCPIPRange struct {
	ID      int    `json:"id"`
	StartIP string `json:"start-ip"`
	EndIP   string `json:"end-ip"`
}

type apiDHCPServer struct {
	ID             int              `json:"id"`
	Interface      string           `json:"interface"`
	DefaultGateway string           `json:"default-gateway"`
	Netmask        string           `json:"netmask"`
	Domain         string           `json:"domain"`
	DNSService     string           `json:"dns-service"`
	DNSServer1     string           `json:"dns-server1"`
	DNSServer2     string           `json:"dns-server2"`
	DNSServer3     string           `json:"dns-server3"`
	LeaseTime      int              `json:"lease-time"`
	IPRange        []apiDHCPIPRange `json:"ip-range"`
	Status         string           `json:"status"`
}

type apiDHCPv6IPRange struct {
	ID      int    `json:"id"`
	StartIP string `json:"start-ip6"`
	EndIP   string `json:"end-ip6"`
}

type apiDHCPv6Server struct {
	ID         int                `json:"id"`
	Interface  string             `json:"interface"`
	Subnet     string             `json:"subnet"`
	DNSService string             `json:"dns-service"`
	DNSServer1 string             `json:"dns-server1"`
	DNSServer2 string             `json:"dns-server2"`
	IPRange    []apiDHCPv6IPRange `json:"ip-range"`
	Status     string             `json:"status"`
}

type apiSDWANSettings struct {
	Status          string                `json:"status"`
	LoadBalanceMode string                `json:"load-balance-mode"`
	Members         []apiSDWANMember      `json:"members"`
	Zones           []apiSDWANZone        `json:"zone"`
	Services        []apiSDWANService     `json:"service"`
	HealthChecks    []apiSDWANHealthCheck `json:"health-check"`
}

type apiSDWANMember struct {
	ID        int    `json:"id"`
	SeqNum    int    `json:"seq-num"`
	Interface string `json:"interface"`
	Gateway   string `json:"gateway"`
	Zone      string `json:"zone"`
	Status    string `json:"status"`
	Cost      int    `json:"cost"`
	Priority  int    `json:"priority"`
	Comment   string `json:"comment"`
}

type apiSDWANZone struct {
	Name               string `json:"name"`
	ServiceSLATieBreak string `json:"service-sla-tie-break"`
}

type apiSDWANService struct {
	ID       int         `json:"id"`
	Name     string      `json:"name"`
	Mode     string      `json:"mode"`
	Status   string      `json:"status"`
	Priority []namedItem `json:"priority-members"`
}

type apiSDWANHealthCheck struct {
	Name   string `json:"name"`
	Server string `json:"server"`
	Status string `json:"status"`
}

// ListZones retrieves interface zones from a VDOM.
func (c *Client) ListZones(ctx context.Context, vdom string, opts ...ListOption) ([]Zone, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiZone](ctx, c, "/api/v2/cmdb/system/zone",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	zones := make([]Zone, len(items))
	for i, z := range items {
		zones[i] = Zone{
			Name:        z.Name,
			Interfaces:  namesOf(z.Interface),
			Intrazone:   z.Intrazone,
			Description: z.Description,
		}
	}
	return zones, nil
}

// GetDNSSettings retrieves global DNS resolver settings.
func (c *Client) GetDNSSettings(ctx context.Context) (DNSSettings, error) {
	if !c.LoggedIn() {
		return DNSSettings{}, ErrNotLoggedIn
	}
	item, err := getOne[apiDNSSettings](ctx, c, "/api/v2/cmdb/system/dns", nil)
	if err != nil {
		return DNSSettings{}, err
	}
	return DNSSettings{
		Primary:               item.Primary,
		Secondary:             item.Secondary,
		IP6Primary:            item.IP6Primary,
		IP6Secondary:          item.IP6Secondary,
		Protocol:              item.Protocol,
		ServerHostnames:       item.ServerHostnames,
		Domains:               item.Domains,
		SourceIP:              item.SourceIP,
		Interface:             item.Interface,
		InterfaceSelectMethod: item.InterfaceSelectMethod,
	}, nil
}

// ListDNSServers retrieves VDOM DNS services.
func (c *Client) ListDNSServers(ctx context.Context, vdom string, opts ...ListOption) ([]DNSServer, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiDNSServer](ctx, c, "/api/v2/cmdb/system/dns-server",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}
	servers := make([]DNSServer, len(items))
	for i, s := range items {
		servers[i] = DNSServer(s)
	}
	return servers, nil
}

// ListDHCPServers retrieves IPv4 DHCP servers from a VDOM.
func (c *Client) ListDHCPServers(ctx context.Context, vdom string, opts ...ListOption) ([]DHCPServer, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiDHCPServer](ctx, c, "/api/v2/cmdb/system.dhcp/server",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}
	servers := make([]DHCPServer, len(items))
	for i, s := range items {
		servers[i] = DHCPServer{
			ID:             s.ID,
			Interface:      s.Interface,
			DefaultGateway: s.DefaultGateway,
			Netmask:        s.Netmask,
			Domain:         s.Domain,
			DNSService:     s.DNSService,
			DNSServer1:     s.DNSServer1,
			DNSServer2:     s.DNSServer2,
			DNSServer3:     s.DNSServer3,
			LeaseTime:      s.LeaseTime,
			IPRanges:       dhcpIPRanges(s.IPRange),
			Status:         s.Status,
		}
	}
	return servers, nil
}

// ListDHCPv6Servers retrieves IPv6 DHCP servers from a VDOM.
func (c *Client) ListDHCPv6Servers(ctx context.Context, vdom string, opts ...ListOption) ([]DHCPv6Server, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiDHCPv6Server](ctx, c, "/api/v2/cmdb/system.dhcp6/server",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}
	servers := make([]DHCPv6Server, len(items))
	for i, s := range items {
		servers[i] = DHCPv6Server{
			ID:         s.ID,
			Interface:  s.Interface,
			Subnet:     s.Subnet,
			DNSService: s.DNSService,
			DNSServer1: s.DNSServer1,
			DNSServer2: s.DNSServer2,
			IPRanges:   dhcpv6IPRanges(s.IPRange),
			Status:     s.Status,
		}
	}
	return servers, nil
}

// GetSDWANSettings retrieves top-level SD-WAN configuration from a VDOM.
func (c *Client) GetSDWANSettings(ctx context.Context, vdom string) (SDWANSettings, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return SDWANSettings{}, err
	}
	item, err := getOne[apiSDWANSettings](ctx, c, "/api/v2/cmdb/system/sdwan", vdomParams(vdom))
	if err != nil {
		return SDWANSettings{}, err
	}
	return SDWANSettings{
		Status:          item.Status,
		LoadBalanceMode: item.LoadBalanceMode,
		Members:         sdwanMembers(item.Members),
		Zones:           sdwanZones(item.Zones),
		Services:        sdwanServices(item.Services),
		HealthChecks:    sdwanHealthChecks(item.HealthChecks),
	}, nil
}

// ListSDWANMembers retrieves SD-WAN member child objects from a VDOM.
func (c *Client) ListSDWANMembers(ctx context.Context, vdom string, opts ...ListOption) ([]SDWANMember, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	params := vdomParams(vdom)
	items, err := getPaged[apiSDWANMember](ctx, c, "/api/v2/cmdb/system/sdwan/members",
		params, buildListConfig(opts))
	if err != nil {
		return nil, err
	}
	return sdwanMembers(items), nil
}

// ListSDWANZones retrieves SD-WAN zone child objects from a VDOM.
func (c *Client) ListSDWANZones(ctx context.Context, vdom string, opts ...ListOption) ([]SDWANZone, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	params := url.Values{"vdom": {vdom}}
	items, err := getPaged[apiSDWANZone](ctx, c, "/api/v2/cmdb/system/sdwan/zone",
		params, buildListConfig(opts))
	if err != nil {
		return nil, err
	}
	return sdwanZones(items), nil
}

func dhcpIPRanges(items []apiDHCPIPRange) []DHCPIPRange {
	if len(items) == 0 {
		return []DHCPIPRange{}
	}
	out := make([]DHCPIPRange, len(items))
	for i, item := range items {
		out[i] = DHCPIPRange(item)
	}
	return out
}

func dhcpv6IPRanges(items []apiDHCPv6IPRange) []DHCPv6IPRange {
	if len(items) == 0 {
		return []DHCPv6IPRange{}
	}
	out := make([]DHCPv6IPRange, len(items))
	for i, item := range items {
		out[i] = DHCPv6IPRange(item)
	}
	return out
}

func sdwanMembers(items []apiSDWANMember) []SDWANMember {
	if len(items) == 0 {
		return []SDWANMember{}
	}
	out := make([]SDWANMember, len(items))
	for i, item := range items {
		out[i] = SDWANMember(item)
	}
	return out
}

func sdwanZones(items []apiSDWANZone) []SDWANZone {
	if len(items) == 0 {
		return []SDWANZone{}
	}
	out := make([]SDWANZone, len(items))
	for i, item := range items {
		out[i] = SDWANZone(item)
	}
	return out
}

func sdwanServices(items []apiSDWANService) []SDWANService {
	if len(items) == 0 {
		return []SDWANService{}
	}
	out := make([]SDWANService, len(items))
	for i, item := range items {
		out[i] = SDWANService{
			ID:       item.ID,
			Name:     item.Name,
			Mode:     item.Mode,
			Status:   item.Status,
			Priority: namesOf(item.Priority),
		}
	}
	return out
}

func sdwanHealthChecks(items []apiSDWANHealthCheck) []SDWANHealthCheck {
	if len(items) == 0 {
		return []SDWANHealthCheck{}
	}
	out := make([]SDWANHealthCheck, len(items))
	for i, item := range items {
		out[i] = SDWANHealthCheck(item)
	}
	return out
}
