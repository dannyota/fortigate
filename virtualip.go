package fortigate

import "context"

type apiVIPMappedIP struct {
	Range string `json:"range"`
}

type apiVirtualIP struct {
	Name        string           `json:"name"`
	ExtIP       string           `json:"extip"`
	MappedIP    []apiVIPMappedIP `json:"mappedip"`
	ExtIntf     string           `json:"extintf"`
	PortForward string           `json:"portforward"`
	ExtPort     string           `json:"extport"`
	MappedPort  string           `json:"mappedport"`
	Protocol    string           `json:"protocol"`
	Comment     string           `json:"comment"`
	Color       int              `json:"color"`
}

type apiIPv6VirtualIP struct {
	Name        string           `json:"name"`
	ExtIP       string           `json:"extip"`
	MappedIP    []apiVIPMappedIP `json:"mappedip"`
	ExtIntf     string           `json:"extintf"`
	PortForward string           `json:"portforward"`
	ExtPort     string           `json:"extport"`
	MappedPort  string           `json:"mappedport"`
	Protocol    string           `json:"protocol"`
	Comment     string           `json:"comment"`
	Color       int              `json:"color"`
}

type apiVirtualIPGroup struct {
	Name    string      `json:"name"`
	Member  []namedItem `json:"member"`
	Comment string      `json:"comment"`
	Color   int         `json:"color"`
}

// ListVirtualIPs retrieves virtual IP objects (DNAT) from a VDOM.
//
// Pagination is handled transparently.
func (c *Client) ListVirtualIPs(ctx context.Context, vdom string, opts ...ListOption) ([]VirtualIP, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiVirtualIP](ctx, c, "/api/v2/cmdb/firewall/vip",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	vips := make([]VirtualIP, len(items))
	for i, v := range items {
		vips[i] = VirtualIP{
			Name:        v.Name,
			ExtIP:       v.ExtIP,
			MappedIP:    vipMappedIP(v.MappedIP),
			ExtIntf:     v.ExtIntf,
			PortForward: isEnabled(v.PortForward),
			ExtPort:     v.ExtPort,
			MappedPort:  v.MappedPort,
			Protocol:    v.Protocol,
			Comment:     v.Comment,
			Color:       v.Color,
		}
	}

	return vips, nil
}

// ListIPv6VirtualIPs retrieves IPv6 virtual IP objects from a VDOM.
func (c *Client) ListIPv6VirtualIPs(ctx context.Context, vdom string, opts ...ListOption) ([]IPv6VirtualIP, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiIPv6VirtualIP](ctx, c, "/api/v2/cmdb/firewall/vip6",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	vips := make([]IPv6VirtualIP, len(items))
	for i, v := range items {
		vips[i] = IPv6VirtualIP{
			Name:        v.Name,
			ExtIP:       v.ExtIP,
			MappedIP:    vipMappedIP(v.MappedIP),
			ExtIntf:     v.ExtIntf,
			PortForward: isEnabled(v.PortForward),
			ExtPort:     v.ExtPort,
			MappedPort:  v.MappedPort,
			Protocol:    v.Protocol,
			Comment:     v.Comment,
			Color:       v.Color,
		}
	}

	return vips, nil
}

// ListVirtualIPGroups retrieves virtual IP groups from a VDOM.
func (c *Client) ListVirtualIPGroups(ctx context.Context, vdom string, opts ...ListOption) ([]VirtualIPGroup, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiVirtualIPGroup](ctx, c, "/api/v2/cmdb/firewall/vipgrp",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	groups := make([]VirtualIPGroup, len(items))
	for i, g := range items {
		groups[i] = VirtualIPGroup{
			Name:    g.Name,
			Members: namesOf(g.Member),
			Comment: g.Comment,
			Color:   g.Color,
		}
	}

	return groups, nil
}

// ListIPv6VirtualIPGroups retrieves IPv6 virtual IP groups from a VDOM.
func (c *Client) ListIPv6VirtualIPGroups(ctx context.Context, vdom string, opts ...ListOption) ([]IPv6VirtualIPGroup, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiVirtualIPGroup](ctx, c, "/api/v2/cmdb/firewall/vipgrp6",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	groups := make([]IPv6VirtualIPGroup, len(items))
	for i, g := range items {
		groups[i] = IPv6VirtualIPGroup{
			Name:    g.Name,
			Members: namesOf(g.Member),
			Comment: g.Comment,
			Color:   g.Color,
		}
	}

	return groups, nil
}
