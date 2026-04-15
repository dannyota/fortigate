package fortigate

import "context"

type apiAddress struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Subnet    string `json:"subnet"`
	StartIP   string `json:"start-ip"`
	EndIP     string `json:"end-ip"`
	FQDN      string `json:"fqdn"`
	Country   string `json:"country"`
	Wildcard  string `json:"wildcard"`
	Comment   string `json:"comment"`
	Color     int    `json:"color"`
	AssocIntf string `json:"associated-interface"`
}

type apiAddressGroup struct {
	Name    string      `json:"name"`
	Member  []namedItem `json:"member"`
	Comment string      `json:"comment"`
	Color   int         `json:"color"`
}

// ListAddresses retrieves firewall address objects from a VDOM.
//
// Pagination is handled transparently; use WithPageSize and WithPageCallback
// to control page size and observe progress.
func (c *Client) ListAddresses(ctx context.Context, vdom string, opts ...ListOption) ([]Address, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiAddress](ctx, c, "/api/v2/cmdb/firewall/address",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	addresses := make([]Address, len(items))
	for i, a := range items {
		addresses[i] = Address{
			Name:      a.Name,
			Type:      a.Type,
			Subnet:    spaceSubnetToCIDR(a.Subnet),
			StartIP:   a.StartIP,
			EndIP:     a.EndIP,
			FQDN:      a.FQDN,
			Country:   a.Country,
			Wildcard:  spaceSubnetToCIDR(a.Wildcard),
			Comment:   a.Comment,
			Color:     a.Color,
			AssocIntf: a.AssocIntf,
		}
	}

	return addresses, nil
}

// ListAddressGroups retrieves firewall address groups from a VDOM.
func (c *Client) ListAddressGroups(ctx context.Context, vdom string, opts ...ListOption) ([]AddressGroup, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiAddressGroup](ctx, c, "/api/v2/cmdb/firewall/addrgrp",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	groups := make([]AddressGroup, len(items))
	for i, g := range items {
		groups[i] = AddressGroup{
			Name:    g.Name,
			Members: namesOf(g.Member),
			Comment: g.Comment,
			Color:   g.Color,
		}
	}

	return groups, nil
}
