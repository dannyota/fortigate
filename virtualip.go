package fortigate

import "context"

type apiVIPMappedIP struct {
	Range string `json:"range"`
}

type apiVirtualIP struct {
	Name        string            `json:"name"`
	ExtIP       string            `json:"extip"`
	MappedIP    []apiVIPMappedIP  `json:"mappedip"`
	ExtIntf     string            `json:"extintf"`
	PortForward string            `json:"portforward"`
	ExtPort     string            `json:"extport"`
	MappedPort  string            `json:"mappedport"`
	Protocol    string            `json:"protocol"`
	Comment     string            `json:"comment"`
	Color       int               `json:"color"`
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
