package fortigate

import "context"

type apiService struct {
	Name         string `json:"name"`
	Protocol     string `json:"protocol"`
	TCPPortRange string `json:"tcp-portrange"`
	UDPPortRange string `json:"udp-portrange"`
	Comment      string `json:"comment"`
	Color        int    `json:"color"`
}

type apiServiceGroup struct {
	Name    string      `json:"name"`
	Member  []namedItem `json:"member"`
	Comment string      `json:"comment"`
	Color   int         `json:"color"`
}

// ListServices retrieves custom firewall service objects from a VDOM.
//
// Pagination is handled transparently.
func (c *Client) ListServices(ctx context.Context, vdom string, opts ...ListOption) ([]Service, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiService](ctx, c, "/api/v2/cmdb/firewall.service/custom",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	services := make([]Service, len(items))
	for i, s := range items {
		services[i] = Service{
			Name:         s.Name,
			Protocol:     s.Protocol,
			TCPPortRange: s.TCPPortRange,
			UDPPortRange: s.UDPPortRange,
			Comment:      s.Comment,
			Color:        s.Color,
		}
	}

	return services, nil
}

// ListServiceGroups retrieves firewall service groups from a VDOM.
//
// Pagination is handled transparently.
func (c *Client) ListServiceGroups(ctx context.Context, vdom string, opts ...ListOption) ([]ServiceGroup, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiServiceGroup](ctx, c, "/api/v2/cmdb/firewall.service/group",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	groups := make([]ServiceGroup, len(items))
	for i, g := range items {
		groups[i] = ServiceGroup{
			Name:    g.Name,
			Members: namesOf(g.Member),
			Comment: g.Comment,
			Color:   g.Color,
		}
	}

	return groups, nil
}
