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

type apiServiceCategory struct {
	Name    string `json:"name"`
	Comment string `json:"comment"`
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
		services[i] = Service(s)
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

// ListServiceCategories retrieves firewall service categories from a VDOM.
func (c *Client) ListServiceCategories(ctx context.Context, vdom string, opts ...ListOption) ([]ServiceCategory, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiServiceCategory](ctx, c, "/api/v2/cmdb/firewall.service/category",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	categories := make([]ServiceCategory, len(items))
	for i, cat := range items {
		categories[i] = ServiceCategory(cat)
	}

	return categories, nil
}
