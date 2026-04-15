package fortigate

import "context"

type apiStaticRoute struct {
	SeqNum   int    `json:"seq-num"`
	Dst      string `json:"dst"`
	Gateway  string `json:"gateway"`
	Device   string `json:"device"`
	Distance int    `json:"distance"`
	Priority int    `json:"priority"`
	Comment  string `json:"comment"`
	Status   string `json:"status"`
}

// ListStaticRoutes retrieves static routes from a VDOM.
//
// Pagination is handled transparently.
func (c *Client) ListStaticRoutes(ctx context.Context, vdom string, opts ...ListOption) ([]StaticRoute, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiStaticRoute](ctx, c, "/api/v2/cmdb/router/static",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	routes := make([]StaticRoute, len(items))
	for i, r := range items {
		routes[i] = StaticRoute{
			SeqNum:   r.SeqNum,
			Dst:      spaceSubnetToCIDR(r.Dst),
			Gateway:  r.Gateway,
			Device:   r.Device,
			Distance: r.Distance,
			Priority: r.Priority,
			Comment:  r.Comment,
			Status:   r.Status,
		}
	}

	return routes, nil
}
