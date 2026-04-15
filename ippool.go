package fortigate

import "context"

type apiIPPool struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	StartIP       string `json:"startip"`
	EndIP         string `json:"endip"`
	SourceStartIP string `json:"source-startip"`
	SourceEndIP   string `json:"source-endip"`
	Comment       string `json:"comments"`
	Color         int    `json:"color"`
}

// ListIPPools retrieves IP pool objects (SNAT) from a VDOM.
//
// Pagination is handled transparently.
func (c *Client) ListIPPools(ctx context.Context, vdom string, opts ...ListOption) ([]IPPool, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiIPPool](ctx, c, "/api/v2/cmdb/firewall/ippool",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	pools := make([]IPPool, len(items))
	for i, p := range items {
		pools[i] = IPPool{
			Name:          p.Name,
			Type:          p.Type,
			StartIP:       p.StartIP,
			EndIP:         p.EndIP,
			SourceStartIP: p.SourceStartIP,
			SourceEndIP:   p.SourceEndIP,
			Comment:       p.Comment,
			Color:         p.Color,
		}
	}

	return pools, nil
}
