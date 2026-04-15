package fortigate

import "context"

type apiPolicy struct {
	PolicyID   int         `json:"policyid"`
	Name       string      `json:"name"`
	SrcIntf    []namedItem `json:"srcintf"`
	DstIntf    []namedItem `json:"dstintf"`
	SrcAddr    []namedItem `json:"srcaddr"`
	DstAddr    []namedItem `json:"dstaddr"`
	Service    []namedItem `json:"service"`
	Action     string      `json:"action"`
	Status     string      `json:"status"`
	LogTraffic string      `json:"logtraffic"`
	NAT        string      `json:"nat"`
	Schedule   string      `json:"schedule"`
	Comments   string      `json:"comments"`
}

// ListPolicies retrieves firewall policies from a VDOM.
//
// Pagination is handled transparently.
func (c *Client) ListPolicies(ctx context.Context, vdom string, opts ...ListOption) ([]Policy, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiPolicy](ctx, c, "/api/v2/cmdb/firewall/policy",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	policies := make([]Policy, len(items))
	for i, p := range items {
		policies[i] = Policy{
			ID:         p.PolicyID,
			Name:       p.Name,
			SrcIntfs:   namesOf(p.SrcIntf),
			DstIntfs:   namesOf(p.DstIntf),
			SrcAddrs:   namesOf(p.SrcAddr),
			DstAddrs:   namesOf(p.DstAddr),
			Services:   namesOf(p.Service),
			Action:     p.Action,
			Status:     p.Status,
			LogTraffic: p.LogTraffic,
			NATEnabled: isEnabled(p.NAT),
			Schedule:   p.Schedule,
			Comment:    p.Comments,
		}
	}

	return policies, nil
}
