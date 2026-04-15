package fortigate

import (
	"context"
	"strings"
)

type apiInterface struct {
	Name        string `json:"name"`
	IP          string `json:"ip"`
	Type        string `json:"type"`
	Alias       string `json:"alias"`
	Role        string `json:"role"`
	Status      string `json:"status"`
	VLANID      int    `json:"vlanid"`
	Mode        string `json:"mode"`
	Interface   string `json:"interface"` // parent interface for VLANs and tunnels
	AllowAccess string `json:"allowaccess"`
	MTU         int    `json:"mtu"`
	Speed       string `json:"speed"`
	Description string `json:"description"`
}

// ListInterfaces retrieves network interfaces from a VDOM.
//
// Pagination is handled transparently.
func (c *Client) ListInterfaces(ctx context.Context, vdom string, opts ...ListOption) ([]Interface, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiInterface](ctx, c, "/api/v2/cmdb/system/interface",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	ifaces := make([]Interface, len(items))
	for i, iface := range items {
		ifaces[i] = Interface{
			Name:        iface.Name,
			IP:          zeroIPToEmpty(spaceSubnetToCIDR(iface.IP)),
			Type:        iface.Type,
			Alias:       iface.Alias,
			Role:        iface.Role,
			Status:      iface.Status,
			VLANID:      iface.VLANID,
			Mode:        iface.Mode,
			ParentIntf:  iface.Interface,
			AllowAccess: splitAllowAccess(iface.AllowAccess),
			MTU:         iface.MTU,
			Speed:       iface.Speed,
			Description: iface.Description,
		}
	}

	return ifaces, nil
}

// splitAllowAccess parses a space-separated allowaccess string
// (e.g. "ping https ssh http fgfm") into a slice. Empty input → nil.
func splitAllowAccess(s string) []string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return nil
	}
	return fields
}
