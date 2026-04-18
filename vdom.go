package fortigate

import (
	"context"
)

type apiVDOM struct {
	Name   string `json:"name"`
	OpMode string `json:"opmode"`
}

// ListVDOMs retrieves all virtual domains from the device.
//
// Requires the client to be connected to the global admin context (not a per-VDOM context).
// Pagination is handled transparently.
func (c *Client) ListVDOMs(ctx context.Context, opts ...ListOption) ([]VDOM, error) {
	if !c.LoggedIn() {
		return nil, ErrNotLoggedIn
	}

	items, err := getPaged[apiVDOM](ctx, c, "/api/v2/cmdb/system/vdom",
		nil, buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	vdoms := make([]VDOM, len(items))
	for i, v := range items {
		vdoms[i] = VDOM(v)
	}

	return vdoms, nil
}
