package fortigate

import (
	"context"
)

type apiSystemGlobal struct {
	Hostname   string `json:"hostname"`
	Timezone   string `json:"timezone"` // FortiGate returns timezone as a string index e.g. "53"
	AdminSport int    `json:"admin-sport"`
	AdminPort  int    `json:"admin-port"`
}

// GetSystemInfo retrieves top-level system configuration from the device.
func (c *Client) GetSystemInfo(ctx context.Context) (SystemInfo, error) {
	if !c.LoggedIn() {
		return SystemInfo{}, ErrNotLoggedIn
	}

	item, err := getOne[apiSystemGlobal](ctx, c, "/api/v2/cmdb/system/global", nil)
	if err != nil {
		return SystemInfo{}, err
	}

	return SystemInfo(item), nil
}
