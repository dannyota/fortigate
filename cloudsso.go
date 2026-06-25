package fortigate

import (
	"context"
)

// apiSSOAdmin mirrors an entry of /api/v2/cmdb/system/sso-admin — a FortiCloud
// SSO administrator account. The presence of any entry means FortiCloud SSO
// admin login is configured on the device.
type apiSSOAdmin struct {
	Name       string      `json:"name"`
	Accprofile string      `json:"accprofile"`
	Vdom       []namedItem `json:"vdom"`
}

// ListSSOAdmins retrieves the FortiCloud SSO administrator accounts. These are
// global (not VDOM-scoped); an empty result means no SSO admin is configured.
func (c *Client) ListSSOAdmins(ctx context.Context) ([]SSOAdmin, error) {
	if !c.LoggedIn() {
		return nil, ErrNotLoggedIn
	}
	items, err := get[apiSSOAdmin](ctx, c, "/api/v2/cmdb/system/sso-admin", nil)
	if err != nil {
		return nil, err
	}
	out := make([]SSOAdmin, len(items))
	for i, item := range items {
		out[i] = SSOAdmin{
			Name:       item.Name,
			Accprofile: item.Accprofile,
			Vdoms:      namesOf(item.Vdom),
		}
	}
	return out, nil
}

// apiCentralManagement mirrors /api/v2/cmdb/system/central-management.
type apiCentralManagement struct {
	Mode                   string      `json:"mode"`
	Type                   string      `json:"type"`
	IncludeDefaultServers  string      `json:"include-default-servers"`
	FmgSourceIP            string      `json:"fmg-source-ip"`
	CloudSSODefaultProfile string      `json:"fortigate-cloud-sso-default-profile"`
	ServerList             []namedItem `json:"server-list"`
}

// GetCentralManagement retrieves the device's central-management configuration.
// Type "fortiguard" together with a cloud SSO default profile indicates
// FortiCloud-managed SSO is in play.
func (c *Client) GetCentralManagement(ctx context.Context) (CentralManagement, error) {
	if !c.LoggedIn() {
		return CentralManagement{}, ErrNotLoggedIn
	}
	item, err := getOne[apiCentralManagement](ctx, c, "/api/v2/cmdb/system/central-management", nil)
	if err != nil {
		return CentralManagement{}, err
	}
	return CentralManagement{
		Mode:                   item.Mode,
		Type:                   item.Type,
		IncludeDefaultServers:  item.IncludeDefaultServers,
		FmgSourceIP:            item.FmgSourceIP,
		CloudSSODefaultProfile: item.CloudSSODefaultProfile,
		ServerList:             namesOf(item.ServerList),
	}, nil
}

// apiFortiGuard mirrors the SSO-relevant fields of /api/v2/cmdb/system/fortiguard.
type apiFortiGuard struct {
	AutoJoinForticloud string `json:"auto-join-forticloud"`
	ServiceAccountID   string `json:"service-account-id"`
}

// GetFortiGuard retrieves the device's FortiGuard/FortiCloud linkage settings.
// AutoJoinForticloud "enable" means the device auto-registers with FortiCloud.
func (c *Client) GetFortiGuard(ctx context.Context) (FortiGuard, error) {
	if !c.LoggedIn() {
		return FortiGuard{}, ErrNotLoggedIn
	}
	item, err := getOne[apiFortiGuard](ctx, c, "/api/v2/cmdb/system/fortiguard", nil)
	if err != nil {
		return FortiGuard{}, err
	}
	return FortiGuard{
		AutoJoinForticloud: item.AutoJoinForticloud,
		ServiceAccountID:   item.ServiceAccountID,
	}, nil
}
