package fortigate

import "context"

type apiLocalUser struct {
	Name                    string `json:"name"`
	ID                      int    `json:"id"`
	Status                  string `json:"status"`
	Type                    string `json:"type"`
	LDAPServer              string `json:"ldap-server"`
	RadiusServer            string `json:"radius-server"`
	TACACSServer            string `json:"tacacs+-server"`
	TwoFactor               string `json:"two-factor"`
	TwoFactorAuthentication string `json:"two-factor-authentication"`
	TwoFactorNotification   string `json:"two-factor-notification"`
	FortiToken              string `json:"fortitoken"`
	EmailTo                 string `json:"email-to"`
	SMSPhone                string `json:"sms-phone"`
	PasswordPolicy          string `json:"passwd-policy"`
	PasswordTime            string `json:"passwd-time"`
	AuthTimeout             int    `json:"authtimeout"`
	UsernameSensitivity     string `json:"username-sensitivity"`
}

type apiUserGroup struct {
	Name              string      `json:"name"`
	ID                int         `json:"id"`
	Type              string      `json:"group-type"`
	Members           []namedItem `json:"member"`
	AuthTimeout       int         `json:"authtimeout"`
	ConcurrentMode    string      `json:"auth-concurrent-override"`
	ConcurrentValue   int         `json:"auth-concurrent-value"`
	SSOAttributeValue string      `json:"sso-attribute-value"`
	ExpireType        string      `json:"expire-type"`
	Expire            int         `json:"expire"`
}

type apiRemoteAuthServer struct {
	Name                  string `json:"name"`
	Server                string `json:"server"`
	SecondaryServer       string `json:"secondary-server"`
	TertiaryServer        string `json:"tertiary-server"`
	Timeout               int    `json:"timeout"`
	AuthType              string `json:"auth-type"`
	SourceIP              string `json:"source-ip"`
	InterfaceSelectMethod string `json:"interface-select-method"`
	Interface             string `json:"interface"`
}

// ListLocalUsers retrieves local user accounts from a VDOM.
func (c *Client) ListLocalUsers(ctx context.Context, vdom string, opts ...ListOption) ([]LocalUser, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiLocalUser](ctx, c, "/api/v2/cmdb/user/local",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}
	out := make([]LocalUser, len(items))
	for i, item := range items {
		out[i] = LocalUser(item)
	}
	return out, nil
}

// ListUserGroups retrieves user groups from a VDOM.
func (c *Client) ListUserGroups(ctx context.Context, vdom string, opts ...ListOption) ([]UserGroup, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiUserGroup](ctx, c, "/api/v2/cmdb/user/group",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}
	out := make([]UserGroup, len(items))
	for i, item := range items {
		out[i] = UserGroup{
			Name:              item.Name,
			ID:                item.ID,
			Type:              item.Type,
			Members:           namesOf(item.Members),
			AuthTimeout:       item.AuthTimeout,
			ConcurrentMode:    item.ConcurrentMode,
			ConcurrentValue:   item.ConcurrentValue,
			SSOAttributeValue: item.SSOAttributeValue,
			ExpireType:        item.ExpireType,
			Expire:            item.Expire,
		}
	}
	return out, nil
}

// ListLDAPServers retrieves LDAP authentication servers from a VDOM.
func (c *Client) ListLDAPServers(ctx context.Context, vdom string, opts ...ListOption) ([]RemoteAuthServer, error) {
	return c.listRemoteAuthServers(ctx, vdom, "ldap", "/api/v2/cmdb/user/ldap", opts...)
}

// ListRadiusServers retrieves RADIUS authentication servers from a VDOM.
func (c *Client) ListRadiusServers(ctx context.Context, vdom string, opts ...ListOption) ([]RemoteAuthServer, error) {
	return c.listRemoteAuthServers(ctx, vdom, "radius", "/api/v2/cmdb/user/radius", opts...)
}

// ListTACACSServers retrieves TACACS+ authentication servers from a VDOM.
func (c *Client) ListTACACSServers(ctx context.Context, vdom string, opts ...ListOption) ([]RemoteAuthServer, error) {
	return c.listRemoteAuthServers(ctx, vdom, "tacacs+", "/api/v2/cmdb/user/tacacs+", opts...)
}

func (c *Client) listRemoteAuthServers(ctx context.Context, vdom, serverType, path string, opts ...ListOption) ([]RemoteAuthServer, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiRemoteAuthServer](ctx, c, path, vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}
	out := make([]RemoteAuthServer, len(items))
	for i, item := range items {
		out[i] = RemoteAuthServer{
			Name:                  item.Name,
			Type:                  serverType,
			Server:                item.Server,
			SecondaryServer:       item.SecondaryServer,
			TertiaryServer:        item.TertiaryServer,
			Timeout:               item.Timeout,
			AuthType:              item.AuthType,
			SourceIP:              item.SourceIP,
			InterfaceSelectMethod: item.InterfaceSelectMethod,
			Interface:             item.Interface,
		}
	}
	return out, nil
}
