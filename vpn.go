package fortigate

import "context"

type apiIPsecPhase1 struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Interface     string `json:"interface"`
	IPVersion     string `json:"ip-version"`
	IKEVersion    string `json:"ike-version"`
	LocalGateway  string `json:"local-gw"`
	RemoteGateway string `json:"remote-gw"`
	RemoteGWDDNS  string `json:"remotegw-ddns"`
	AuthMethod    string `json:"authmethod"`
	Mode          string `json:"mode"`
	PeerType      string `json:"peertype"`
	Proposal      string `json:"proposal"`
	DHGroups      string `json:"dhgrp"`
	AddRoute      string `json:"add-route"`
	AutoNegotiate string `json:"auto-negotiate"`
	DPD           string `json:"dpd"`
	NATTraversal  string `json:"nattraversal"`
	NetDevice     string `json:"net-device"`
	Distance      int    `json:"distance"`
	Priority      int    `json:"priority"`
	KeyLife       int    `json:"keylife"`
	Comments      string `json:"comments"`
	WizardType    string `json:"wizard-type"`
}

type apiIPsecPhase2 struct {
	Name           string `json:"name"`
	Phase1Name     string `json:"phase1name"`
	Proposal       string `json:"proposal"`
	PFS            string `json:"pfs"`
	DHGroups       string `json:"dhgrp"`
	Replay         string `json:"replay"`
	AutoNegotiate  string `json:"auto-negotiate"`
	AddRoute       string `json:"add-route"`
	KeyLifeSeconds int    `json:"keylifeseconds"`
	KeyLifeKB      int    `json:"keylifekbs"`
	KeyLifeType    string `json:"keylife-type"`
	Protocol       int    `json:"protocol"`
	SrcName        string `json:"src-name"`
	SrcSubnet      string `json:"src-subnet"`
	SrcPort        int    `json:"src-port"`
	DstName        string `json:"dst-name"`
	DstSubnet      string `json:"dst-subnet"`
	DstPort        int    `json:"dst-port"`
	Comments       string `json:"comments"`
}

type apiSSLVPNPortal struct {
	Name            string      `json:"name"`
	TunnelMode      string      `json:"tunnel-mode"`
	WebMode         string      `json:"web-mode"`
	IPMode          string      `json:"ip-mode"`
	AutoConnect     string      `json:"auto-connect"`
	KeepAlive       string      `json:"keep-alive"`
	SavePassword    string      `json:"save-password"`
	IPPools         []namedItem `json:"ip-pools"`
	IPv6Pools       []namedItem `json:"ipv6-pools"`
	SplitTunneling  string      `json:"split-tunneling"`
	DNSServer1      string      `json:"dns-server1"`
	DNSServer2      string      `json:"dns-server2"`
	DNSSuffix       string      `json:"dns-suffix"`
	AllowUserAccess string      `json:"allow-user-access"`
	Theme           string      `json:"theme"`
	Heading         string      `json:"heading"`
	LimitUserLogins string      `json:"limit-user-logins"`
	UseSDWAN        string      `json:"use-sdwan"`
	PreferIPv6DNS   string      `json:"prefer-ipv6-dns"`
}

type apiSSLVPNSettings struct {
	Status                 string      `json:"status"`
	RequireClientCert      string      `json:"reqclientcert"`
	SSLMinProtoVersion     string      `json:"ssl-min-proto-ver"`
	SSLMaxProtoVersion     string      `json:"ssl-max-proto-ver"`
	ServerCert             string      `json:"servercert"`
	Algorithm              string      `json:"algorithm"`
	IdleTimeout            int         `json:"idle-timeout"`
	AuthTimeout            int         `json:"auth-timeout"`
	LoginAttemptLimit      int         `json:"login-attempt-limit"`
	LoginBlockTime         int         `json:"login-block-time"`
	Port                   int         `json:"port"`
	TunnelIPPools          []namedItem `json:"tunnel-ip-pools"`
	TunnelIPv6Pools        []namedItem `json:"tunnel-ipv6-pools"`
	SourceInterfaces       []namedItem `json:"source-interface"`
	SourceAddresses        []namedItem `json:"source-address"`
	SourceAddressNegate    string      `json:"source-address-negate"`
	DefaultPortal          string      `json:"default-portal"`
	DTLSTunnel             string      `json:"dtls-tunnel"`
	CheckReferer           string      `json:"check-referer"`
	DualStackMode          string      `json:"dual-stack-mode"`
	TunnelAddrAssignMethod string      `json:"tunnel-addr-assigned-method"`
	ServerHostname         string      `json:"server-hostname"`
}

// ListIPsecPhase1s retrieves IPsec phase 1 interface entries from a VDOM.
func (c *Client) ListIPsecPhase1s(ctx context.Context, vdom string, opts ...ListOption) ([]IPsecPhase1, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiIPsecPhase1](ctx, c, "/api/v2/cmdb/vpn.ipsec/phase1-interface",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}
	out := make([]IPsecPhase1, len(items))
	for i, item := range items {
		out[i] = IPsecPhase1{
			Name:          item.Name,
			Type:          item.Type,
			Interface:     item.Interface,
			IPVersion:     item.IPVersion,
			IKEVersion:    item.IKEVersion,
			LocalGateway:  item.LocalGateway,
			RemoteGateway: item.RemoteGateway,
			RemoteGWDDNS:  item.RemoteGWDDNS,
			AuthMethod:    item.AuthMethod,
			Mode:          item.Mode,
			PeerType:      item.PeerType,
			Proposal:      item.Proposal,
			DHGroups:      item.DHGroups,
			AddRoute:      item.AddRoute,
			AutoNegotiate: item.AutoNegotiate,
			DPD:           item.DPD,
			NATTraversal:  item.NATTraversal,
			NetDevice:     item.NetDevice,
			Distance:      item.Distance,
			Priority:      item.Priority,
			KeyLife:       item.KeyLife,
			Comment:       item.Comments,
			WizardType:    item.WizardType,
		}
	}
	return out, nil
}

// ListIPsecPhase2s retrieves IPsec phase 2 interface entries from a VDOM.
func (c *Client) ListIPsecPhase2s(ctx context.Context, vdom string, opts ...ListOption) ([]IPsecPhase2, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiIPsecPhase2](ctx, c, "/api/v2/cmdb/vpn.ipsec/phase2-interface",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}
	out := make([]IPsecPhase2, len(items))
	for i, item := range items {
		out[i] = IPsecPhase2{
			Name:           item.Name,
			Phase1Name:     item.Phase1Name,
			Proposal:       item.Proposal,
			PFS:            item.PFS,
			DHGroups:       item.DHGroups,
			Replay:         item.Replay,
			AutoNegotiate:  item.AutoNegotiate,
			AddRoute:       item.AddRoute,
			KeyLifeSeconds: item.KeyLifeSeconds,
			KeyLifeKB:      item.KeyLifeKB,
			KeyLifeType:    item.KeyLifeType,
			Protocol:       item.Protocol,
			SrcName:        item.SrcName,
			SrcSubnet:      spaceSubnetToCIDR(item.SrcSubnet),
			SrcPort:        item.SrcPort,
			DstName:        item.DstName,
			DstSubnet:      spaceSubnetToCIDR(item.DstSubnet),
			DstPort:        item.DstPort,
			Comment:        item.Comments,
		}
	}
	return out, nil
}

// ListSSLVPNPortals retrieves SSL VPN portal entries from a VDOM.
func (c *Client) ListSSLVPNPortals(ctx context.Context, vdom string, opts ...ListOption) ([]SSLVPNPortal, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiSSLVPNPortal](ctx, c, "/api/v2/cmdb/vpn.ssl.web/portal",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}
	out := make([]SSLVPNPortal, len(items))
	for i, item := range items {
		out[i] = SSLVPNPortal{
			Name:            item.Name,
			TunnelMode:      item.TunnelMode,
			WebMode:         item.WebMode,
			IPMode:          item.IPMode,
			AutoConnect:     item.AutoConnect,
			KeepAlive:       item.KeepAlive,
			SavePassword:    item.SavePassword,
			IPPools:         namesOf(item.IPPools),
			IPv6Pools:       namesOf(item.IPv6Pools),
			SplitTunneling:  item.SplitTunneling,
			DNSServer1:      item.DNSServer1,
			DNSServer2:      item.DNSServer2,
			DNSSuffix:       item.DNSSuffix,
			AllowUserAccess: item.AllowUserAccess,
			Theme:           item.Theme,
			Heading:         item.Heading,
			LimitUserLogins: item.LimitUserLogins,
			UseSDWAN:        item.UseSDWAN,
			PreferIPv6DNS:   item.PreferIPv6DNS,
		}
	}
	return out, nil
}

// GetSSLVPNSettings retrieves top-level SSL VPN settings from a VDOM.
func (c *Client) GetSSLVPNSettings(ctx context.Context, vdom string) (SSLVPNSettings, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return SSLVPNSettings{}, err
	}
	item, err := getOne[apiSSLVPNSettings](ctx, c, "/api/v2/cmdb/vpn.ssl/settings", vdomParams(vdom))
	if err != nil {
		return SSLVPNSettings{}, err
	}
	return SSLVPNSettings{
		Status:                 item.Status,
		RequireClientCert:      item.RequireClientCert,
		SSLMinProtoVersion:     item.SSLMinProtoVersion,
		SSLMaxProtoVersion:     item.SSLMaxProtoVersion,
		ServerCert:             item.ServerCert,
		Algorithm:              item.Algorithm,
		IdleTimeout:            item.IdleTimeout,
		AuthTimeout:            item.AuthTimeout,
		LoginAttemptLimit:      item.LoginAttemptLimit,
		LoginBlockTime:         item.LoginBlockTime,
		Port:                   item.Port,
		TunnelIPPools:          namesOf(item.TunnelIPPools),
		TunnelIPv6Pools:        namesOf(item.TunnelIPv6Pools),
		SourceInterfaces:       namesOf(item.SourceInterfaces),
		SourceAddresses:        namesOf(item.SourceAddresses),
		SourceAddressNegate:    item.SourceAddressNegate,
		DefaultPortal:          item.DefaultPortal,
		DTLSTunnel:             item.DTLSTunnel,
		CheckReferer:           item.CheckReferer,
		DualStackMode:          item.DualStackMode,
		TunnelAddrAssignMethod: item.TunnelAddrAssignMethod,
		ServerHostname:         item.ServerHostname,
	}, nil
}
