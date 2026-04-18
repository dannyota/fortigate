package fortigate

import "context"

type apiSystemStatus struct {
	ModelName     string `json:"model_name"`
	ModelNumber   string `json:"model_number"`
	Model         string `json:"model"`
	Hostname      string `json:"hostname"`
	LogDiskStatus string `json:"log_disk_status"`
}

type apiMonitorPolicyStats struct {
	PolicyID         int   `json:"policyid"`
	ActiveSessions   int   `json:"active_sessions"`
	Bytes            int64 `json:"bytes"`
	Packets          int64 `json:"packets"`
	SoftwareBytes    int64 `json:"software_bytes"`
	SoftwarePackets  int64 `json:"software_packets"`
	ASICBytes        int64 `json:"asic_bytes"`
	ASICPackets      int64 `json:"asic_packets"`
	HitCount         int64 `json:"hit_count"`
	SessionCount     int   `json:"session_count"`
	LastUsed         int64 `json:"last_used"`
	FirstUsed        int64 `json:"first_used"`
	SessionLastUsed  int64 `json:"session_last_used"`
	SessionFirstUsed int64 `json:"session_first_used"`
}

type apiMonitorRoute struct {
	IPVersion    int    `json:"ip_version"`
	Type         string `json:"type"`
	IPMask       string `json:"ip_mask"`
	Distance     int    `json:"distance"`
	Metric       int    `json:"metric"`
	Priority     int    `json:"priority"`
	VRF          int    `json:"vrf"`
	Gateway      string `json:"gateway"`
	NonRCGateway string `json:"non_rc_gateway"`
	Interface    string `json:"interface"`
}

type apiMonitorIPsecTunnel struct {
	Name            string `json:"name"`
	Comments        string `json:"comments"`
	WizardType      string `json:"wizard-type"`
	ConnectionCount int    `json:"connection_count"`
	CreationTime    int64  `json:"creation_time"`
	Username        string `json:"username"`
	Type            string `json:"type"`
	IncomingBytes   int64  `json:"incoming_bytes"`
	OutgoingBytes   int64  `json:"outgoing_bytes"`
	RemoteGateway   string `json:"rgwy"`
	TunnelID        string `json:"tun_id"`
	TunnelID6       string `json:"tun_id6"`
}

type apiMonitorSSLTunnel struct {
	Name          string `json:"name"`
	Username      string `json:"username"`
	RemoteAddress string `json:"remote_addr"`
	IncomingBytes int64  `json:"incoming_bytes"`
	OutgoingBytes int64  `json:"outgoing_bytes"`
}

// GetSystemStatus retrieves monitor system status.
func (c *Client) GetSystemStatus(ctx context.Context, vdom string) (SystemStatus, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return SystemStatus{}, err
	}
	item, err := getOne[apiSystemStatus](ctx, c, "/api/v2/monitor/system/status", vdomParams(vdom))
	if err != nil {
		return SystemStatus{}, err
	}
	return SystemStatus(item), nil
}

// ListMonitorPolicyStats retrieves runtime firewall policy counters.
func (c *Client) ListMonitorPolicyStats(ctx context.Context, vdom string, opts ...ListOption) ([]MonitorPolicyStats, error) {
	items, err := getVDOMPaged[apiMonitorPolicyStats](ctx, c, vdom, "/api/v2/monitor/firewall/policy", opts)
	if err != nil {
		return nil, err
	}
	out := make([]MonitorPolicyStats, len(items))
	for i, item := range items {
		out[i] = MonitorPolicyStats(item)
	}
	return out, nil
}

// ListMonitorRoutes retrieves runtime IPv4 routing table entries.
func (c *Client) ListMonitorRoutes(ctx context.Context, vdom string, opts ...ListOption) ([]MonitorRoute, error) {
	items, err := getVDOMPaged[apiMonitorRoute](ctx, c, vdom, "/api/v2/monitor/router/ipv4", opts)
	if err != nil {
		return nil, err
	}
	out := make([]MonitorRoute, len(items))
	for i, item := range items {
		out[i] = MonitorRoute(item)
	}
	return out, nil
}

// ListMonitorIPsecTunnels retrieves runtime IPsec tunnel counters.
// noinspection DuplicatedCode
func (c *Client) ListMonitorIPsecTunnels(ctx context.Context, vdom string, opts ...ListOption) ([]MonitorIPsecTunnel, error) {
	items, err := getVDOMPaged[apiMonitorIPsecTunnel](ctx, c, vdom, "/api/v2/monitor/vpn/ipsec", opts)
	if err != nil {
		return nil, err
	}
	out := make([]MonitorIPsecTunnel, len(items))
	for i, item := range items {
		out[i] = MonitorIPsecTunnel{
			Name:            item.Name,
			Comment:         item.Comments,
			WizardType:      item.WizardType,
			ConnectionCount: item.ConnectionCount,
			CreationTime:    item.CreationTime,
			Username:        item.Username,
			Type:            item.Type,
			IncomingBytes:   item.IncomingBytes,
			OutgoingBytes:   item.OutgoingBytes,
			RemoteGateway:   item.RemoteGateway,
			TunnelID:        item.TunnelID,
			TunnelID6:       item.TunnelID6,
		}
	}
	return out, nil
}

// ListMonitorSSLTunnels retrieves runtime SSL VPN sessions.
func (c *Client) ListMonitorSSLTunnels(ctx context.Context, vdom string, opts ...ListOption) ([]MonitorSSLTunnel, error) {
	items, err := getVDOMPaged[apiMonitorSSLTunnel](ctx, c, vdom, "/api/v2/monitor/vpn/ssl", opts)
	if err != nil {
		return nil, err
	}
	out := make([]MonitorSSLTunnel, len(items))
	for i, item := range items {
		out[i] = MonitorSSLTunnel(item)
	}
	return out, nil
}
