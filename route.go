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

type apiIPv6StaticRoute struct {
	SeqNum   int    `json:"seq-num"`
	Dst      string `json:"dst"`
	Gateway  string `json:"gateway"`
	Device   string `json:"device"`
	Distance int    `json:"distance"`
	Priority int    `json:"priority"`
	Comment  string `json:"comment"`
	Status   string `json:"status"`
}

type apiPolicyRoute struct {
	SeqNum          int         `json:"seq-num"`
	InputDevice     []namedItem `json:"input-device"`
	SrcAddr         []namedItem `json:"srcaddr"`
	DstAddr         []namedItem `json:"dstaddr"`
	Action          string      `json:"action"`
	Protocol        int         `json:"protocol"`
	StartPort       int         `json:"start-port"`
	EndPort         int         `json:"end-port"`
	StartSourcePort int         `json:"start-source-port"`
	EndSourcePort   int         `json:"end-source-port"`
	Gateway         string      `json:"gateway"`
	OutputDevice    string      `json:"output-device"`
	TOS             string      `json:"tos"`
	TOSMask         string      `json:"tos-mask"`
	Status          string      `json:"status"`
	Comments        string      `json:"comments"`
}

type apiNamedRuleList[T any] struct {
	Name     string `json:"name"`
	Comment  string `json:"comment"`
	Comments string `json:"comments"`
	Rules    []T    `json:"rule"`
}

type apiRouteMapRule struct {
	ID           int    `json:"id"`
	Action       string `json:"action"`
	MatchIP      string `json:"match-ip-address"`
	MatchIPv6    string `json:"match-ip6-address"`
	MatchASPath  string `json:"match-as-path"`
	SetCommunity string `json:"set-community"`
	Status       string `json:"status"`
}

type apiAccessListRule struct {
	ID         int    `json:"id"`
	Action     string `json:"action"`
	Prefix     string `json:"prefix"`
	ExactMatch string `json:"exact-match"`
	Status     string `json:"status"`
}

type apiPrefixListRule struct {
	ID     int    `json:"id"`
	Action string `json:"action"`
	Prefix string `json:"prefix"`
	GE     int    `json:"ge"`
	LE     int    `json:"le"`
	Status string `json:"status"`
}

type apiASPathListRule struct {
	ID       int    `json:"id"`
	Action   string `json:"action"`
	Regexp   string `json:"regexp"`
	Status   string `json:"status"`
	Comments string `json:"comments"`
}

type apiCommunityListRule struct {
	ID       int    `json:"id"`
	Action   string `json:"action"`
	Match    string `json:"match"`
	Regexp   string `json:"regexp"`
	Status   string `json:"status"`
	Comments string `json:"comments"`
}

type apiRouteRedistribute struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	RouteMap   string `json:"route-map"`
	Routemap   string `json:"routemap"`
	Metric     int    `json:"metric"`
	MetricType string `json:"metric-type"`
	Tag        int    `json:"tag"`
}

type apiBGPSettings struct {
	AS                  string                 `json:"as"`
	RouterID            string                 `json:"router-id"`
	KeepaliveTimer      int                    `json:"keepalive-timer"`
	HoldtimeTimer       int                    `json:"holdtime-timer"`
	EBGPMultipath       string                 `json:"ebgp-multipath"`
	IBGPMultipath       string                 `json:"ibgp-multipath"`
	LogNeighbourChanges string                 `json:"log-neighbour-changes"`
	NetworkImportCheck  string                 `json:"network-import-check"`
	DistanceExternal    int                    `json:"distance-external"`
	DistanceInternal    int                    `json:"distance-internal"`
	DistanceLocal       int                    `json:"distance-local"`
	GracefulRestart     string                 `json:"graceful-restart"`
	Redistribute        []apiRouteRedistribute `json:"redistribute"`
	Redistribute6       []apiRouteRedistribute `json:"redistribute6"`
}

type apiOSPFSettings struct {
	RouterID                     string                 `json:"router-id"`
	ABRType                      string                 `json:"abr-type"`
	AutoCostReferenceBandwidth   int                    `json:"auto-cost-ref-bandwidth"`
	Distance                     int                    `json:"distance"`
	DistanceExternal             int                    `json:"distance-external"`
	DistanceInterArea            int                    `json:"distance-inter-area"`
	DistanceIntraArea            int                    `json:"distance-intra-area"`
	DefaultInformationOriginate  string                 `json:"default-information-originate"`
	DefaultInformationMetric     int                    `json:"default-information-metric"`
	DefaultInformationMetricType string                 `json:"default-information-metric-type"`
	DefaultMetric                int                    `json:"default-metric"`
	SPFTimers                    string                 `json:"spf-timers"`
	BFD                          string                 `json:"bfd"`
	LogNeighbourChanges          string                 `json:"log-neighbour-changes"`
	Redistribute                 []apiRouteRedistribute `json:"redistribute"`
}

type apiOSPFv6Settings struct {
	RouterID                     string                 `json:"router-id"`
	ABRType                      string                 `json:"abr-type"`
	AutoCostReferenceBandwidth   int                    `json:"auto-cost-ref-bandwidth"`
	DefaultInformationOriginate  string                 `json:"default-information-originate"`
	DefaultInformationMetric     int                    `json:"default-information-metric"`
	DefaultInformationMetricType string                 `json:"default-information-metric-type"`
	DefaultMetric                int                    `json:"default-metric"`
	SPFTimers                    string                 `json:"spf-timers"`
	BFD                          string                 `json:"bfd"`
	LogNeighbourChanges          string                 `json:"log-neighbour-changes"`
	Redistribute                 []apiRouteRedistribute `json:"redistribute"`
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

// ListPolicyRoutes retrieves IPv4 policy routes from a VDOM.
func (c *Client) ListPolicyRoutes(ctx context.Context, vdom string, opts ...ListOption) ([]PolicyRoute, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiPolicyRoute](ctx, c, "/api/v2/cmdb/router/policy",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	routes := make([]PolicyRoute, len(items))
	for i, r := range items {
		routes[i] = policyRouteFromAPI(r)
	}
	return routes, nil
}

// ListIPv6PolicyRoutes retrieves IPv6 policy routes from a VDOM.
func (c *Client) ListIPv6PolicyRoutes(ctx context.Context, vdom string, opts ...ListOption) ([]IPv6PolicyRoute, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiPolicyRoute](ctx, c, "/api/v2/cmdb/router/policy6",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	routes := make([]IPv6PolicyRoute, len(items))
	for i, r := range items {
		p := policyRouteFromAPI(r)
		routes[i] = IPv6PolicyRoute(p)
	}
	return routes, nil
}

// ListRouteMaps retrieves route maps from a VDOM.
func (c *Client) ListRouteMaps(ctx context.Context, vdom string, opts ...ListOption) ([]RouteMap, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiNamedRuleList[apiRouteMapRule]](ctx, c, "/api/v2/cmdb/router/route-map",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	out := make([]RouteMap, len(items))
	for i, item := range items {
		out[i] = RouteMap{Name: item.Name, Comment: coalesce(item.Comment, item.Comments), Rules: routeMapRulesFromAPI(item.Rules)}
	}
	return out, nil
}

// ListAccessLists retrieves IPv4 router access lists from a VDOM.
func (c *Client) ListAccessLists(ctx context.Context, vdom string, opts ...ListOption) ([]AccessList, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiNamedRuleList[apiAccessListRule]](ctx, c, "/api/v2/cmdb/router/access-list",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	out := make([]AccessList, len(items))
	for i, item := range items {
		out[i] = AccessList{Name: item.Name, Comment: coalesce(item.Comment, item.Comments), Rules: accessListRulesFromAPI(item.Rules)}
	}
	return out, nil
}

// ListIPv6AccessLists retrieves IPv6 router access lists from a VDOM.
func (c *Client) ListIPv6AccessLists(ctx context.Context, vdom string, opts ...ListOption) ([]IPv6AccessList, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiNamedRuleList[apiAccessListRule]](ctx, c, "/api/v2/cmdb/router/access-list6",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	out := make([]IPv6AccessList, len(items))
	for i, item := range items {
		out[i] = IPv6AccessList{Name: item.Name, Comment: coalesce(item.Comment, item.Comments), Rules: accessListRulesFromAPI(item.Rules)}
	}
	return out, nil
}

// ListPrefixLists retrieves IPv4 router prefix lists from a VDOM.
func (c *Client) ListPrefixLists(ctx context.Context, vdom string, opts ...ListOption) ([]PrefixList, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiNamedRuleList[apiPrefixListRule]](ctx, c, "/api/v2/cmdb/router/prefix-list",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	out := make([]PrefixList, len(items))
	for i, item := range items {
		out[i] = PrefixList{Name: item.Name, Comment: coalesce(item.Comment, item.Comments), Rules: prefixListRulesFromAPI(item.Rules)}
	}
	return out, nil
}

// ListIPv6PrefixLists retrieves IPv6 router prefix lists from a VDOM.
func (c *Client) ListIPv6PrefixLists(ctx context.Context, vdom string, opts ...ListOption) ([]IPv6PrefixList, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiNamedRuleList[apiPrefixListRule]](ctx, c, "/api/v2/cmdb/router/prefix-list6",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	out := make([]IPv6PrefixList, len(items))
	for i, item := range items {
		out[i] = IPv6PrefixList{Name: item.Name, Comment: coalesce(item.Comment, item.Comments), Rules: prefixListRulesFromAPI(item.Rules)}
	}
	return out, nil
}

// ListASPathLists retrieves BGP AS path lists from a VDOM.
func (c *Client) ListASPathLists(ctx context.Context, vdom string, opts ...ListOption) ([]ASPathList, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiNamedRuleList[apiASPathListRule]](ctx, c, "/api/v2/cmdb/router/aspath-list",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	out := make([]ASPathList, len(items))
	for i, item := range items {
		out[i] = ASPathList{Name: item.Name, Comment: coalesce(item.Comment, item.Comments), Rules: asPathListRulesFromAPI(item.Rules)}
	}
	return out, nil
}

// ListCommunityLists retrieves BGP community lists from a VDOM.
func (c *Client) ListCommunityLists(ctx context.Context, vdom string, opts ...ListOption) ([]CommunityList, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiNamedRuleList[apiCommunityListRule]](ctx, c, "/api/v2/cmdb/router/community-list",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	out := make([]CommunityList, len(items))
	for i, item := range items {
		out[i] = CommunityList{Name: item.Name, Comment: coalesce(item.Comment, item.Comments), Rules: communityListRulesFromAPI(item.Rules)}
	}
	return out, nil
}

// GetBGPSettings retrieves top-level BGP settings from a VDOM.
func (c *Client) GetBGPSettings(ctx context.Context, vdom string) (BGPSettings, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return BGPSettings{}, err
	}
	item, err := getOne[apiBGPSettings](ctx, c, "/api/v2/cmdb/router/bgp", vdomParams(vdom))
	if err != nil {
		return BGPSettings{}, err
	}
	return BGPSettings{
		AS:                  item.AS,
		RouterID:            item.RouterID,
		KeepaliveTimer:      item.KeepaliveTimer,
		HoldtimeTimer:       item.HoldtimeTimer,
		EBGPMultipath:       item.EBGPMultipath,
		IBGPMultipath:       item.IBGPMultipath,
		LogNeighbourChanges: item.LogNeighbourChanges,
		NetworkImportCheck:  item.NetworkImportCheck,
		DistanceExternal:    item.DistanceExternal,
		DistanceInternal:    item.DistanceInternal,
		DistanceLocal:       item.DistanceLocal,
		GracefulRestart:     item.GracefulRestart,
		Redistribute:        routeRedistributeFromAPI(item.Redistribute),
		Redistribute6:       routeRedistributeFromAPI(item.Redistribute6),
	}, nil
}

// GetOSPFSettings retrieves top-level OSPF settings from a VDOM.
func (c *Client) GetOSPFSettings(ctx context.Context, vdom string) (OSPFSettings, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return OSPFSettings{}, err
	}
	item, err := getOne[apiOSPFSettings](ctx, c, "/api/v2/cmdb/router/ospf", vdomParams(vdom))
	if err != nil {
		return OSPFSettings{}, err
	}
	return OSPFSettings{
		RouterID:                     item.RouterID,
		ABRType:                      item.ABRType,
		AutoCostReferenceBandwidth:   item.AutoCostReferenceBandwidth,
		Distance:                     item.Distance,
		DistanceExternal:             item.DistanceExternal,
		DistanceInterArea:            item.DistanceInterArea,
		DistanceIntraArea:            item.DistanceIntraArea,
		DefaultInformationOriginate:  item.DefaultInformationOriginate,
		DefaultInformationMetric:     item.DefaultInformationMetric,
		DefaultInformationMetricType: item.DefaultInformationMetricType,
		DefaultMetric:                item.DefaultMetric,
		SPFTimers:                    item.SPFTimers,
		BFD:                          item.BFD,
		LogNeighbourChanges:          item.LogNeighbourChanges,
		Redistribute:                 routeRedistributeFromAPI(item.Redistribute),
	}, nil
}

// GetOSPFv6Settings retrieves top-level OSPFv3 settings from a VDOM.
func (c *Client) GetOSPFv6Settings(ctx context.Context, vdom string) (OSPFv6Settings, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return OSPFv6Settings{}, err
	}
	item, err := getOne[apiOSPFv6Settings](ctx, c, "/api/v2/cmdb/router/ospf6", vdomParams(vdom))
	if err != nil {
		return OSPFv6Settings{}, err
	}
	return OSPFv6Settings{
		RouterID:                     item.RouterID,
		ABRType:                      item.ABRType,
		AutoCostReferenceBandwidth:   item.AutoCostReferenceBandwidth,
		DefaultInformationOriginate:  item.DefaultInformationOriginate,
		DefaultInformationMetric:     item.DefaultInformationMetric,
		DefaultInformationMetricType: item.DefaultInformationMetricType,
		DefaultMetric:                item.DefaultMetric,
		SPFTimers:                    item.SPFTimers,
		BFD:                          item.BFD,
		LogNeighbourChanges:          item.LogNeighbourChanges,
		Redistribute:                 routeRedistributeFromAPI(item.Redistribute),
	}, nil
}

func policyRouteFromAPI(r apiPolicyRoute) PolicyRoute {
	return PolicyRoute{
		SeqNum:          r.SeqNum,
		InputDevices:    namesOf(r.InputDevice),
		SrcAddrs:        namesOf(r.SrcAddr),
		DstAddrs:        namesOf(r.DstAddr),
		Action:          r.Action,
		Protocol:        r.Protocol,
		StartPort:       r.StartPort,
		EndPort:         r.EndPort,
		StartSourcePort: r.StartSourcePort,
		EndSourcePort:   r.EndSourcePort,
		Gateway:         r.Gateway,
		OutputDevice:    r.OutputDevice,
		TOS:             r.TOS,
		TOSMask:         r.TOSMask,
		Status:          r.Status,
		Comment:         r.Comments,
	}
}

func routeMapRulesFromAPI(items []apiRouteMapRule) []RouteMapRule {
	out := make([]RouteMapRule, len(items))
	for i, item := range items {
		out[i] = RouteMapRule(item)
	}
	return out
}

func accessListRulesFromAPI(items []apiAccessListRule) []AccessListRule {
	out := make([]AccessListRule, len(items))
	for i, item := range items {
		out[i] = AccessListRule(item)
	}
	return out
}

func prefixListRulesFromAPI(items []apiPrefixListRule) []PrefixListRule {
	out := make([]PrefixListRule, len(items))
	for i, item := range items {
		out[i] = PrefixListRule(item)
	}
	return out
}

func asPathListRulesFromAPI(items []apiASPathListRule) []ASPathListRule {
	out := make([]ASPathListRule, len(items))
	for i, item := range items {
		out[i] = ASPathListRule{
			ID:      item.ID,
			Action:  item.Action,
			Regexp:  item.Regexp,
			Status:  item.Status,
			Comment: item.Comments,
		}
	}
	return out
}

func communityListRulesFromAPI(items []apiCommunityListRule) []CommunityListRule {
	out := make([]CommunityListRule, len(items))
	for i, item := range items {
		out[i] = CommunityListRule{
			ID:      item.ID,
			Action:  item.Action,
			Match:   item.Match,
			Regexp:  item.Regexp,
			Status:  item.Status,
			Comment: item.Comments,
		}
	}
	return out
}

func routeRedistributeFromAPI(items []apiRouteRedistribute) []RouteRedistribute {
	out := make([]RouteRedistribute, len(items))
	for i, item := range items {
		out[i] = RouteRedistribute{
			Name:       item.Name,
			Status:     item.Status,
			RouteMap:   coalesce(item.RouteMap, item.Routemap),
			Metric:     item.Metric,
			MetricType: item.MetricType,
			Tag:        item.Tag,
		}
	}
	return out
}

func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ListIPv6StaticRoutes retrieves IPv6 static routes from a VDOM.
func (c *Client) ListIPv6StaticRoutes(ctx context.Context, vdom string, opts ...ListOption) ([]IPv6StaticRoute, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiIPv6StaticRoute](ctx, c, "/api/v2/cmdb/router/static6",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	routes := make([]IPv6StaticRoute, len(items))
	for i, r := range items {
		routes[i] = IPv6StaticRoute(r)
	}

	return routes, nil
}
