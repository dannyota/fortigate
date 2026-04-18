package fortigate

import (
	"context"
	"testing"
)

func TestListStaticRoutes(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.ListStaticRoutes(context.Background(), "root")
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/router/static": `[
				{
					"seq-num": 1,
					"dst": "0.0.0.0 0.0.0.0",
					"gateway": "203.0.113.1",
					"device": "wan1",
					"distance": 10,
					"priority": 0,
					"comment": "default route",
					"status": "enable"
				},
				{
					"seq-num": 2,
					"dst": "192.0.2.0 255.255.255.0",
					"gateway": "198.51.100.254",
					"device": "port1",
					"distance": 20,
					"priority": 1,
					"comment": "",
					"status": "enable"
				},
				{
					"seq-num": 3,
					"dst": "198.51.100.0 255.255.255.0",
					"gateway": "0.0.0.0",
					"device": "tun0",
					"distance": 10,
					"priority": 0,
					"comment": "VPN route",
					"status": "disable"
				}
			]`,
		})

		routes, err := client.ListStaticRoutes(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(routes) != 3 {
			t.Fatalf("len = %d, want 3", len(routes))
		}

		// Default route — 0.0.0.0/0.
		r := routes[0]
		if r.SeqNum != 1 {
			t.Errorf("SeqNum = %d", r.SeqNum)
		}
		if r.Dst != "0.0.0.0/0" {
			t.Errorf("Dst = %q, want 0.0.0.0/0", r.Dst)
		}
		if r.Gateway != "203.0.113.1" {
			t.Errorf("Gateway = %q", r.Gateway)
		}
		if r.Device != "wan1" {
			t.Errorf("Device = %q", r.Device)
		}
		if r.Comment != "default route" {
			t.Errorf("Comment = %q", r.Comment)
		}

		// Network route — dotted mask → CIDR.
		if routes[1].Dst != "192.0.2.0/24" {
			t.Errorf("Dst = %q, want 192.0.2.0/24", routes[1].Dst)
		}

		// Disabled VPN route.
		if routes[2].Status != "disable" {
			t.Errorf("Status = %q, want disable", routes[2].Status)
		}
		if routes[2].Dst != "198.51.100.0/24" {
			t.Errorf("Dst = %q, want 198.51.100.0/24", routes[2].Dst)
		}
	})
}

func TestListIPv6StaticRoutes(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.ListIPv6StaticRoutes(context.Background(), "root")
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/router/static6": `[
				{
					"seq-num": 1,
					"dst": "::/0",
					"gateway": "2001:db8::1",
					"device": "wan1",
					"distance": 10,
					"priority": 0,
					"comment": "IPv6 default",
					"status": "enable"
				}
			]`,
		})

		routes, err := client.ListIPv6StaticRoutes(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(routes) != 1 {
			t.Fatalf("len = %d, want 1", len(routes))
		}
		if routes[0].Dst != "::/0" || routes[0].Gateway != "2001:db8::1" || routes[0].Comment != "IPv6 default" {
			t.Errorf("route = %+v", routes[0])
		}
	})
}

func TestListPolicyRoutes(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/router/policy": `[
			{
				"seq-num": 10,
				"input-device": [{"name": "wan1"}],
				"srcaddr": [{"name": "src-net"}],
				"dstaddr": [{"name": "dst-net"}],
				"action": "permit",
				"protocol": 6,
				"start-port": 443,
				"end-port": 443,
				"start-source-port": 1024,
				"end-source-port": 65535,
				"gateway": "192.0.2.1",
				"output-device": "port2",
				"tos": "0x00",
				"tos-mask": "0x00",
				"status": "enable",
				"comments": "policy route"
			}
		]`,
	})

	routes, err := client.ListPolicyRoutes(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatalf("len = %d, want 1", len(routes))
	}
	r := routes[0]
	if r.SeqNum != 10 || r.Protocol != 6 || r.Gateway != "192.0.2.1" || r.OutputDevice != "port2" {
		t.Errorf("route = %+v", r)
	}
	if len(r.InputDevices) != 1 || r.InputDevices[0] != "wan1" {
		t.Errorf("InputDevices = %#v", r.InputDevices)
	}
	if len(r.SrcAddrs) != 1 || r.SrcAddrs[0] != "src-net" {
		t.Errorf("SrcAddrs = %#v", r.SrcAddrs)
	}
	if len(r.DstAddrs) != 1 || r.DstAddrs[0] != "dst-net" {
		t.Errorf("DstAddrs = %#v", r.DstAddrs)
	}
}

func TestGetBGPSettings(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/router/bgp": `{
			"as": "65000",
			"router-id": "192.0.2.10",
			"keepalive-timer": 60,
			"holdtime-timer": 180,
			"ebgp-multipath": "enable",
			"ibgp-multipath": "disable",
			"log-neighbour-changes": "enable",
			"network-import-check": "enable",
			"distance-external": 20,
			"distance-internal": 200,
			"distance-local": 200,
			"graceful-restart": "disable",
			"redistribute": [{"name": "connected", "status": "enable", "route-map": "rm-connected"}],
			"redistribute6": [{"name": "static", "status": "disable", "route-map": ""}]
		}`,
	})

	settings, err := client.GetBGPSettings(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if settings.AS != "65000" || settings.RouterID != "192.0.2.10" || settings.KeepaliveTimer != 60 {
		t.Errorf("settings = %+v", settings)
	}
	if len(settings.Redistribute) != 1 || settings.Redistribute[0].RouteMap != "rm-connected" {
		t.Errorf("Redistribute = %#v", settings.Redistribute)
	}
	if len(settings.Redistribute6) != 1 || settings.Redistribute6[0].Name != "static" {
		t.Errorf("Redistribute6 = %#v", settings.Redistribute6)
	}
}

func TestGetOSPFSettings(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/router/ospf": `{
			"router-id": "192.0.2.20",
			"abr-type": "standard",
			"auto-cost-ref-bandwidth": 1000,
			"distance": 110,
			"distance-external": 110,
			"distance-inter-area": 110,
			"distance-intra-area": 110,
			"default-information-originate": "enable",
			"default-information-metric": 10,
			"default-information-metric-type": "type-2",
			"default-metric": 10,
			"spf-timers": "5 10",
			"bfd": "disable",
			"log-neighbour-changes": "enable",
			"redistribute": [{"name": "static", "status": "enable", "metric": 20, "routemap": "rm-static", "metric-type": "type-1", "tag": 100}]
		}`,
		"/api/v2/cmdb/router/ospf6": `{
			"router-id": "192.0.2.30",
			"abr-type": "cisco",
			"auto-cost-ref-bandwidth": 100,
			"default-information-originate": "disable",
			"default-information-metric": 1,
			"default-information-metric-type": "type-2",
			"default-metric": 1,
			"spf-timers": "5 10",
			"bfd": "enable",
			"log-neighbour-changes": "disable",
			"redistribute": [{"name": "connected", "status": "enable", "metric": 5}]
		}`,
	})

	ospf, err := client.GetOSPFSettings(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if ospf.RouterID != "192.0.2.20" || ospf.DefaultInformationMetric != 10 {
		t.Errorf("ospf = %+v", ospf)
	}
	if len(ospf.Redistribute) != 1 || ospf.Redistribute[0].RouteMap != "rm-static" || ospf.Redistribute[0].Tag != 100 {
		t.Errorf("OSPF Redistribute = %#v", ospf.Redistribute)
	}

	ospf6, err := client.GetOSPFv6Settings(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if ospf6.RouterID != "192.0.2.30" || ospf6.BFD != "enable" {
		t.Errorf("ospf6 = %+v", ospf6)
	}
}

func TestRouteHelperLists(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/router/route-map": `[
			{"name": "rm1", "comments": "route map", "rule": [{"id": 1, "action": "permit", "match-ip-address": "pl1", "match-as-path": "as1", "set-community": "65000:1", "status": "enable"}]}
		]`,
		"/api/v2/cmdb/router/access-list": `[
			{"name": "acl1", "comments": "access list", "rule": [{"id": 1, "action": "permit", "prefix": "192.0.2.0/24", "exact-match": "enable", "status": "enable"}]}
		]`,
		"/api/v2/cmdb/router/access-list6": `[
			{"name": "acl6", "comments": "access list 6", "rule": [{"id": 1, "action": "deny", "prefix": "2001:db8::/32", "exact-match": "disable", "status": "enable"}]}
		]`,
		"/api/v2/cmdb/router/prefix-list": `[
			{"name": "pl1", "comments": "prefix list", "rule": [{"id": 1, "action": "permit", "prefix": "192.0.2.0/24", "ge": 24, "le": 32, "status": "enable"}]}
		]`,
		"/api/v2/cmdb/router/prefix-list6": `[
			{"name": "pl6", "comments": "prefix list 6", "rule": [{"id": 1, "action": "permit", "prefix": "2001:db8::/32", "ge": 32, "le": 64, "status": "enable"}]}
		]`,
		"/api/v2/cmdb/router/aspath-list": `[
			{"name": "as1", "comments": "as path", "rule": [{"id": 1, "action": "permit", "regexp": "^65000_", "status": "enable", "comments": "rule"}]}
		]`,
		"/api/v2/cmdb/router/community-list": `[
			{"name": "cl1", "comments": "community", "rule": [{"id": 1, "action": "permit", "match": "65000:1", "regexp": "", "status": "enable", "comments": "rule"}]}
		]`,
	})

	routeMaps, err := client.ListRouteMaps(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(routeMaps) != 1 || routeMaps[0].Rules[0].SetCommunity != "65000:1" {
		t.Errorf("routeMaps = %#v", routeMaps)
	}

	accessLists, err := client.ListAccessLists(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(accessLists) != 1 || accessLists[0].Rules[0].ExactMatch != "enable" {
		t.Errorf("accessLists = %#v", accessLists)
	}

	accessLists6, err := client.ListIPv6AccessLists(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(accessLists6) != 1 || accessLists6[0].Rules[0].Prefix != "2001:db8::/32" {
		t.Errorf("accessLists6 = %#v", accessLists6)
	}

	prefixLists, err := client.ListPrefixLists(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixLists) != 1 || prefixLists[0].Rules[0].LE != 32 {
		t.Errorf("prefixLists = %#v", prefixLists)
	}

	prefixLists6, err := client.ListIPv6PrefixLists(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixLists6) != 1 || prefixLists6[0].Rules[0].GE != 32 {
		t.Errorf("prefixLists6 = %#v", prefixLists6)
	}

	asPathLists, err := client.ListASPathLists(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(asPathLists) != 1 || asPathLists[0].Rules[0].Regexp != "^65000_" {
		t.Errorf("asPathLists = %#v", asPathLists)
	}

	communityLists, err := client.ListCommunityLists(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(communityLists) != 1 || communityLists[0].Rules[0].Match != "65000:1" {
		t.Errorf("communityLists = %#v", communityLists)
	}
}
