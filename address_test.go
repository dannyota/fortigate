package fortigate

import (
	"context"
	"testing"
)

func TestListAddresses(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.ListAddresses(context.Background(), "root")
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("invalid vdom", func(t *testing.T) {
		c := newTestClient(t, nil)
		_, err := c.ListAddresses(context.Background(), "bad/vdom")
		if err == nil {
			t.Error("expected error for invalid VDOM name")
		}
	})

	t.Run("success — all types", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/firewall/address": `[
				{
					"name": "host-server",
					"type": "ipmask",
					"subnet": "192.0.2.1 255.255.255.255",
					"start-ip": "",
					"end-ip": "",
					"fqdn": "",
					"country": "",
					"wildcard": "",
					"comment": "Production server",
					"color": 3,
					"associated-interface": "port1"
				},
				{
					"name": "internal-net",
					"type": "ipmask",
					"subnet": "198.51.100.0 255.255.255.0",
					"start-ip": "",
					"end-ip": "",
					"fqdn": "",
					"country": "",
					"wildcard": "",
					"comment": "",
					"color": 0,
					"associated-interface": ""
				},
				{
					"name": "dhcp-range",
					"type": "iprange",
					"subnet": "",
					"start-ip": "192.0.2.100",
					"end-ip": "192.0.2.200",
					"fqdn": "",
					"country": "",
					"wildcard": "",
					"comment": "DHCP pool",
					"color": 0,
					"associated-interface": ""
				},
				{
					"name": "example.com",
					"type": "fqdn",
					"subnet": "",
					"start-ip": "",
					"end-ip": "",
					"fqdn": "example.com",
					"country": "",
					"wildcard": "",
					"comment": "",
					"color": 0,
					"associated-interface": ""
				},
				{
					"name": "geo-vn",
					"type": "geography",
					"subnet": "",
					"start-ip": "",
					"end-ip": "",
					"fqdn": "",
					"country": "VN",
					"wildcard": "",
					"comment": "",
					"color": 0,
					"associated-interface": ""
				}
			]`,
		})

		addrs, err := client.ListAddresses(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(addrs) != 5 {
			t.Fatalf("len = %d, want 5", len(addrs))
		}

		// ipmask host — /32 stripped.
		a := addrs[0]
		if a.Name != "host-server" {
			t.Errorf("Name = %q", a.Name)
		}
		if a.Type != "ipmask" {
			t.Errorf("Type = %q", a.Type)
		}
		if a.Subnet != "192.0.2.1" {
			t.Errorf("Subnet = %q, want %q (host, no /32)", a.Subnet, "192.0.2.1")
		}
		if a.Comment != "Production server" {
			t.Errorf("Comment = %q", a.Comment)
		}
		if a.Color != 3 {
			t.Errorf("Color = %d", a.Color)
		}
		if a.AssocIntf != "port1" {
			t.Errorf("AssocIntf = %q", a.AssocIntf)
		}

		// ipmask network — CIDR.
		if addrs[1].Subnet != "198.51.100.0/24" {
			t.Errorf("Subnet = %q, want 198.51.100.0/24", addrs[1].Subnet)
		}

		// iprange.
		r := addrs[2]
		if r.Type != "iprange" {
			t.Errorf("Type = %q", r.Type)
		}
		if r.StartIP != "192.0.2.100" || r.EndIP != "192.0.2.200" {
			t.Errorf("StartIP=%q EndIP=%q", r.StartIP, r.EndIP)
		}

		// fqdn.
		if addrs[3].Type != "fqdn" || addrs[3].FQDN != "example.com" {
			t.Errorf("fqdn: type=%q fqdn=%q", addrs[3].Type, addrs[3].FQDN)
		}

		// geography.
		if addrs[4].Type != "geography" || addrs[4].Country != "VN" {
			t.Errorf("geography: type=%q country=%q", addrs[4].Type, addrs[4].Country)
		}
	})
}

func TestListAddressGroups(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.ListAddressGroups(context.Background(), "root")
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/firewall/addrgrp": `[
				{
					"name": "web-servers",
					"member": [
						{"name": "web-01"},
						{"name": "web-02"},
						{"name": "web-03"}
					],
					"comment": "Web server group",
					"color": 5
				},
				{
					"name": "empty-group",
					"member": [],
					"comment": "",
					"color": 0
				}
			]`,
		})

		groups, err := client.ListAddressGroups(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 2 {
			t.Fatalf("len = %d, want 2", len(groups))
		}

		g := groups[0]
		if g.Name != "web-servers" {
			t.Errorf("Name = %q", g.Name)
		}
		if len(g.Members) != 3 || g.Members[0] != "web-01" || g.Members[2] != "web-03" {
			t.Errorf("Members = %v", g.Members)
		}
		if g.Comment != "Web server group" {
			t.Errorf("Comment = %q", g.Comment)
		}
		if g.Color != 5 {
			t.Errorf("Color = %d", g.Color)
		}

		if len(groups[1].Members) != 0 {
			t.Errorf("empty group Members = %v", groups[1].Members)
		}
	})
}

func TestListIPv6Addresses(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.ListIPv6Addresses(context.Background(), "root")
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/firewall/address6": `[
				{
					"name": "v6-net",
					"type": "ipprefix",
					"ip6": "2001:db8::/64",
					"comment": "IPv6 network",
					"color": 4
				},
				{
					"name": "v6-fqdn",
					"type": "fqdn",
					"fqdn": "example.net"
				}
			]`,
		})

		addrs, err := client.ListIPv6Addresses(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(addrs) != 2 {
			t.Fatalf("len = %d, want 2", len(addrs))
		}
		if addrs[0].Name != "v6-net" || addrs[0].IP6 != "2001:db8::/64" || addrs[0].Comment != "IPv6 network" {
			t.Errorf("addr = %+v", addrs[0])
		}
		if addrs[1].FQDN != "example.net" {
			t.Errorf("FQDN = %q", addrs[1].FQDN)
		}
	})
}

func TestListIPv6AddressGroups(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/firewall/addrgrp6": `[
				{
					"name": "v6-group",
					"member": [{"name": "v6-net"}],
					"comment": "IPv6 group",
					"color": 2
				}
			]`,
		})

		groups, err := client.ListIPv6AddressGroups(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 1 {
			t.Fatalf("len = %d, want 1", len(groups))
		}
		if groups[0].Name != "v6-group" || len(groups[0].Members) != 1 || groups[0].Members[0] != "v6-net" {
			t.Errorf("group = %+v", groups[0])
		}
	})
}
