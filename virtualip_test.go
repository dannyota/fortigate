package fortigate

import (
	"context"
	"testing"
)

func TestListVirtualIPs(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.ListVirtualIPs(context.Background(), "root")
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/firewall/vip": `[
				{
					"name": "web-dnat",
					"extip": "203.0.113.10",
					"mappedip": [{"range": "192.0.2.10"}],
					"extintf": "wan1",
					"portforward": "enable",
					"extport": "443",
					"mappedport": "443",
					"protocol": "tcp",
					"comment": "HTTPS DNAT",
					"color": 0
				},
				{
					"name": "full-nat",
					"extip": "203.0.113.20",
					"mappedip": [{"range": "192.0.2.20"}],
					"extintf": "any",
					"portforward": "disable",
					"extport": "0-65535",
					"mappedport": "0-65535",
					"protocol": "tcp",
					"comment": "",
					"color": 0
				},
				{
					"name": "multi-range",
					"extip": "203.0.113.30",
					"mappedip": [{"range": "192.0.2.30"}, {"range": "192.0.2.31"}],
					"extintf": "wan1",
					"portforward": "disable",
					"extport": "0-65535",
					"mappedport": "0-65535",
					"protocol": "tcp",
					"comment": "",
					"color": 0
				}
			]`,
		})

		vips, err := client.ListVirtualIPs(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(vips) != 3 {
			t.Fatalf("len = %d, want 3", len(vips))
		}

		v := vips[0]
		if v.Name != "web-dnat" {
			t.Errorf("Name = %q", v.Name)
		}
		if v.ExtIP != "203.0.113.10" {
			t.Errorf("ExtIP = %q", v.ExtIP)
		}
		if v.MappedIP != "192.0.2.10" {
			t.Errorf("MappedIP = %q, want 192.0.2.10", v.MappedIP)
		}
		if v.ExtIntf != "wan1" {
			t.Errorf("ExtIntf = %q", v.ExtIntf)
		}
		if !v.PortForward {
			t.Error("PortForward = false, want true")
		}
		if v.Protocol != "tcp" {
			t.Errorf("Protocol = %q", v.Protocol)
		}
		if v.Comment != "HTTPS DNAT" {
			t.Errorf("Comment = %q", v.Comment)
		}

		// No port-forward.
		if vips[1].PortForward {
			t.Error("PortForward = true, want false")
		}

		// Multiple mapped IPs joined.
		if vips[2].MappedIP != "192.0.2.30,192.0.2.31" {
			t.Errorf("MappedIP = %q, want 192.0.2.30,192.0.2.31", vips[2].MappedIP)
		}
	})
}

func TestListIPv6VirtualIPs(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.ListIPv6VirtualIPs(context.Background(), "root")
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/firewall/vip6": `[
				{
					"name": "v6-dnat",
					"extip": "2001:db8::10",
					"mappedip": [{"range": "2001:db8:1::10"}],
					"extintf": "wan1",
					"portforward": "enable",
					"extport": "443",
					"mappedport": "8443",
					"protocol": "tcp",
					"comment": "IPv6 DNAT",
					"color": 1
				}
			]`,
		})

		vips, err := client.ListIPv6VirtualIPs(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(vips) != 1 {
			t.Fatalf("len = %d, want 1", len(vips))
		}
		if vips[0].ExtIP != "2001:db8::10" || vips[0].MappedIP != "2001:db8:1::10" || !vips[0].PortForward {
			t.Errorf("vip = %+v", vips[0])
		}
	})
}

func TestListVirtualIPGroups(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/firewall/vipgrp": `[
				{
					"name": "vip-group",
					"member": [{"name": "web-dnat"}, {"name": "full-nat"}],
					"comment": "VIP group",
					"color": 3
				}
			]`,
		})

		groups, err := client.ListVirtualIPGroups(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 1 {
			t.Fatalf("len = %d, want 1", len(groups))
		}
		if groups[0].Name != "vip-group" || len(groups[0].Members) != 2 || groups[0].Members[1] != "full-nat" {
			t.Errorf("group = %+v", groups[0])
		}
	})
}

func TestListIPv6VirtualIPGroups(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/firewall/vipgrp6": `[
				{
					"name": "v6-vip-group",
					"member": [{"name": "v6-dnat"}],
					"comment": "IPv6 VIP group",
					"color": 4
				}
			]`,
		})

		groups, err := client.ListIPv6VirtualIPGroups(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 1 {
			t.Fatalf("len = %d, want 1", len(groups))
		}
		if groups[0].Name != "v6-vip-group" || len(groups[0].Members) != 1 || groups[0].Members[0] != "v6-dnat" {
			t.Errorf("group = %+v", groups[0])
		}
	})
}
