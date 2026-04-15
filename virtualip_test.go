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
