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
