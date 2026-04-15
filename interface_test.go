package fortigate

import (
	"context"
	"testing"
)

func TestListInterfaces(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.ListInterfaces(context.Background(), "root")
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/system/interface": `[
				{
					"name": "port1",
					"ip": "192.0.2.1 255.255.255.0",
					"type": "physical",
					"alias": "LAN",
					"role": "lan",
					"status": "up",
					"vlanid": 0,
					"mode": "static",
					"interface": "",
					"allowaccess": "ping https ssh http",
					"mtu": 1500,
					"speed": "1000full",
					"description": "LAN uplink"
				},
				{
					"name": "vlan100",
					"ip": "198.51.100.1 255.255.255.0",
					"type": "vlan",
					"alias": "",
					"role": "lan",
					"status": "up",
					"vlanid": 100,
					"mode": "static",
					"interface": "port1",
					"allowaccess": "",
					"mtu": 1500,
					"speed": "auto",
					"description": ""
				},
				{
					"name": "wan1",
					"ip": "203.0.113.1 255.255.255.252",
					"type": "physical",
					"alias": "WAN",
					"role": "wan",
					"status": "up",
					"vlanid": 0,
					"mode": "dhcp",
					"interface": "",
					"allowaccess": "ping",
					"mtu": 1500,
					"speed": "auto",
					"description": ""
				},
				{
					"name": "tun0",
					"ip": "0.0.0.0 0.0.0.0",
					"type": "tunnel",
					"alias": "",
					"role": "undefined",
					"status": "up",
					"vlanid": 0,
					"mode": "static",
					"interface": "wan1",
					"allowaccess": "",
					"mtu": 0,
					"speed": "",
					"description": ""
				}
			]`,
		})

		ifaces, err := client.ListInterfaces(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(ifaces) != 4 {
			t.Fatalf("len = %d, want 4", len(ifaces))
		}

		// Physical with IP.
		p := ifaces[0]
		if p.Name != "port1" {
			t.Errorf("Name = %q", p.Name)
		}
		if p.IP != "192.0.2.1/24" {
			t.Errorf("IP = %q, want 192.0.2.1/24", p.IP)
		}
		if p.Type != "physical" {
			t.Errorf("Type = %q", p.Type)
		}
		if p.Alias != "LAN" {
			t.Errorf("Alias = %q", p.Alias)
		}
		if p.Role != "lan" {
			t.Errorf("Role = %q", p.Role)
		}
		if p.ParentIntf != "" {
			t.Errorf("ParentIntf = %q, want empty for physical", p.ParentIntf)
		}
		wantAccess := []string{"ping", "https", "ssh", "http"}
		if len(p.AllowAccess) != len(wantAccess) {
			t.Errorf("AllowAccess = %v, want %v", p.AllowAccess, wantAccess)
		} else {
			for i := range wantAccess {
				if p.AllowAccess[i] != wantAccess[i] {
					t.Errorf("AllowAccess[%d] = %q, want %q", i, p.AllowAccess[i], wantAccess[i])
				}
			}
		}
		if p.MTU != 1500 {
			t.Errorf("MTU = %d, want 1500", p.MTU)
		}
		if p.Speed != "1000full" {
			t.Errorf("Speed = %q, want 1000full", p.Speed)
		}
		if p.Description != "LAN uplink" {
			t.Errorf("Description = %q", p.Description)
		}

		// Empty allowaccess should be nil, not [""].
		if ifaces[1].AllowAccess != nil {
			t.Errorf("vlan100 AllowAccess = %v, want nil for empty string", ifaces[1].AllowAccess)
		}

		// VLAN — parent interface set.
		vlan := ifaces[1]
		if vlan.VLANID != 100 {
			t.Errorf("VLANID = %d, want 100", vlan.VLANID)
		}
		if vlan.ParentIntf != "port1" {
			t.Errorf("ParentIntf = %q, want port1", vlan.ParentIntf)
		}
		if vlan.IP != "198.51.100.1/24" {
			t.Errorf("IP = %q, want 198.51.100.1/24", vlan.IP)
		}

		// Tunnel — no IP (0.0.0.0 0.0.0.0 → empty string).
		tun := ifaces[3]
		if tun.IP != "" {
			t.Errorf("tunnel IP = %q, want empty (unnumbered)", tun.IP)
		}
		if tun.ParentIntf != "wan1" {
			t.Errorf("tunnel ParentIntf = %q, want wan1", tun.ParentIntf)
		}
	})
}
