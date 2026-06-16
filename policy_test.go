package fortigate

import (
	"context"
	"testing"
)

func TestListPolicies(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.ListPolicies(context.Background(), "root")
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/firewall/policy": `[
				{
					"policyid": 1,
					"name": "allow-outbound",
					"srcintf": [{"name": "port1"}],
					"dstintf": [{"name": "wan1"}, {"name": "wan2"}],
					"srcaddr": [{"name": "all"}],
					"dstaddr": [{"name": "all"}],
					"srcaddr6": [{"name": "all"}],
					"dstaddr6": [{"name": "lan-v6"}, {"name": "dmz-v6"}],
					"service": [{"name": "ALL"}],
					"action": "accept",
					"status": "enable",
					"logtraffic": "utm",
					"nat": "enable",
					"schedule": "always",
					"comments": "default outbound"
				},
				{
					"policyid": 2,
					"name": "block-bad",
					"srcintf": [{"name": "port1"}],
					"dstintf": [{"name": "wan1"}],
					"srcaddr": [{"name": "all"}],
					"dstaddr": [{"name": "bad-hosts"}],
					"service": [{"name": "ALL"}],
					"action": "deny",
					"status": "enable",
					"logtraffic": "all",
					"nat": "disable",
					"schedule": "always",
					"comments": ""
				}
			]`,
		})

		policies, err := client.ListPolicies(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(policies) != 2 {
			t.Fatalf("len = %d, want 2", len(policies))
		}

		p := policies[0]
		if p.ID != 1 {
			t.Errorf("ID = %d, want 1", p.ID)
		}
		if p.Name != "allow-outbound" {
			t.Errorf("Name = %q", p.Name)
		}
		if len(p.SrcIntfs) != 1 || p.SrcIntfs[0] != "port1" {
			t.Errorf("SrcIntfs = %v", p.SrcIntfs)
		}
		if len(p.DstIntfs) != 2 || p.DstIntfs[0] != "wan1" || p.DstIntfs[1] != "wan2" {
			t.Errorf("DstIntfs = %v", p.DstIntfs)
		}
		if p.Action != "accept" {
			t.Errorf("Action = %q", p.Action)
		}
		if !p.NATEnabled {
			t.Error("NATEnabled = false, want true")
		}
		if p.LogTraffic != "utm" {
			t.Errorf("LogTraffic = %q", p.LogTraffic)
		}
		if p.Comment != "default outbound" {
			t.Errorf("Comment = %q", p.Comment)
		}
		if len(p.SrcAddrs6) != 1 || p.SrcAddrs6[0] != "all" {
			t.Errorf("SrcAddrs6 = %v, want [all]", p.SrcAddrs6)
		}
		if len(p.DstAddrs6) != 2 || p.DstAddrs6[0] != "lan-v6" || p.DstAddrs6[1] != "dmz-v6" {
			t.Errorf("DstAddrs6 = %v, want [lan-v6 dmz-v6]", p.DstAddrs6)
		}

		p2 := policies[1]
		if p2.Action != "deny" {
			t.Errorf("Action = %q", p2.Action)
		}
		if p2.NATEnabled {
			t.Error("NATEnabled = true, want false")
		}
		if len(p2.SrcAddrs6) != 0 || len(p2.DstAddrs6) != 0 {
			t.Errorf("v6 addrs = %v/%v, want empty (no srcaddr6/dstaddr6 in fixture)", p2.SrcAddrs6, p2.DstAddrs6)
		}
	})
}
