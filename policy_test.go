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

		p2 := policies[1]
		if p2.Action != "deny" {
			t.Errorf("Action = %q", p2.Action)
		}
		if p2.NATEnabled {
			t.Error("NATEnabled = true, want false")
		}
	})
}
