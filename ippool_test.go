package fortigate

import (
	"context"
	"testing"
)

func TestListIPPools(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.ListIPPools(context.Background(), "root")
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/firewall/ippool": `[
				{
					"name": "nat-pool",
					"type": "overload",
					"startip": "203.0.113.100",
					"endip": "203.0.113.110",
					"source-startip": "0.0.0.0",
					"source-endip": "0.0.0.0",
					"comments": "NAT pool",
					"color": 0
				},
				{
					"name": "one-to-one-pool",
					"type": "one-to-one",
					"startip": "203.0.113.120",
					"endip": "203.0.113.130",
					"source-startip": "192.0.2.0",
					"source-endip": "192.0.2.10",
					"comments": "",
					"color": 3
				}
			]`,
		})

		pools, err := client.ListIPPools(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(pools) != 2 {
			t.Fatalf("len = %d, want 2", len(pools))
		}

		p := pools[0]
		if p.Name != "nat-pool" {
			t.Errorf("Name = %q", p.Name)
		}
		if p.Type != "overload" {
			t.Errorf("Type = %q", p.Type)
		}
		if p.StartIP != "203.0.113.100" || p.EndIP != "203.0.113.110" {
			t.Errorf("StartIP=%q EndIP=%q", p.StartIP, p.EndIP)
		}
		if p.Comment != "NAT pool" {
			t.Errorf("Comment = %q", p.Comment)
		}

		p2 := pools[1]
		if p2.Type != "one-to-one" {
			t.Errorf("Type = %q", p2.Type)
		}
		if p2.SourceStartIP != "192.0.2.0" || p2.SourceEndIP != "192.0.2.10" {
			t.Errorf("SourceStartIP=%q SourceEndIP=%q", p2.SourceStartIP, p2.SourceEndIP)
		}
	})
}

func TestListIPv6IPPools(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.ListIPv6IPPools(context.Background(), "root")
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/firewall/ippool6": `[
				{
					"name": "v6-nat-pool",
					"type": "overload",
					"startip": "2001:db8::100",
					"endip": "2001:db8::1ff",
					"comments": "IPv6 NAT pool",
					"color": 5
				}
			]`,
		})

		pools, err := client.ListIPv6IPPools(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(pools) != 1 {
			t.Fatalf("len = %d, want 1", len(pools))
		}
		if pools[0].Name != "v6-nat-pool" || pools[0].StartIP != "2001:db8::100" || pools[0].Comment != "IPv6 NAT pool" {
			t.Errorf("pool = %+v", pools[0])
		}
	})
}
