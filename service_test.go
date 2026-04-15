package fortigate

import (
	"context"
	"testing"
)

func TestListServices(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.ListServices(context.Background(), "root")
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/firewall.service/custom": `[
				{
					"name": "HTTP",
					"protocol": "TCP/UDP/SCTP",
					"tcp-portrange": "80",
					"udp-portrange": "",
					"comment": "",
					"color": 0
				},
				{
					"name": "DNS",
					"protocol": "TCP/UDP/SCTP",
					"tcp-portrange": "53",
					"udp-portrange": "53",
					"comment": "DNS service",
					"color": 2
				},
				{
					"name": "PING",
					"protocol": "ICMP",
					"tcp-portrange": "",
					"udp-portrange": "",
					"comment": "",
					"color": 0
				}
			]`,
		})

		svcs, err := client.ListServices(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(svcs) != 3 {
			t.Fatalf("len = %d, want 3", len(svcs))
		}

		if svcs[0].Name != "HTTP" || svcs[0].Protocol != "TCP/UDP/SCTP" || svcs[0].TCPPortRange != "80" {
			t.Errorf("HTTP: %+v", svcs[0])
		}
		if svcs[1].UDPPortRange != "53" || svcs[1].Comment != "DNS service" || svcs[1].Color != 2 {
			t.Errorf("DNS: %+v", svcs[1])
		}
		if svcs[2].Protocol != "ICMP" {
			t.Errorf("PING protocol = %q", svcs[2].Protocol)
		}
	})
}

func TestListServiceGroups(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.ListServiceGroups(context.Background(), "root")
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/firewall.service/group": `[
				{
					"name": "Web-Services",
					"member": [
						{"name": "HTTP"},
						{"name": "HTTPS"}
					],
					"comment": "Web ports",
					"color": 1
				}
			]`,
		})

		groups, err := client.ListServiceGroups(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 1 {
			t.Fatalf("len = %d, want 1", len(groups))
		}
		g := groups[0]
		if g.Name != "Web-Services" {
			t.Errorf("Name = %q", g.Name)
		}
		if len(g.Members) != 2 || g.Members[0] != "HTTP" || g.Members[1] != "HTTPS" {
			t.Errorf("Members = %v", g.Members)
		}
		if g.Comment != "Web ports" {
			t.Errorf("Comment = %q", g.Comment)
		}
	})
}
