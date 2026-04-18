package fortigate

import (
	"context"
	"testing"
)

func TestListZones(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.ListZones(context.Background(), "root")
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/system/zone": `[
				{
					"name": "LAN-ZONE",
					"interface": [{"name": "port1"}, {"name": "vlan100"}],
					"intrazone": "allow",
					"description": "Internal zone"
				}
			]`,
		})

		zones, err := client.ListZones(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(zones) != 1 {
			t.Fatalf("len = %d, want 1", len(zones))
		}
		if zones[0].Name != "LAN-ZONE" || len(zones[0].Interfaces) != 2 || zones[0].Interfaces[1] != "vlan100" {
			t.Errorf("zone = %+v", zones[0])
		}
		if zones[0].Intrazone != "allow" || zones[0].Description != "Internal zone" {
			t.Errorf("zone details = %+v", zones[0])
		}
	})
}

func TestGetDNSSettings(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.GetDNSSettings(context.Background())
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/system/dns": `{
				"primary": "192.0.2.53",
				"secondary": "198.51.100.53",
				"ip6-primary": "2001:db8::53",
				"protocol": "dot",
				"server-hostname": [{"hostname": "dns1.example.test"}, {"hostname": "dns2.example.test"}],
				"domain": [{"domain": "example.test"}],
				"source-ip": "192.0.2.1",
				"interface": "wan1",
				"interface-select-method": "specify"
			}`,
		})

		settings, err := client.GetDNSSettings(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if settings.Primary != "192.0.2.53" || settings.Protocol != "dot" || settings.Interface != "wan1" {
			t.Errorf("settings = %+v", settings)
		}
		if len(settings.ServerHostnames) != 2 || settings.ServerHostnames[0] != "dns1.example.test" {
			t.Errorf("server hostnames = %v", settings.ServerHostnames)
		}
		if len(settings.Domains) != 1 || settings.Domains[0] != "example.test" {
			t.Errorf("domains = %v", settings.Domains)
		}
	})
}

func TestListDNSServers(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/system/dns-server": `[
			{"name": "port1", "mode": "recursive", "dnsfilter-profile": "default"}
		]`,
	})

	servers, err := client.ListDNSServers(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("len = %d, want 1", len(servers))
	}
	if servers[0].Name != "port1" || servers[0].Mode != "recursive" || servers[0].DNSFilterProfile != "default" {
		t.Errorf("server = %+v", servers[0])
	}
}

func TestListDHCPServers(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/system.dhcp/server": `[
			{
				"id": 1,
				"interface": "port1",
				"default-gateway": "192.0.2.1",
				"netmask": "255.255.255.0",
				"domain": "example.test",
				"dns-service": "specify",
				"dns-server1": "192.0.2.53",
				"dns-server2": "198.51.100.53",
				"lease-time": 86400,
				"ip-range": [
					{"id": 1, "start-ip": "192.0.2.100", "end-ip": "192.0.2.150"}
				],
				"status": "enable"
			}
		]`,
	})

	servers, err := client.ListDHCPServers(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("len = %d, want 1", len(servers))
	}
	s := servers[0]
	if s.ID != 1 || s.Interface != "port1" || s.DefaultGateway != "192.0.2.1" {
		t.Errorf("server = %+v", s)
	}
	if len(s.IPRanges) != 1 || s.IPRanges[0].StartIP != "192.0.2.100" {
		t.Errorf("ranges = %+v", s.IPRanges)
	}
}

func TestListDHCPv6Servers(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/system.dhcp6/server": `[
			{
				"id": 1,
				"interface": "port2",
				"subnet": "2001:db8::/64",
				"dns-service": "specify",
				"dns-server1": "2001:db8::53",
				"ip-range": [
					{"id": 1, "start-ip6": "2001:db8::100", "end-ip6": "2001:db8::1ff"}
				],
				"status": "enable"
			}
		]`,
	})

	servers, err := client.ListDHCPv6Servers(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("len = %d, want 1", len(servers))
	}
	if servers[0].Subnet != "2001:db8::/64" || servers[0].IPRanges[0].EndIP != "2001:db8::1ff" {
		t.Errorf("server = %+v", servers[0])
	}
}

func TestGetSDWANSettings(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/system/sdwan": `{
			"status": "enable",
			"load-balance-mode": "source-ip-based",
			"members": [
				{"seq-num": 1, "interface": "wan1", "gateway": "203.0.113.1", "zone": "virtual-wan-link", "status": "enable", "cost": 10}
			],
			"zone": [
				{"name": "virtual-wan-link", "service-sla-tie-break": "cfg-order"}
			],
			"service": [
				{"id": 1, "name": "default", "mode": "auto", "status": "enable", "priority-members": [{"name": "wan1"}]}
			],
			"health-check": [
				{"name": "internet", "server": "192.0.2.53", "status": "enable"}
			]
		}`,
	})

	settings, err := client.GetSDWANSettings(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if settings.Status != "enable" || len(settings.Members) != 1 || settings.Members[0].Interface != "wan1" {
		t.Errorf("settings = %+v", settings)
	}
	if len(settings.Services) != 1 || len(settings.Services[0].Priority) != 1 || settings.Services[0].Priority[0] != "wan1" {
		t.Errorf("services = %+v", settings.Services)
	}
}

func TestListSDWANMembers(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/system/sdwan/members": `[
			{"seq-num": 1, "interface": "wan1", "gateway": "203.0.113.1", "zone": "virtual-wan-link", "status": "enable", "priority": 1}
		]`,
	})

	members, err := client.ListSDWANMembers(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0].Interface != "wan1" || members[0].Priority != 1 {
		t.Errorf("members = %+v", members)
	}
}

func TestListSDWANZones(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/system/sdwan/zone": `[
			{"name": "virtual-wan-link", "service-sla-tie-break": "cfg-order"}
		]`,
	})

	zones, err := client.ListSDWANZones(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 1 || zones[0].Name != "virtual-wan-link" || zones[0].ServiceSLATieBreak != "cfg-order" {
		t.Errorf("zones = %+v", zones)
	}
}
