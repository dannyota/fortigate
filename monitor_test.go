package fortigate

import (
	"context"
	"testing"
)

func TestMonitorEndpoints(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/monitor/system/status": `{
			"model_name": "FortiGate",
			"model_number": "FGT",
			"model": "FGT-VM",
			"hostname": "fw1",
			"log_disk_status": "available"
		}`,
		"/api/v2/monitor/firewall/policy": `[
			{
				"policyid": 1,
				"active_sessions": 2,
				"bytes": 1000,
				"packets": 10,
				"software_bytes": 900,
				"software_packets": 9,
				"asic_bytes": 100,
				"asic_packets": 1,
				"last_used": 1700000000,
				"first_used": 1690000000,
				"hit_count": 42,
				"session_last_used": 1700000001,
				"session_first_used": 1690000001,
				"session_count": 3
			}
		]`,
		"/api/v2/monitor/router/ipv4": `[
			{
				"ip_version": 4,
				"type": "static",
				"ip_mask": "0.0.0.0/0",
				"distance": 10,
				"metric": 0,
				"priority": 1,
				"vrf": 0,
				"gateway": "192.0.2.1",
				"non_rc_gateway": "",
				"interface": "wan1"
			}
		]`,
		"/api/v2/monitor/vpn/ipsec": `[
			{
				"name": "to-branch",
				"comments": "branch",
				"wizard-type": "custom",
				"connection_count": 1,
				"creation_time": 1700000000,
				"username": "",
				"type": "ipsec",
				"incoming_bytes": 100,
				"outgoing_bytes": 200,
				"rgwy": "198.51.100.10",
				"tun_id": "1",
				"tun_id6": ""
			}
		]`,
		"/api/v2/monitor/vpn/ssl": `[
			{
				"name": "ssl1",
				"username": "alice",
				"remote_addr": "198.51.100.20",
				"incoming_bytes": 10,
				"outgoing_bytes": 20
			}
		]`,
	})

	status, err := client.GetSystemStatus(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if status.Model != "FGT-VM" || status.LogDiskStatus != "available" {
		t.Errorf("status = %+v", status)
	}

	policies, err := client.ListMonitorPolicyStats(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 || policies[0].HitCount != 42 || policies[0].ActiveSessions != 2 {
		t.Errorf("policies = %#v", policies)
	}

	routes, err := client.ListMonitorRoutes(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].IPMask != "0.0.0.0/0" || routes[0].Interface != "wan1" {
		t.Errorf("routes = %#v", routes)
	}

	ipsec, err := client.ListMonitorIPsecTunnels(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(ipsec) != 1 || ipsec[0].IncomingBytes != 100 || ipsec[0].RemoteGateway != "198.51.100.10" {
		t.Errorf("ipsec = %#v", ipsec)
	}

	ssl, err := client.ListMonitorSSLTunnels(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(ssl) != 1 || ssl[0].Username != "alice" || ssl[0].OutgoingBytes != 20 {
		t.Errorf("ssl = %#v", ssl)
	}
}
