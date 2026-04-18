package fortigate

import (
	"context"
	"testing"
)

func TestListIPsecPhase1s(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/vpn.ipsec/phase1-interface": `[
			{
				"name": "to-branch",
				"type": "dynamic",
				"interface": "wan1",
				"ip-version": "4",
				"ike-version": "2",
				"local-gw": "192.0.2.10",
				"remote-gw": "198.51.100.10",
				"authmethod": "psk",
				"mode": "main",
				"peertype": "any",
				"proposal": "aes256-sha256",
				"dhgrp": "14",
				"add-route": "enable",
				"auto-negotiate": "enable",
				"dpd": "on-idle",
				"nattraversal": "enable",
				"net-device": "disable",
				"distance": 15,
				"priority": 1,
				"keylife": 28800,
				"comments": "branch tunnel",
				"wizard-type": "custom"
			}
		]`,
	})

	phase1s, err := client.ListIPsecPhase1s(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(phase1s) != 1 {
		t.Fatalf("len = %d, want 1", len(phase1s))
	}
	p := phase1s[0]
	if p.Name != "to-branch" || p.IKEVersion != "2" || p.Proposal != "aes256-sha256" || p.KeyLife != 28800 {
		t.Errorf("phase1 = %+v", p)
	}
}

func TestListIPsecPhase2s(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/vpn.ipsec/phase2-interface": `[
			{
				"name": "to-branch-p2",
				"phase1name": "to-branch",
				"proposal": "aes256-sha256",
				"pfs": "enable",
				"dhgrp": "14",
				"replay": "enable",
				"auto-negotiate": "enable",
				"add-route": "phase1",
				"keylifeseconds": 3600,
				"keylifekbs": 5120,
				"keylife-type": "seconds",
				"protocol": 0,
				"src-name": "",
				"src-subnet": "192.0.2.0 255.255.255.0",
				"src-port": 0,
				"dst-name": "",
				"dst-subnet": "198.51.100.0 255.255.255.0",
				"dst-port": 0,
				"comments": "phase2"
			}
		]`,
	})

	phase2s, err := client.ListIPsecPhase2s(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(phase2s) != 1 {
		t.Fatalf("len = %d, want 1", len(phase2s))
	}
	p := phase2s[0]
	if p.Phase1Name != "to-branch" || p.SrcSubnet != "192.0.2.0/24" || p.DstSubnet != "198.51.100.0/24" {
		t.Errorf("phase2 = %+v", p)
	}
}

func TestSSLVPN(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/vpn.ssl.web/portal": `[
			{
				"name": "full-access",
				"tunnel-mode": "enable",
				"web-mode": "enable",
				"ip-mode": "range",
				"auto-connect": "disable",
				"keep-alive": "enable",
				"save-password": "disable",
				"ip-pools": [{"name": "SSLVPN_TUNNEL_ADDR1"}],
				"ipv6-pools": [{"name": "SSLVPN_TUNNEL_IPv6_ADDR1"}],
				"split-tunneling": "enable",
				"dns-server1": "192.0.2.53",
				"dns-server2": "192.0.2.54",
				"dns-suffix": "example.test",
				"allow-user-access": "web ftp smb",
				"theme": "blue",
				"heading": "Portal",
				"limit-user-logins": "enable",
				"use-sdwan": "disable",
				"prefer-ipv6-dns": "disable"
			}
		]`,
		"/api/v2/cmdb/vpn.ssl/settings": `{
			"status": "enable",
			"reqclientcert": "disable",
			"ssl-min-proto-ver": "tls1-2",
			"ssl-max-proto-ver": "tls1-3",
			"servercert": "Fortinet_Factory",
			"algorithm": "high",
			"idle-timeout": 300,
			"auth-timeout": 28800,
			"login-attempt-limit": 2,
			"login-block-time": 60,
			"port": 10443,
			"tunnel-ip-pools": [{"name": "SSLVPN_TUNNEL_ADDR1"}],
			"tunnel-ipv6-pools": [{"name": "SSLVPN_TUNNEL_IPv6_ADDR1"}],
			"source-interface": [{"name": "wan1"}],
			"source-address": [{"name": "all"}],
			"source-address-negate": "disable",
			"default-portal": "full-access",
			"dtls-tunnel": "enable",
			"check-referer": "enable",
			"dual-stack-mode": "enable",
			"tunnel-addr-assigned-method": "first-available",
			"server-hostname": "vpn.example.test"
		}`,
	})

	portals, err := client.ListSSLVPNPortals(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(portals) != 1 || portals[0].IPPools[0] != "SSLVPN_TUNNEL_ADDR1" {
		t.Errorf("portals = %#v", portals)
	}

	settings, err := client.GetSSLVPNSettings(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if settings.Status != "enable" || settings.Port != 10443 || settings.SourceInterfaces[0] != "wan1" {
		t.Errorf("settings = %+v", settings)
	}
}
