package fortigate

import (
	"context"
	"testing"
)

// TestEnumConstants verifies the exported enum constants match the raw
// strings the FortiGate API returns, so consumers can switch or filter
// on them safely.
func TestEnumConstants(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/firewall/address": `[
			{"name":"h","type":"ipmask","subnet":"192.0.2.1 255.255.255.255"},
			{"name":"r","type":"iprange","start-ip":"192.0.2.10","end-ip":"192.0.2.20"},
			{"name":"f","type":"fqdn","fqdn":"example.com"}
		]`,
		"/api/v2/cmdb/firewall/policy": `[
			{"policyid":1,"name":"a","action":"accept","status":"enable","logtraffic":"all","nat":"enable"}
		]`,
		"/api/v2/cmdb/system/interface": `[
			{"name":"port1","type":"physical","role":"lan","status":"up","mode":"static","ip":"192.0.2.1 255.255.255.0"}
		]`,
		"/api/v2/cmdb/firewall/vip": `[
			{"name":"v","extip":"203.0.113.10","mappedip":[{"range":"192.0.2.10"}],"protocol":"tcp","portforward":"enable","extintf":"wan1"}
		]`,
		"/api/v2/cmdb/firewall/ippool": `[
			{"name":"p","type":"overload","startip":"203.0.113.100","endip":"203.0.113.110"}
		]`,
	})

	ctx := context.Background()

	addrs, err := client.ListAddresses(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	if addrs[0].Type != AddressTypeIPMask {
		t.Errorf("AddressTypeIPMask = %q, want %q", AddressTypeIPMask, addrs[0].Type)
	}
	if addrs[1].Type != AddressTypeIPRange {
		t.Errorf("AddressTypeIPRange = %q, want %q", AddressTypeIPRange, addrs[1].Type)
	}
	if addrs[2].Type != AddressTypeFQDN {
		t.Errorf("AddressTypeFQDN = %q, want %q", AddressTypeFQDN, addrs[2].Type)
	}

	pols, err := client.ListPolicies(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	if pols[0].Action != PolicyActionAccept {
		t.Errorf("PolicyActionAccept = %q, want %q", PolicyActionAccept, pols[0].Action)
	}
	if pols[0].Status != StatusEnable {
		t.Errorf("StatusEnable = %q, want %q", StatusEnable, pols[0].Status)
	}
	if pols[0].LogTraffic != LogTrafficAll {
		t.Errorf("LogTrafficAll = %q, want %q", LogTrafficAll, pols[0].LogTraffic)
	}

	ifs, err := client.ListInterfaces(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	if ifs[0].Type != InterfaceTypePhysical {
		t.Errorf("InterfaceTypePhysical = %q, want %q", InterfaceTypePhysical, ifs[0].Type)
	}
	if ifs[0].Role != InterfaceRoleLAN {
		t.Errorf("InterfaceRoleLAN = %q, want %q", InterfaceRoleLAN, ifs[0].Role)
	}
	if ifs[0].Status != InterfaceUp {
		t.Errorf("InterfaceUp = %q, want %q", InterfaceUp, ifs[0].Status)
	}
	if ifs[0].Mode != InterfaceModeStatic {
		t.Errorf("InterfaceModeStatic = %q, want %q", InterfaceModeStatic, ifs[0].Mode)
	}

	vips, err := client.ListVirtualIPs(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	if vips[0].Protocol != VIPProtocolTCP {
		t.Errorf("VIPProtocolTCP = %q, want %q", VIPProtocolTCP, vips[0].Protocol)
	}

	pools, err := client.ListIPPools(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	if pools[0].Type != IPPoolOverload {
		t.Errorf("IPPoolOverload = %q, want %q", IPPoolOverload, pools[0].Type)
	}
}
