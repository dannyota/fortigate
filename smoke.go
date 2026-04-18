//go:build ignore

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"text/tabwriter"

	"danny.vn/fortigate"
)

type config struct {
	Address            string `json:"address"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	VDOM               string `json:"vdom"`
	InsecureTLS        bool   `json:"insecure_tls"`
	X509NegativeSerial bool   `json:"x509_negative_serial"`
}

func loadConfig() config {
	var cfg config

	// Load from .fortigate.json if it exists.
	if data, err := os.ReadFile(".fortigate.json"); err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("invalid .fortigate.json: %v", err)
		}
	}

	// Env vars override file values.
	if v := os.Getenv("FORTIGATE_ADDRESS"); v != "" {
		cfg.Address = v
	}
	if v := os.Getenv("FORTIGATE_USERNAME"); v != "" {
		cfg.Username = v
	}
	if v := os.Getenv("FORTIGATE_PASSWORD"); v != "" {
		cfg.Password = v
	}
	if v := os.Getenv("FORTIGATE_VDOM"); v != "" {
		cfg.VDOM = v
	}

	if cfg.Address == "" || cfg.Username == "" || cfg.Password == "" {
		fmt.Fprintln(os.Stderr, "Create .fortigate.json or set FORTIGATE_ADDRESS, FORTIGATE_USERNAME, FORTIGATE_PASSWORD")
		os.Exit(1)
	}

	return cfg
}

func writeSample(name string, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: marshal %s sample: %v\n", name, err)
		return
	}
	os.MkdirAll("samples/sdk", 0o755)
	path := fmt.Sprintf("samples/sdk/%s.json", name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "warning: write %s: %v\n", path, err)
		return
	}
	fmt.Printf("  → %s (%d bytes)\n", path, len(data))
}

func main() {
	cfg := loadConfig()

	var opts []fortigate.ClientOption
	opts = append(opts, fortigate.WithCredentials(cfg.Username, cfg.Password))
	if cfg.InsecureTLS {
		opts = append(opts, fortigate.WithInsecureTLS())
	}
	if cfg.X509NegativeSerial {
		opts = append(opts, fortigate.WithX509NegativeSerial())
	}

	ctx := context.Background()

	client, err := fortigate.NewClient(cfg.Address, opts...)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	fmt.Printf("Connecting to %s...\n", cfg.Address)
	if err := client.Login(ctx); err != nil {
		log.Fatalf("Login: %v", err)
	}
	fmt.Println("Login OK")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)

	// System info.
	sysInfo, sysErr := client.GetSystemInfo(ctx)
	if sysErr != nil {
		fmt.Printf("GetSystemInfo: %v\n", sysErr)
	} else {
		fmt.Printf("Device: %s  admin-https: %d\n\n", sysInfo.Hostname, sysInfo.AdminSport)
	}

	// VDOMs.
	vdoms, vdomErr := client.ListVDOMs(ctx)
	if vdomErr != nil {
		fmt.Printf("ListVDOMs: %v\n\n", vdomErr)
	} else {
		fmt.Printf("VDOMs: %d\n", len(vdoms))
		fmt.Fprintf(w, "VDOM\tMODE\n")
		for _, v := range vdoms {
			fmt.Fprintf(w, "%s\t%s\n", v.Name, v.OpMode)
		}
		w.Flush()
		fmt.Println()
	}

	// Auto-detect VDOM from the list when not configured: first available.
	if cfg.VDOM == "" {
		if vdomErr != nil {
			log.Fatalf("ListVDOMs (needed for auto-detect): %v", vdomErr)
		}
		if len(vdoms) == 0 {
			log.Fatal("no VDOMs found")
		}
		cfg.VDOM = vdoms[0].Name
		fmt.Printf("Auto-selected VDOM: %s\n\n", cfg.VDOM)
	} else {
		fmt.Printf("Using VDOM: %s\n\n", cfg.VDOM)
	}

	// Collect all resources.
	type resource struct {
		name  string
		count int
		err   error
	}
	var resources []resource

	addrs, err := client.ListAddresses(ctx, cfg.VDOM,
		fortigate.WithPageCallback(func(fetched, page int) {
			fmt.Printf("  ListAddresses page %d → %d rows cumulative\n", page, fetched)
		}),
	)
	resources = append(resources, resource{"Addresses", len(addrs), err})

	addrGroups, err := client.ListAddressGroups(ctx, cfg.VDOM)
	resources = append(resources, resource{"Address Groups", len(addrGroups), err})

	ipv6Addrs, err := client.ListIPv6Addresses(ctx, cfg.VDOM)
	resources = append(resources, resource{"IPv6 Addresses", len(ipv6Addrs), err})

	ipv6AddrGroups, err := client.ListIPv6AddressGroups(ctx, cfg.VDOM)
	resources = append(resources, resource{"IPv6 Address Groups", len(ipv6AddrGroups), err})

	policies, err := client.ListPolicies(ctx, cfg.VDOM)
	resources = append(resources, resource{"Policies", len(policies), err})

	ifaces, err := client.ListInterfaces(ctx, cfg.VDOM)
	resources = append(resources, resource{"Interfaces", len(ifaces), err})

	zones, err := client.ListZones(ctx, cfg.VDOM)
	resources = append(resources, resource{"Zones", len(zones), err})

	dnsSettings, dnsSettingsErr := client.GetDNSSettings(ctx)

	dnsServers, err := client.ListDNSServers(ctx, cfg.VDOM)
	resources = append(resources, resource{"DNS Servers", len(dnsServers), err})

	dhcpServers, err := client.ListDHCPServers(ctx, cfg.VDOM)
	resources = append(resources, resource{"DHCP Servers", len(dhcpServers), err})

	dhcpv6Servers, err := client.ListDHCPv6Servers(ctx, cfg.VDOM)
	resources = append(resources, resource{"DHCPv6 Servers", len(dhcpv6Servers), err})

	sdwanSettings, sdwanSettingsErr := client.GetSDWANSettings(ctx, cfg.VDOM)

	sdwanMembers, err := client.ListSDWANMembers(ctx, cfg.VDOM)
	resources = append(resources, resource{"SD-WAN Members", len(sdwanMembers), err})

	sdwanZones, err := client.ListSDWANZones(ctx, cfg.VDOM)
	resources = append(resources, resource{"SD-WAN Zones", len(sdwanZones), err})

	bgpSettings, bgpSettingsErr := client.GetBGPSettings(ctx, cfg.VDOM)

	ospfSettings, ospfSettingsErr := client.GetOSPFSettings(ctx, cfg.VDOM)

	ospf6Settings, ospf6SettingsErr := client.GetOSPFv6Settings(ctx, cfg.VDOM)

	sslVPNSettings, sslVPNSettingsErr := client.GetSSLVPNSettings(ctx, cfg.VDOM)

	systemStatus, systemStatusErr := client.GetSystemStatus(ctx, cfg.VDOM)

	routes, err := client.ListStaticRoutes(ctx, cfg.VDOM)
	resources = append(resources, resource{"Static Routes", len(routes), err})

	ipv6Routes, err := client.ListIPv6StaticRoutes(ctx, cfg.VDOM)
	resources = append(resources, resource{"IPv6 Static Routes", len(ipv6Routes), err})

	policyRoutes, err := client.ListPolicyRoutes(ctx, cfg.VDOM)
	resources = append(resources, resource{"Policy Routes", len(policyRoutes), err})

	ipv6PolicyRoutes, err := client.ListIPv6PolicyRoutes(ctx, cfg.VDOM)
	resources = append(resources, resource{"IPv6 Policy Routes", len(ipv6PolicyRoutes), err})

	routeMaps, err := client.ListRouteMaps(ctx, cfg.VDOM)
	resources = append(resources, resource{"Route Maps", len(routeMaps), err})

	accessLists, err := client.ListAccessLists(ctx, cfg.VDOM)
	resources = append(resources, resource{"Access Lists", len(accessLists), err})

	ipv6AccessLists, err := client.ListIPv6AccessLists(ctx, cfg.VDOM)
	resources = append(resources, resource{"IPv6 Access Lists", len(ipv6AccessLists), err})

	prefixLists, err := client.ListPrefixLists(ctx, cfg.VDOM)
	resources = append(resources, resource{"Prefix Lists", len(prefixLists), err})

	ipv6PrefixLists, err := client.ListIPv6PrefixLists(ctx, cfg.VDOM)
	resources = append(resources, resource{"IPv6 Prefix Lists", len(ipv6PrefixLists), err})

	asPathLists, err := client.ListASPathLists(ctx, cfg.VDOM)
	resources = append(resources, resource{"AS Path Lists", len(asPathLists), err})

	communityLists, err := client.ListCommunityLists(ctx, cfg.VDOM)
	resources = append(resources, resource{"Community Lists", len(communityLists), err})

	ipsecPhase1s, err := client.ListIPsecPhase1s(ctx, cfg.VDOM)
	resources = append(resources, resource{"IPsec Phase1s", len(ipsecPhase1s), err})

	ipsecPhase2s, err := client.ListIPsecPhase2s(ctx, cfg.VDOM)
	resources = append(resources, resource{"IPsec Phase2s", len(ipsecPhase2s), err})

	sslVPNPortals, err := client.ListSSLVPNPortals(ctx, cfg.VDOM)
	resources = append(resources, resource{"SSL VPN Portals", len(sslVPNPortals), err})

	localUsers, err := client.ListLocalUsers(ctx, cfg.VDOM)
	resources = append(resources, resource{"Local Users", len(localUsers), err})

	userGroups, err := client.ListUserGroups(ctx, cfg.VDOM)
	resources = append(resources, resource{"User Groups", len(userGroups), err})

	ldapServers, err := client.ListLDAPServers(ctx, cfg.VDOM)
	resources = append(resources, resource{"LDAP Servers", len(ldapServers), err})

	radiusServers, err := client.ListRadiusServers(ctx, cfg.VDOM)
	resources = append(resources, resource{"RADIUS Servers", len(radiusServers), err})

	tacacsServers, err := client.ListTACACSServers(ctx, cfg.VDOM)
	resources = append(resources, resource{"TACACS+ Servers", len(tacacsServers), err})

	localCerts, err := client.ListLocalCertificates(ctx, cfg.VDOM)
	resources = append(resources, resource{"Local Certificates", len(localCerts), err})

	caCerts, err := client.ListCACertificates(ctx, cfg.VDOM)
	resources = append(resources, resource{"CA Certificates", len(caCerts), err})

	crlCerts, err := client.ListCRLCertificates(ctx, cfg.VDOM)
	resources = append(resources, resource{"CRL Certificates", len(crlCerts), err})

	remoteCerts, err := client.ListRemoteCertificates(ctx, cfg.VDOM)
	resources = append(resources, resource{"Remote Certificates", len(remoteCerts), err})

	monitorPolicyStats, err := client.ListMonitorPolicyStats(ctx, cfg.VDOM)
	resources = append(resources, resource{"Monitor Policy Stats", len(monitorPolicyStats), err})

	monitorRoutes, err := client.ListMonitorRoutes(ctx, cfg.VDOM)
	resources = append(resources, resource{"Monitor Routes", len(monitorRoutes), err})

	monitorIPsecTunnels, err := client.ListMonitorIPsecTunnels(ctx, cfg.VDOM)
	resources = append(resources, resource{"Monitor IPsec Tunnels", len(monitorIPsecTunnels), err})

	monitorSSLTunnels, err := client.ListMonitorSSLTunnels(ctx, cfg.VDOM)
	resources = append(resources, resource{"Monitor SSL Tunnels", len(monitorSSLTunnels), err})

	services, err := client.ListServices(ctx, cfg.VDOM)
	resources = append(resources, resource{"Services", len(services), err})

	svcGroups, err := client.ListServiceGroups(ctx, cfg.VDOM)
	resources = append(resources, resource{"Service Groups", len(svcGroups), err})

	svcCategories, err := client.ListServiceCategories(ctx, cfg.VDOM)
	resources = append(resources, resource{"Service Categories", len(svcCategories), err})

	recurringSchedules, err := client.ListRecurringSchedules(ctx, cfg.VDOM)
	resources = append(resources, resource{"Recurring Schedules", len(recurringSchedules), err})

	oneTimeSchedules, err := client.ListOneTimeSchedules(ctx, cfg.VDOM)
	resources = append(resources, resource{"One-Time Schedules", len(oneTimeSchedules), err})

	scheduleGroups, err := client.ListScheduleGroups(ctx, cfg.VDOM)
	resources = append(resources, resource{"Schedule Groups", len(scheduleGroups), err})

	vips, err := client.ListVirtualIPs(ctx, cfg.VDOM)
	resources = append(resources, resource{"Virtual IPs", len(vips), err})

	ipv6VIPs, err := client.ListIPv6VirtualIPs(ctx, cfg.VDOM)
	resources = append(resources, resource{"IPv6 Virtual IPs", len(ipv6VIPs), err})

	vipGroups, err := client.ListVirtualIPGroups(ctx, cfg.VDOM)
	resources = append(resources, resource{"Virtual IP Groups", len(vipGroups), err})

	ipv6VIPGroups, err := client.ListIPv6VirtualIPGroups(ctx, cfg.VDOM)
	resources = append(resources, resource{"IPv6 Virtual IP Groups", len(ipv6VIPGroups), err})

	pools, err := client.ListIPPools(ctx, cfg.VDOM)
	resources = append(resources, resource{"IP Pools", len(pools), err})

	ipv6Pools, err := client.ListIPv6IPPools(ctx, cfg.VDOM)
	resources = append(resources, resource{"IPv6 IP Pools", len(ipv6Pools), err})

	// Summary table.
	fmt.Println()
	fmt.Fprintf(w, "RESOURCE\tCOUNT\tSTATUS\n")
	if sysErr != nil {
		fmt.Fprintf(w, "System Info\t0\t%s\n", sysErr)
	} else {
		fmt.Fprintf(w, "System Info\t1\t%s\n", sysInfo.Hostname)
	}
	if vdomErr != nil {
		fmt.Fprintf(w, "VDOMs\t0\t%s\n", vdomErr)
	} else {
		fmt.Fprintf(w, "VDOMs\t%d\tOK\n", len(vdoms))
	}
	if dnsSettingsErr != nil {
		fmt.Fprintf(w, "DNS Settings\t0\t%s\n", dnsSettingsErr)
	} else {
		fmt.Fprintf(w, "DNS Settings\t1\tOK\n")
	}
	if sdwanSettingsErr != nil {
		fmt.Fprintf(w, "SD-WAN Settings\t0\t%s\n", sdwanSettingsErr)
	} else {
		fmt.Fprintf(w, "SD-WAN Settings\t1\tOK\n")
	}
	if bgpSettingsErr != nil {
		fmt.Fprintf(w, "BGP Settings\t0\t%s\n", bgpSettingsErr)
	} else {
		fmt.Fprintf(w, "BGP Settings\t1\tOK\n")
	}
	if ospfSettingsErr != nil {
		fmt.Fprintf(w, "OSPF Settings\t0\t%s\n", ospfSettingsErr)
	} else {
		fmt.Fprintf(w, "OSPF Settings\t1\tOK\n")
	}
	if ospf6SettingsErr != nil {
		fmt.Fprintf(w, "OSPFv6 Settings\t0\t%s\n", ospf6SettingsErr)
	} else {
		fmt.Fprintf(w, "OSPFv6 Settings\t1\tOK\n")
	}
	if sslVPNSettingsErr != nil {
		fmt.Fprintf(w, "SSL VPN Settings\t0\t%s\n", sslVPNSettingsErr)
	} else {
		fmt.Fprintf(w, "SSL VPN Settings\t1\tOK\n")
	}
	if systemStatusErr != nil {
		fmt.Fprintf(w, "Monitor System Status\t0\t%s\n", systemStatusErr)
	} else {
		fmt.Fprintf(w, "Monitor System Status\t1\tOK\n")
	}
	for _, r := range resources {
		status := "OK"
		if r.err != nil {
			status = r.err.Error()
		}
		fmt.Fprintf(w, "%s\t%d\t%s\n", r.name, r.count, status)
	}
	w.Flush()
	fmt.Println()

	// Write samples for field inspection.
	fmt.Println("Writing samples/...")
	writeSample("system_info", sysInfo)
	writeSample("vdoms", vdoms)
	writeSample("addresses", firstN(addrs, 10))
	writeSample("address_groups", firstN(addrGroups, 5))
	writeSample("ipv6_addresses", firstN(ipv6Addrs, 10))
	writeSample("ipv6_address_groups", firstN(ipv6AddrGroups, 5))
	writeSample("policies", firstN(policies, 5))
	writeSample("interfaces", firstN(ifaces, 10))
	writeSample("zones", firstN(zones, 10))
	writeSample("dns_settings", dnsSettings)
	writeSample("dns_servers", firstN(dnsServers, 10))
	writeSample("dhcp_servers", firstN(dhcpServers, 10))
	writeSample("dhcpv6_servers", firstN(dhcpv6Servers, 10))
	writeSample("sdwan_settings", sdwanSettings)
	writeSample("sdwan_members", firstN(sdwanMembers, 10))
	writeSample("sdwan_zones", firstN(sdwanZones, 10))
	writeSample("bgp_settings", bgpSettings)
	writeSample("ospf_settings", ospfSettings)
	writeSample("ospf6_settings", ospf6Settings)
	writeSample("ssl_vpn_settings", sslVPNSettings)
	writeSample("monitor_system_status", systemStatus)
	writeSample("static_routes", firstN(routes, 10))
	writeSample("ipv6_static_routes", firstN(ipv6Routes, 10))
	writeSample("policy_routes", firstN(policyRoutes, 10))
	writeSample("ipv6_policy_routes", firstN(ipv6PolicyRoutes, 10))
	writeSample("route_maps", firstN(routeMaps, 10))
	writeSample("access_lists", firstN(accessLists, 10))
	writeSample("ipv6_access_lists", firstN(ipv6AccessLists, 10))
	writeSample("prefix_lists", firstN(prefixLists, 10))
	writeSample("ipv6_prefix_lists", firstN(ipv6PrefixLists, 10))
	writeSample("aspath_lists", firstN(asPathLists, 10))
	writeSample("community_lists", firstN(communityLists, 10))
	writeSample("ipsec_phase1s", firstN(ipsecPhase1s, 10))
	writeSample("ipsec_phase2s", firstN(ipsecPhase2s, 10))
	writeSample("ssl_vpn_portals", firstN(sslVPNPortals, 10))
	writeSample("local_users", firstN(localUsers, 10))
	writeSample("user_groups", firstN(userGroups, 10))
	writeSample("ldap_servers", firstN(ldapServers, 10))
	writeSample("radius_servers", firstN(radiusServers, 10))
	writeSample("tacacs_servers", firstN(tacacsServers, 10))
	writeSample("local_certificates", firstN(localCerts, 10))
	writeSample("ca_certificates", firstN(caCerts, 10))
	writeSample("crl_certificates", firstN(crlCerts, 10))
	writeSample("remote_certificates", firstN(remoteCerts, 10))
	writeSample("monitor_policy_stats", firstN(monitorPolicyStats, 10))
	writeSample("monitor_routes", firstN(monitorRoutes, 10))
	writeSample("monitor_ipsec_tunnels", firstN(monitorIPsecTunnels, 10))
	writeSample("monitor_ssl_tunnels", firstN(monitorSSLTunnels, 10))
	writeSample("services", firstN(services, 10))
	writeSample("service_groups", firstN(svcGroups, 5))
	writeSample("service_categories", firstN(svcCategories, 10))
	writeSample("recurring_schedules", firstN(recurringSchedules, 10))
	writeSample("one_time_schedules", firstN(oneTimeSchedules, 10))
	writeSample("schedule_groups", firstN(scheduleGroups, 5))
	writeSample("virtual_ips", firstN(vips, 5))
	writeSample("ipv6_virtual_ips", firstN(ipv6VIPs, 5))
	writeSample("virtual_ip_groups", firstN(vipGroups, 5))
	writeSample("ipv6_virtual_ip_groups", firstN(ipv6VIPGroups, 5))
	writeSample("ip_pools", firstN(pools, 5))
	writeSample("ipv6_ip_pools", firstN(ipv6Pools, 5))
}

func firstN[T any](s []T, n int) []T {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
