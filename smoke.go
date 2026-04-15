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
	os.MkdirAll("samples", 0o755)
	path := fmt.Sprintf("samples/%s.json", name)
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

	policies, err := client.ListPolicies(ctx, cfg.VDOM)
	resources = append(resources, resource{"Policies", len(policies), err})

	ifaces, err := client.ListInterfaces(ctx, cfg.VDOM)
	resources = append(resources, resource{"Interfaces", len(ifaces), err})

	routes, err := client.ListStaticRoutes(ctx, cfg.VDOM)
	resources = append(resources, resource{"Static Routes", len(routes), err})

	services, err := client.ListServices(ctx, cfg.VDOM)
	resources = append(resources, resource{"Services", len(services), err})

	svcGroups, err := client.ListServiceGroups(ctx, cfg.VDOM)
	resources = append(resources, resource{"Service Groups", len(svcGroups), err})

	vips, err := client.ListVirtualIPs(ctx, cfg.VDOM)
	resources = append(resources, resource{"Virtual IPs", len(vips), err})

	pools, err := client.ListIPPools(ctx, cfg.VDOM)
	resources = append(resources, resource{"IP Pools", len(pools), err})

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
	writeSample("policies", firstN(policies, 5))
	writeSample("interfaces", firstN(ifaces, 10))
	writeSample("static_routes", firstN(routes, 10))
	writeSample("services", firstN(services, 10))
	writeSample("service_groups", firstN(svcGroups, 5))
	writeSample("virtual_ips", firstN(vips, 5))
	writeSample("ip_pools", firstN(pools, 5))
}

func firstN[T any](s []T, n int) []T {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
