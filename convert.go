package fortigate

import (
	"fmt"
	"net"
	"strings"
)

// spaceSubnetToCIDR converts a FortiGate space-separated subnet to CIDR.
// "192.0.2.0 255.255.255.0" → "192.0.2.0/24"
// "192.0.2.1 255.255.255.255" → "192.0.2.1" (host address, /32 stripped)
// "0.0.0.0 0.0.0.0" → "0.0.0.0/0"
// Single-token values (already CIDR) pass through unchanged.
func spaceSubnetToCIDR(s string) string {
	if s == "" {
		return ""
	}
	parts := strings.Fields(s)
	if len(parts) != 2 {
		return s
	}
	ip, mask := parts[0], parts[1]

	prefix := maskToCIDRPrefix(mask)
	if prefix < 0 {
		return s
	}
	if prefix == 32 {
		return ip
	}
	return fmt.Sprintf("%s/%d", ip, prefix)
}

func maskToCIDRPrefix(mask string) int {
	ip := net.ParseIP(mask)
	if ip == nil {
		return -1
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return -1
	}
	ones, _ := net.IPv4Mask(ip4[0], ip4[1], ip4[2], ip4[3]).Size()
	return ones
}

// namedItem is used for FortiGate reference arrays like
// [{"name": "port1"}, {"name": "port2"}].
type namedItem struct {
	Name string `json:"name"`
}

// namesOf extracts the Name field from a slice of namedItems.
func namesOf(items []namedItem) []string {
	if len(items) == 0 {
		return []string{}
	}
	names := make([]string, len(items))
	for i, item := range items {
		names[i] = item.Name
	}
	return names
}

// isEnabled returns true if v is "enable".
func isEnabled(v string) bool {
	return v == "enable"
}

// zeroIPToEmpty returns "" when v is "0.0.0.0" or "0.0.0.0/0",
// which FortiGate uses for interfaces with no IP configured.
func zeroIPToEmpty(v string) string {
	if v == "0.0.0.0" || v == "0.0.0.0/0" {
		return ""
	}
	return v
}

// vipMappedIP joins VIP mappedip range entries into a comma-separated string.
// FortiGate returns mappedip as [{range: "x.x.x.x"}, ...].
func vipMappedIP(items []apiVIPMappedIP) string {
	ranges := make([]string, len(items))
	for i, m := range items {
		ranges[i] = m.Range
	}
	return strings.Join(ranges, ",")
}
