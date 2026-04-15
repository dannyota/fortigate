package fortigate

// Address represents a FortiGate firewall address object.
type Address struct {
	Name      string
	Type      string // "ipmask", "iprange", "fqdn", "wildcard", "geography", "dynamic", "mac"
	Subnet    string // CIDR notation, e.g. "192.0.2.0/24" (ipmask)
	StartIP   string // iprange
	EndIP     string // iprange
	FQDN      string // fqdn
	Country   string // geography
	Wildcard  string // wildcard
	Comment   string
	Color     int
	AssocIntf string
}

// AddressGroup represents a FortiGate firewall address group.
type AddressGroup struct {
	Name    string
	Members []string
	Comment string
	Color   int
}

// Policy represents a FortiGate firewall policy.
type Policy struct {
	ID         int
	Name       string
	SrcIntfs   []string
	DstIntfs   []string
	SrcAddrs   []string
	DstAddrs   []string
	Services   []string
	Action     string // "accept", "deny", "ipsec"
	Status     string // "enable", "disable"
	LogTraffic string // "disable", "utm", "all"
	NATEnabled bool
	Schedule   string
	Comment    string
}

// Interface represents a FortiGate network interface.
type Interface struct {
	Name        string
	IP          string // CIDR notation; empty string if no IP configured
	Type        string // "physical", "vlan", "loopback", "tunnel", "aggregate", "redundant"
	Alias       string
	Role        string // "lan", "wan", "dmz", "undefined"
	Status      string // "up", "down"
	VLANID      int
	Mode        string   // "static", "dhcp", "pppoe"
	ParentIntf  string   // parent interface name for VLANs and tunnels
	AllowAccess []string // management protocols allowed on this interface (e.g. "ping", "https", "ssh")
	MTU         int      // 0 if the device returned mtu-override=disable
	Speed       string   // "auto", "1000full", "10000full", etc.
	Description string
}

// StaticRoute represents a FortiGate static route.
type StaticRoute struct {
	SeqNum   int
	Dst      string // CIDR notation
	Gateway  string
	Device   string
	Distance int
	Priority int
	Comment  string
	Status   string // "enable", "disable"
}

// Service represents a FortiGate firewall service object.
type Service struct {
	Name         string
	Protocol     string // "TCP/UDP/SCTP", "ICMP", "IP", "ICMP6"
	TCPPortRange string
	UDPPortRange string
	Comment      string
	Color        int
}

// ServiceGroup represents a FortiGate firewall service group.
type ServiceGroup struct {
	Name    string
	Members []string
	Comment string
	Color   int
}

// VirtualIP represents a FortiGate virtual IP (DNAT).
type VirtualIP struct {
	Name       string
	ExtIP      string
	MappedIP   string
	ExtIntf    string
	PortForward bool
	ExtPort    string
	MappedPort string
	Protocol   string // "tcp", "udp", "sctp", "icmp"
	Comment    string
	Color      int
}

// IPPool represents a FortiGate IP pool (SNAT).
type IPPool struct {
	Name     string
	Type     string // "overload", "one-to-one", "fixed-port-range", "port-block-allocation"
	StartIP  string
	EndIP    string
	SourceStartIP string
	SourceEndIP   string
	Comment  string
	Color    int
}

// VDOM represents a FortiGate virtual domain.
type VDOM struct {
	Name   string
	OpMode string // "nat", "transparent"
}

// SystemInfo holds top-level FortiGate system information.
type SystemInfo struct {
	Hostname   string
	Timezone   string // timezone index string as returned by FortiGate, e.g. "53"
	AdminSport int
	AdminPort  int
}
