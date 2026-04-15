package fortigate

// Exported string constants for the enum fields returned by the FortiGate
// REST API v2. FortiGate returns these as named strings directly, so we do
// not need a numeric-to-name translation layer like fortimgr does. Consumers
// should prefer these constants over string literals when filtering or
// switching on values returned by the SDK.

// Address types (firewall/address).
const (
	AddressTypeIPMask      = "ipmask"
	AddressTypeIPRange     = "iprange"
	AddressTypeFQDN        = "fqdn"
	AddressTypeWildcard    = "wildcard"
	AddressTypeGeography   = "geography"
	AddressTypeWildcardFQDN = "wildcard-fqdn"
	AddressTypeDynamic     = "dynamic"
	AddressTypeMAC         = "mac"
)

// Policy actions (firewall/policy).
const (
	PolicyActionAccept = "accept"
	PolicyActionDeny   = "deny"
	PolicyActionIPsec  = "ipsec"
)

// Policy log traffic modes (firewall/policy).
const (
	LogTrafficDisable = "disable"
	LogTrafficUTM     = "utm"
	LogTrafficAll     = "all"
)

// Enable/disable status, used by many resources.
const (
	StatusEnable  = "enable"
	StatusDisable = "disable"
)

// Interface operational status.
const (
	InterfaceUp   = "up"
	InterfaceDown = "down"
)

// Interface types (system/interface).
const (
	InterfaceTypePhysical  = "physical"
	InterfaceTypeVLAN      = "vlan"
	InterfaceTypeLoopback  = "loopback"
	InterfaceTypeTunnel    = "tunnel"
	InterfaceTypeAggregate = "aggregate"
	InterfaceTypeRedundant = "redundant"
	InterfaceTypeWireless  = "wireless"
	InterfaceTypeVDOMLink  = "vdom-link"
)

// Interface roles (system/interface).
const (
	InterfaceRoleLAN       = "lan"
	InterfaceRoleWAN       = "wan"
	InterfaceRoleDMZ       = "dmz"
	InterfaceRoleUndefined = "undefined"
)

// Interface addressing modes (system/interface).
const (
	InterfaceModeStatic = "static"
	InterfaceModeDHCP   = "dhcp"
	InterfaceModePPPoE  = "pppoe"
)

// Service protocol categories (firewall.service/custom).
const (
	ServiceProtoTCPUDPSCTP = "TCP/UDP/SCTP"
	ServiceProtoICMP       = "ICMP"
	ServiceProtoICMP6      = "ICMP6"
	ServiceProtoIP         = "IP"
)

// Virtual IP protocols (firewall/vip).
const (
	VIPProtocolTCP  = "tcp"
	VIPProtocolUDP  = "udp"
	VIPProtocolSCTP = "sctp"
	VIPProtocolICMP = "icmp"
)

// IP pool types (firewall/ippool).
const (
	IPPoolOverload            = "overload"
	IPPoolOneToOne            = "one-to-one"
	IPPoolFixedPortRange      = "fixed-port-range"
	IPPoolPortBlockAllocation = "port-block-allocation"
)

// VDOM operating modes (system/vdom).
const (
	VDOMModeNAT         = "nat"
	VDOMModeTransparent = "transparent"
)
