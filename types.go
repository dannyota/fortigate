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

// IPv6Address represents a FortiGate IPv6 firewall address object.
type IPv6Address struct {
	Name    string
	Type    string
	IP6     string
	StartIP string
	EndIP   string
	FQDN    string
	Country string
	Comment string
	Color   int
}

// IPv6AddressGroup represents a FortiGate IPv6 firewall address group.
type IPv6AddressGroup struct {
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

// Zone represents a FortiGate interface zone.
type Zone struct {
	Name        string
	Interfaces  []string
	Intrazone   string
	Description string
}

// DNSSettings represents global DNS resolver settings.
type DNSSettings struct {
	Primary               string
	Secondary             string
	IP6Primary            string
	IP6Secondary          string
	Protocol              string
	ServerHostnames       []string
	Domains               []string
	SourceIP              string
	Interface             string
	InterfaceSelectMethod string
}

// DNSServer represents a VDOM DNS service bound to an interface.
type DNSServer struct {
	Name             string
	Mode             string
	DNSFilterProfile string
}

// DHCPIPRange represents an IPv4 DHCP lease range.
type DHCPIPRange struct {
	ID      int
	StartIP string
	EndIP   string
}

// DHCPServer represents an IPv4 DHCP server.
type DHCPServer struct {
	ID             int
	Interface      string
	DefaultGateway string
	Netmask        string
	Domain         string
	DNSService     string
	DNSServer1     string
	DNSServer2     string
	DNSServer3     string
	LeaseTime      int
	IPRanges       []DHCPIPRange
	Status         string
}

// DHCPv6IPRange represents an IPv6 DHCP lease range.
type DHCPv6IPRange struct {
	ID      int
	StartIP string
	EndIP   string
}

// DHCPv6Server represents an IPv6 DHCP server.
type DHCPv6Server struct {
	ID         int
	Interface  string
	Subnet     string
	DNSService string
	DNSServer1 string
	DNSServer2 string
	IPRanges   []DHCPv6IPRange
	Status     string
}

// SDWANSettings represents top-level SD-WAN configuration.
type SDWANSettings struct {
	Status          string
	LoadBalanceMode string
	Members         []SDWANMember
	Zones           []SDWANZone
	Services        []SDWANService
	HealthChecks    []SDWANHealthCheck
}

// SDWANMember represents an SD-WAN member interface.
type SDWANMember struct {
	ID        int
	SeqNum    int
	Interface string
	Gateway   string
	Zone      string
	Status    string
	Cost      int
	Priority  int
	Comment   string
}

// SDWANZone represents an SD-WAN zone.
type SDWANZone struct {
	Name               string
	ServiceSLATieBreak string
}

// SDWANService represents an SD-WAN rule/service.
type SDWANService struct {
	ID       int
	Name     string
	Mode     string
	Status   string
	Priority []string
}

// SDWANHealthCheck represents an SD-WAN health check.
type SDWANHealthCheck struct {
	Name   string
	Server string
	Status string
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

// IPv6StaticRoute represents a FortiGate IPv6 static route.
type IPv6StaticRoute struct {
	SeqNum   int
	Dst      string
	Gateway  string
	Device   string
	Distance int
	Priority int
	Comment  string
	Status   string // "enable", "disable"
}

// PolicyRoute represents an IPv4 policy route.
type PolicyRoute struct {
	SeqNum          int
	InputDevices    []string
	SrcAddrs        []string
	DstAddrs        []string
	Action          string
	Protocol        int
	StartPort       int
	EndPort         int
	StartSourcePort int
	EndSourcePort   int
	Gateway         string
	OutputDevice    string
	TOS             string
	TOSMask         string
	Status          string
	Comment         string
}

// IPv6PolicyRoute represents an IPv6 policy route.
type IPv6PolicyRoute struct {
	SeqNum          int
	InputDevices    []string
	SrcAddrs        []string
	DstAddrs        []string
	Action          string
	Protocol        int
	StartPort       int
	EndPort         int
	StartSourcePort int
	EndSourcePort   int
	Gateway         string
	OutputDevice    string
	TOS             string
	TOSMask         string
	Status          string
	Comment         string
}

// RouteMap represents a BGP/OSPF route map.
type RouteMap struct {
	Name    string
	Comment string
	Rules   []RouteMapRule
}

// RouteMapRule represents a route map rule.
type RouteMapRule struct {
	ID           int
	Action       string
	MatchIP      string
	MatchIPv6    string
	MatchASPath  string
	SetCommunity string
	Status       string
}

// AccessList represents an IPv4 router access list.
type AccessList struct {
	Name    string
	Comment string
	Rules   []AccessListRule
}

// IPv6AccessList represents an IPv6 router access list.
type IPv6AccessList struct {
	Name    string
	Comment string
	Rules   []AccessListRule
}

// AccessListRule represents a router access list rule.
type AccessListRule struct {
	ID         int
	Action     string
	Prefix     string
	ExactMatch string
	Status     string
}

// PrefixList represents an IPv4 router prefix list.
type PrefixList struct {
	Name    string
	Comment string
	Rules   []PrefixListRule
}

// IPv6PrefixList represents an IPv6 router prefix list.
type IPv6PrefixList struct {
	Name    string
	Comment string
	Rules   []PrefixListRule
}

// PrefixListRule represents a router prefix list rule.
type PrefixListRule struct {
	ID     int
	Action string
	Prefix string
	GE     int
	LE     int
	Status string
}

// ASPathList represents a BGP AS path list.
type ASPathList struct {
	Name    string
	Comment string
	Rules   []ASPathListRule
}

// ASPathListRule represents a BGP AS path list rule.
type ASPathListRule struct {
	ID      int
	Action  string
	Regexp  string
	Status  string
	Comment string
}

// CommunityList represents a BGP community list.
type CommunityList struct {
	Name    string
	Comment string
	Rules   []CommunityListRule
}

// CommunityListRule represents a BGP community list rule.
type CommunityListRule struct {
	ID      int
	Action  string
	Match   string
	Regexp  string
	Status  string
	Comment string
}

// RouteRedistribute represents a routing protocol redistribution rule.
type RouteRedistribute struct {
	Name       string
	Status     string
	RouteMap   string
	Metric     int
	MetricType string
	Tag        int
}

// BGPSettings represents top-level BGP configuration.
type BGPSettings struct {
	AS                  string
	RouterID            string
	KeepaliveTimer      int
	HoldtimeTimer       int
	EBGPMultipath       string
	IBGPMultipath       string
	LogNeighbourChanges string
	NetworkImportCheck  string
	DistanceExternal    int
	DistanceInternal    int
	DistanceLocal       int
	GracefulRestart     string
	Redistribute        []RouteRedistribute
	Redistribute6       []RouteRedistribute
}

// OSPFSettings represents top-level OSPF configuration.
type OSPFSettings struct {
	RouterID                     string
	ABRType                      string
	AutoCostReferenceBandwidth   int
	Distance                     int
	DistanceExternal             int
	DistanceInterArea            int
	DistanceIntraArea            int
	DefaultInformationOriginate  string
	DefaultInformationMetric     int
	DefaultInformationMetricType string
	DefaultMetric                int
	SPFTimers                    string
	BFD                          string
	LogNeighbourChanges          string
	Redistribute                 []RouteRedistribute
}

// OSPFv6Settings represents top-level OSPFv3 configuration.
type OSPFv6Settings struct {
	RouterID                     string
	ABRType                      string
	AutoCostReferenceBandwidth   int
	DefaultInformationOriginate  string
	DefaultInformationMetric     int
	DefaultInformationMetricType string
	DefaultMetric                int
	SPFTimers                    string
	BFD                          string
	LogNeighbourChanges          string
	Redistribute                 []RouteRedistribute
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

// ServiceCategory represents a FortiGate firewall service category.
type ServiceCategory struct {
	Name    string
	Comment string
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
	Name        string
	ExtIP       string
	MappedIP    string
	ExtIntf     string
	PortForward bool
	ExtPort     string
	MappedPort  string
	Protocol    string // "tcp", "udp", "sctp", "icmp"
	Comment     string
	Color       int
}

// IPv6VirtualIP represents a FortiGate IPv6 virtual IP.
type IPv6VirtualIP struct {
	Name        string
	ExtIP       string
	MappedIP    string
	ExtIntf     string
	PortForward bool
	ExtPort     string
	MappedPort  string
	Protocol    string // "tcp", "udp", "sctp", "icmp"
	Comment     string
	Color       int
}

// VirtualIPGroup represents a FortiGate virtual IP group.
type VirtualIPGroup struct {
	Name    string
	Members []string
	Comment string
	Color   int
}

// IPv6VirtualIPGroup represents a FortiGate IPv6 virtual IP group.
type IPv6VirtualIPGroup struct {
	Name    string
	Members []string
	Comment string
	Color   int
}

// IPPool represents a FortiGate IP pool (SNAT).
type IPPool struct {
	Name          string
	Type          string // "overload", "one-to-one", "fixed-port-range", "port-block-allocation"
	StartIP       string
	EndIP         string
	SourceStartIP string
	SourceEndIP   string
	Comment       string
	Color         int
}

// IPv6IPPool represents a FortiGate IPv6 IP pool.
type IPv6IPPool struct {
	Name    string
	Type    string
	StartIP string
	EndIP   string
	Comment string
	Color   int
}

// RecurringSchedule represents a recurring firewall schedule.
type RecurringSchedule struct {
	Name  string
	Days  []string
	Start string
	End   string
	Color int
}

// OneTimeSchedule represents a one-time firewall schedule.
type OneTimeSchedule struct {
	Name     string
	Start    string
	End      string
	StartUTC int
	EndUTC   int
	Color    int
}

// ScheduleGroup represents a firewall schedule group.
type ScheduleGroup struct {
	Name    string
	Members []string
	Color   int
}

// IPsecPhase1 represents an IPsec phase 1 interface configuration.
type IPsecPhase1 struct {
	Name          string
	Type          string
	Interface     string
	IPVersion     string
	IKEVersion    string
	LocalGateway  string
	RemoteGateway string
	RemoteGWDDNS  string
	AuthMethod    string
	Mode          string
	PeerType      string
	Proposal      string
	DHGroups      string
	AddRoute      string
	AutoNegotiate string
	DPD           string
	NATTraversal  string
	NetDevice     string
	Distance      int
	Priority      int
	KeyLife       int
	Comment       string
	WizardType    string
}

// IPsecPhase2 represents an IPsec phase 2 interface configuration.
type IPsecPhase2 struct {
	Name           string
	Phase1Name     string
	Proposal       string
	PFS            string
	DHGroups       string
	Replay         string
	AutoNegotiate  string
	AddRoute       string
	KeyLifeSeconds int
	KeyLifeKB      int
	KeyLifeType    string
	Protocol       int
	SrcName        string
	SrcSubnet      string
	SrcPort        int
	DstName        string
	DstSubnet      string
	DstPort        int
	Comment        string
}

// SSLVPNPortal represents an SSL VPN web portal.
type SSLVPNPortal struct {
	Name            string
	TunnelMode      string
	WebMode         string
	IPMode          string
	AutoConnect     string
	KeepAlive       string
	SavePassword    string
	IPPools         []string
	IPv6Pools       []string
	SplitTunneling  string
	DNSServer1      string
	DNSServer2      string
	DNSSuffix       string
	AllowUserAccess string
	Theme           string
	Heading         string
	LimitUserLogins string
	UseSDWAN        string
	PreferIPv6DNS   string
}

// SSLVPNSettings represents top-level SSL VPN settings.
type SSLVPNSettings struct {
	Status                 string
	RequireClientCert      string
	SSLMinProtoVersion     string
	SSLMaxProtoVersion     string
	ServerCert             string
	Algorithm              string
	IdleTimeout            int
	AuthTimeout            int
	LoginAttemptLimit      int
	LoginBlockTime         int
	Port                   int
	TunnelIPPools          []string
	TunnelIPv6Pools        []string
	SourceInterfaces       []string
	SourceAddresses        []string
	SourceAddressNegate    string
	DefaultPortal          string
	DTLSTunnel             string
	CheckReferer           string
	DualStackMode          string
	TunnelAddrAssignMethod string
	ServerHostname         string
}

// LocalUser represents a local user account without password material.
type LocalUser struct {
	Name                    string
	ID                      int
	Status                  string
	Type                    string
	LDAPServer              string
	RadiusServer            string
	TACACSServer            string
	TwoFactor               string
	TwoFactorAuthentication string
	TwoFactorNotification   string
	FortiToken              string
	EmailTo                 string
	SMSPhone                string
	PasswordPolicy          string
	PasswordTime            string
	AuthTimeout             int
	UsernameSensitivity     string
}

// UserGroup represents a FortiGate user group.
type UserGroup struct {
	Name              string
	ID                int
	Type              string
	Members           []string
	AuthTimeout       int
	ConcurrentMode    string
	ConcurrentValue   int
	SSOAttributeValue string
	ExpireType        string
	Expire            int
}

// RemoteAuthServer represents an LDAP, RADIUS, or TACACS+ authentication server.
type RemoteAuthServer struct {
	Name                  string
	Type                  string
	Server                string
	SecondaryServer       string
	TertiaryServer        string
	Timeout               int
	AuthType              string
	SourceIP              string
	InterfaceSelectMethod string
	Interface             string
}

// LocalCertificate represents local certificate metadata without key/certificate bodies.
type LocalCertificate struct {
	Name                      string
	Comment                   string
	State                     string
	Range                     string
	Source                    string
	LastUpdated               int
	EnrollProtocol            string
	PrivateKeyRetain          string
	AutoRegenerateDays        int
	AutoRegenerateDaysWarning int
	ACMEDomain                string
	ACMEEmail                 string
}

// CACertificate represents CA certificate metadata without certificate bodies.
type CACertificate struct {
	Name                  string
	Range                 string
	Source                string
	SSLInspectionTrusted  string
	SCEPURL               string
	AutoUpdateDays        int
	AutoUpdateDaysWarning int
	SourceIP              string
	CAIdentifier          string
	LastUpdated           int
	Obsolete              string
}

// CRLCertificate represents certificate revocation list metadata.
type CRLCertificate struct {
	Name    string
	Source  string
	Comment string
}

// RemoteCertificate represents remote certificate metadata without certificate bodies.
type RemoteCertificate struct {
	Name    string
	Source  string
	Comment string
}

// SystemStatus represents monitor system status metadata.
type SystemStatus struct {
	ModelName     string
	ModelNumber   string
	Model         string
	Hostname      string
	LogDiskStatus string
}

// MonitorPolicyStats represents firewall policy runtime counters.
type MonitorPolicyStats struct {
	PolicyID         int
	ActiveSessions   int
	Bytes            int64
	Packets          int64
	SoftwareBytes    int64
	SoftwarePackets  int64
	ASICBytes        int64
	ASICPackets      int64
	HitCount         int64
	SessionCount     int
	LastUsed         int64
	FirstUsed        int64
	SessionLastUsed  int64
	SessionFirstUsed int64
}

// MonitorRoute represents a runtime routing-table entry.
type MonitorRoute struct {
	IPVersion    int
	Type         string
	IPMask       string
	Distance     int
	Metric       int
	Priority     int
	VRF          int
	Gateway      string
	NonRCGateway string
	Interface    string
}

// MonitorIPsecTunnel represents runtime IPsec tunnel counters.
type MonitorIPsecTunnel struct {
	Name            string
	Comment         string
	WizardType      string
	ConnectionCount int
	CreationTime    int64
	Username        string
	Type            string
	IncomingBytes   int64
	OutgoingBytes   int64
	RemoteGateway   string
	TunnelID        string
	TunnelID6       string
}

// MonitorSSLTunnel represents a runtime SSL VPN tunnel/session summary.
type MonitorSSLTunnel struct {
	Name          string
	Username      string
	RemoteAddress string
	IncomingBytes int64
	OutgoingBytes int64
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
