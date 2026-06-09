# Plan

Development roadmap for fortigate.

## Phase 1: Core Client - Done

| Component | Description |
|-----------|-------------|
| HTTP client | TLS configuration, cookie jar, timeout, custom transport/client support |
| Session management | Login cookie handling and CSRF token extraction |
| Login / Logout | Explicit session lifecycle |
| REST transport | `/api/v2/cmdb` and `/api/v2/monitor` GET handling |
| Response unwrapping | `http_status`, `error`, `message`, and `results` validation |
| Auto-relogin | Retry once on session expiry |
| Functional options | Credentials, TLS, timeout, transport, HTTP client, user agent, X.509 compatibility |

## Phase 2: Resource Methods - Done

### System

| Method | Description |
|--------|-------------|
| `GetSystemInfo()` | System-global settings |
| `GetSystemStatus(vdom)` | Runtime system status |
| `ListVDOMs()` | Virtual domains |

### Network

| Method | Description |
|--------|-------------|
| `ListInterfaces(vdom)` | Network interfaces |
| `ListZones(vdom)` | Zone objects |
| `GetDNSSettings()` | Global DNS settings |
| `ListDNSServers(vdom)` | DNS server entries |
| `ListDHCPServers(vdom)` | DHCP server entries |
| `ListDHCPv6Servers(vdom)` | DHCPv6 server entries |
| `GetSDWANSettings(vdom)` | SD-WAN settings |
| `ListSDWANMembers(vdom)` / `ListSDWANZones(vdom)` | SD-WAN inventory |

### Routing

| Method | Description |
|--------|-------------|
| `ListStaticRoutes(vdom)` / `ListIPv6StaticRoutes(vdom)` | Static routing |
| `ListPolicyRoutes(vdom)` / `ListIPv6PolicyRoutes(vdom)` | Policy routing |
| `ListRouteMaps(vdom)` | Route maps |
| `ListAccessLists(vdom)` / `ListIPv6AccessLists(vdom)` | Access lists |
| `ListPrefixLists(vdom)` / `ListIPv6PrefixLists(vdom)` | Prefix lists |
| `ListASPathLists(vdom)` | AS path lists |
| `ListCommunityLists(vdom)` | Community lists |
| `GetBGPSettings(vdom)` | BGP settings |
| `GetOSPFSettings(vdom)` / `GetOSPFv6Settings(vdom)` | OSPF settings |

### Firewall Policy and Objects

| Method | Description |
|--------|-------------|
| `ListPolicies(vdom)` | Firewall policies |
| `ListAddresses(vdom)` / `ListIPv6Addresses(vdom)` | Address objects |
| `ListAddressGroups(vdom)` / `ListIPv6AddressGroups(vdom)` | Address groups |
| `ListServices(vdom)` | Custom services |
| `ListServiceGroups(vdom)` | Service groups |
| `ListServiceCategories(vdom)` | Service categories |
| `ListRecurringSchedules(vdom)` / `ListOneTimeSchedules(vdom)` | Schedule objects |
| `ListScheduleGroups(vdom)` | Schedule groups |
| `ListVirtualIPs(vdom)` / `ListIPv6VirtualIPs(vdom)` | Virtual IP objects |
| `ListVirtualIPGroups(vdom)` / `ListIPv6VirtualIPGroups(vdom)` | Virtual IP groups |
| `ListIPPools(vdom)` / `ListIPv6IPPools(vdom)` | IP pool objects |

### User, VPN, Certificates, and Monitoring

| Method | Description |
|--------|-------------|
| `ListLocalUsers(vdom)` | Local users |
| `ListUserGroups(vdom)` | User groups |
| `ListLDAPServers(vdom)` / `ListRadiusServers(vdom)` / `ListTACACSServers(vdom)` | Remote auth servers |
| `ListIPsecPhase1s(vdom)` / `ListIPsecPhase2s(vdom)` | IPsec objects |
| `ListSSLVPNPortals(vdom)` / `GetSSLVPNSettings(vdom)` | SSL VPN configuration |
| `ListLocalCertificates(vdom)` / `ListCACertificates(vdom)` / `ListCRLCertificates(vdom)` / `ListRemoteCertificates(vdom)` | Certificate inventory |
| `ListMonitorPolicyStats(vdom)` / `ListMonitorRoutes(vdom)` | Monitor data |
| `ListMonitorIPsecTunnels(vdom)` / `ListMonitorSSLTunnels(vdom)` | VPN tunnel monitor data |

## Phase 3: Quality - Done

| Task | Description |
|------|-------------|
| Unit tests | httptest-based mock FortiGate server |
| Pagination tests | Boundary, exact-multiple, and callback behavior |
| Session tests | Login, logout, invalid auth, and auto-relogin |
| Conversion tests | IP, enum, schedule, and reference normalization |
| Smoke test | Live FortiGate test with ignored local config |
| Sensitive-field handling | Public models omit secrets, private keys, passwords, and certificate bodies |

## Phase 4: Future

Candidates to add only when needed:

| Resource | Category |
|----------|----------|
| HA detail/status | System |
| Firmware inventory | System |
| Hardware sensor inventory | Monitoring |
| FortiGuard/license status | Monitoring |
| Log fetch | Logging |
| Web filter/application/IPS profiles | Security profiles |

## Non-Goals

| Scope | Reason |
|-------|--------|
| Write operations | Read-only SDK for inventory and audit workflows |
| FortiManager API | Separate project |
| FortiAnalyzer API | Separate project |
| Full FortiOS API parity | Add resources based on concrete reporting use cases |
