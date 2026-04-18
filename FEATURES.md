# fortigate — Go SDK features

A Go client for the FortiGate REST API v2. Designed for read-heavy inventory
and reporting tooling; all exposed operations are currently `List*` / `Get*`.

## Authentication & session

- Username + password login via `POST /logincheck` with URL-encoded form.
- Session stored in a cookie jar; CSRF token extracted from `ccsrftoken*`
  cookie (supports both bare `ccsrftoken` and `ccsrftoken_{port}_{hash}`
  forms, and strips surrounding quotes).
- Rejects the unauthenticated sentinel token `0000000000000000` as `ErrAuth`.
- Transparent re-login: if the device returns 401 mid-request, the client
  re-authenticates once and retries the original call, so long-running
  tools don't need to handle `ErrSessionExpired` themselves.
- `Logout` clears the CSRF token even on network errors; safe to call
  multiple times.

## TLS

- `WithInsecureTLS()` disables certificate verification (appliance with a
  self-signed cert).
- `WithX509NegativeSerial()` sets the Go `x509negativeserial=1` GODEBUG
  flag for FortiGate certificates with negative serial numbers.
- TLS errors surface as `ErrCertificate` (via `errors.Is`) so callers can
  distinguish them from generic transport failures.
- `WithTransport` and `WithHTTPClient` let callers inject their own HTTP
  plumbing (proxies, mTLS, retries). Precedence: `WithHTTPClient` beats
  `WithTransport` beats the default.

## VDOMs

- `ListVDOMs(ctx)` against `/api/v2/cmdb/system/vdom`; no VDOM param
  required. Use the result to auto-discover VDOMs rather than hard-coding
  `"root"`.
- Every per-VDOM list method validates the VDOM name (alphanumeric,
  `-`, `_`, `.` only) to prevent query-param injection.

## Resources

Every list endpoint is VDOM-scoped and paginated. IP/mask fields are
normalized to CIDR at the SDK boundary.

| Method | Endpoint | Type |
|---|---|---|
| `ListAddresses` | `firewall/address` | `Address` |
| `ListAddressGroups` | `firewall/addrgrp` | `AddressGroup` |
| `ListIPv6Addresses` | `firewall/address6` | `IPv6Address` |
| `ListIPv6AddressGroups` | `firewall/addrgrp6` | `IPv6AddressGroup` |
| `ListPolicies` | `firewall/policy` | `Policy` |
| `ListInterfaces` | `system/interface` | `Interface` |
| `ListZones` | `system/zone` | `Zone` |
| `GetDNSSettings` | `system/dns` | `DNSSettings` |
| `ListDNSServers` | `system/dns-server` | `DNSServer` |
| `ListDHCPServers` | `system.dhcp/server` | `DHCPServer` |
| `ListDHCPv6Servers` | `system.dhcp6/server` | `DHCPv6Server` |
| `GetSDWANSettings` | `system/sdwan` | `SDWANSettings` |
| `ListSDWANMembers` | `system/sdwan/members` | `SDWANMember` |
| `ListSDWANZones` | `system/sdwan/zone` | `SDWANZone` |
| `ListStaticRoutes` | `router/static` | `StaticRoute` |
| `ListIPv6StaticRoutes` | `router/static6` | `IPv6StaticRoute` |
| `ListPolicyRoutes` | `router/policy` | `PolicyRoute` |
| `ListIPv6PolicyRoutes` | `router/policy6` | `IPv6PolicyRoute` |
| `ListRouteMaps` | `router/route-map` | `RouteMap` |
| `ListAccessLists` | `router/access-list` | `AccessList` |
| `ListIPv6AccessLists` | `router/access-list6` | `IPv6AccessList` |
| `ListPrefixLists` | `router/prefix-list` | `PrefixList` |
| `ListIPv6PrefixLists` | `router/prefix-list6` | `IPv6PrefixList` |
| `ListASPathLists` | `router/aspath-list` | `ASPathList` |
| `ListCommunityLists` | `router/community-list` | `CommunityList` |
| `GetBGPSettings` | `router/bgp` | `BGPSettings` |
| `GetOSPFSettings` | `router/ospf` | `OSPFSettings` |
| `GetOSPFv6Settings` | `router/ospf6` | `OSPFv6Settings` |
| `ListIPsecPhase1s` | `vpn.ipsec/phase1-interface` | `IPsecPhase1` |
| `ListIPsecPhase2s` | `vpn.ipsec/phase2-interface` | `IPsecPhase2` |
| `ListSSLVPNPortals` | `vpn.ssl.web/portal` | `SSLVPNPortal` |
| `GetSSLVPNSettings` | `vpn.ssl/settings` | `SSLVPNSettings` |
| `ListLocalUsers` | `user/local` | `LocalUser` |
| `ListUserGroups` | `user/group` | `UserGroup` |
| `ListLDAPServers` | `user/ldap` | `RemoteAuthServer` |
| `ListRadiusServers` | `user/radius` | `RemoteAuthServer` |
| `ListTACACSServers` | `user/tacacs+` | `RemoteAuthServer` |
| `ListLocalCertificates` | `vpn.certificate/local` | `LocalCertificate` |
| `ListCACertificates` | `vpn.certificate/ca` | `CACertificate` |
| `ListCRLCertificates` | `vpn.certificate/crl` | `CRLCertificate` |
| `ListRemoteCertificates` | `vpn.certificate/remote` | `RemoteCertificate` |
| `GetSystemStatus` | `monitor/system/status` | `SystemStatus` |
| `ListMonitorPolicyStats` | `monitor/firewall/policy` | `MonitorPolicyStats` |
| `ListMonitorRoutes` | `monitor/router/ipv4` | `MonitorRoute` |
| `ListMonitorIPsecTunnels` | `monitor/vpn/ipsec` | `MonitorIPsecTunnel` |
| `ListMonitorSSLTunnels` | `monitor/vpn/ssl` | `MonitorSSLTunnel` |
| `ListServices` | `firewall.service/custom` | `Service` |
| `ListServiceGroups` | `firewall.service/group` | `ServiceGroup` |
| `ListServiceCategories` | `firewall.service/category` | `ServiceCategory` |
| `ListRecurringSchedules` | `firewall.schedule/recurring` | `RecurringSchedule` |
| `ListOneTimeSchedules` | `firewall.schedule/onetime` | `OneTimeSchedule` |
| `ListScheduleGroups` | `firewall.schedule/group` | `ScheduleGroup` |
| `ListVirtualIPs` | `firewall/vip` | `VirtualIP` |
| `ListIPv6VirtualIPs` | `firewall/vip6` | `IPv6VirtualIP` |
| `ListVirtualIPGroups` | `firewall/vipgrp` | `VirtualIPGroup` |
| `ListIPv6VirtualIPGroups` | `firewall/vipgrp6` | `IPv6VirtualIPGroup` |
| `ListIPPools` | `firewall/ippool` | `IPPool` |
| `ListIPv6IPPools` | `firewall/ippool6` | `IPv6IPPool` |
| `ListVDOMs` | `system/vdom` | `VDOM` |
| `GetSystemInfo` | `system/global` | `SystemInfo` |

### Parsing & normalization applied by the SDK

- `spaceSubnetToCIDR` — `"192.0.2.0 255.255.255.0"` → `"192.0.2.0/24"`;
  `/32` host masks stripped; invalid masks pass through unchanged.
- `zeroIPToEmpty` — `"0.0.0.0"` and `"0.0.0.0/0"` become empty strings
  (FortiGate uses them for unnumbered interfaces).
- `namesOf` — flattens reference arrays (`[{name: "x"}, ...]`) into
  `[]string` for policy/group members.
- `isEnabled` — maps the raw `"enable"/"disable"` strings to Go `bool`
  (currently used for policy `NATEnabled` and VIP `PortForward`).
- `vipMappedIP` — joins VirtualIP `mappedip` range entries with commas,
  since the API returns them as `[{range: "..."}]` objects.
- `splitAllowAccess` — parses the space-separated interface
  `allowaccess` string into `[]string`.
- Sensitive config material returned by FortiGate, such as shared secrets,
  passwords, private keys, and certificate bodies, is intentionally omitted
  from public SDK models. Ignored raw captures can be used for local
  comparison when needed.
- Recurring schedule `day` values are accepted as either FortiGate's
  space-separated string form or a JSON string array and returned as `[]string`.
- Static route `Dst` is converted from `"192.0.2.0 255.255.255.0"` to CIDR.
- `SystemInfo.Timezone` is intentionally a `string` — FortiGate returns
  `"53"`, not an integer.

## Typed enum constants

`enums.go` exports named constants for every enum field the SDK returns
so consumers can switch or filter without stringly-typed literals:

- Address types (`ipmask`, `iprange`, `fqdn`, …)
- Policy actions (`accept`, `deny`, `ipsec`) and log-traffic modes
- Enable/disable status (used across many fields)
- Interface types / roles / modes / operational status
- Service protocol categories (`TCP/UDP/SCTP`, `ICMP`, `IP`, `ICMP6`)
- VIP protocols and IP pool types
- VDOM operating modes (`nat`, `transparent`)

## Pagination

- `?start=N&count=pageSize` against every list endpoint.
- Default page size is 1000; override per call with `WithPageSize(n)`
  (valid range 1..10000).
- `WithPageCallback(func(fetched, page int))` fires after each page —
  use it for progress bars or cancellation.
- Terminates on short page, over-large page (endpoint ignored range),
  exact-multiple boundary (one empty probe), or a 10000-iteration
  safety cap.
- Transparent re-login works mid-pagination: if a page fails with 401,
  the client re-authenticates and re-issues that same page before
  continuing.

## Errors

Sentinel errors for `errors.Is` matching:

- `ErrAuth` — login failed or device returned the zero CSRF token
- `ErrPermission` — 403 from the API after login
- `ErrCertificate` — TLS verification failure
- `ErrNotLoggedIn` — called a list method without `Login()` first
- `ErrNotFound` — 404 for the requested resource
- `ErrInvalidName` — rejected unsafe VDOM name
- `ErrSessionExpired` — 401 mid-request (usually auto-retried)

Non-sentinel failures surface as `*APIError{HTTPStatus, Code, Message}`
with the full envelope from the device.

## Client options

| Option | Purpose |
|---|---|
| `WithCredentials(user, pass)` | **required** — session auth |
| `WithInsecureTLS()` | skip TLS verification |
| `WithTimeout(d)` | HTTP client timeout (default 30s) |
| `WithTransport(rt)` | custom RoundTripper (proxies, etc.) |
| `WithHTTPClient(hc)` | replace the entire HTTP client |
| `WithUserAgent(ua)` | override User-Agent header |
| `WithX509NegativeSerial()` | enable Go's x509negativeserial GODEBUG |

## Testing

- Unit tests use an `httptest` mock that validates the `X-CSRFTOKEN`
  header on every API request (matches real device behavior).
- The mock exposes knobs to trigger mid-request session expiry
  (`expireOnce`, `expireAfter`) so re-login paths are covered.
- Pagination boundary cases (exact multiple of page size, mid-pagination
  expiry) are exercised by `TestPagination` and `TestAutoRelogin`.
- All tests use RFC 5737 documentation IP ranges (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`) — no real device data in the
  source tree.
- A `//go:build ignore` smoke test in `smoke.go` connects to a real
  device (credentials in `.fortigate.json` or `FORTIGATE_*` env vars,
  both gitignored) and exercises every list method end-to-end.
