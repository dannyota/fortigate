# Features

A Go client for the FortiGate REST API v2. Designed for read-heavy inventory
and reporting tooling; all exposed operations are currently `List*` / `Get*`.

## Authentication & Session

- Username + password login via `POST /logincheck` with URL-encoded form.
- Session stored in a cookie jar; CSRF token extracted from `ccsrftoken*`
  cookie forms and stripped of surrounding quotes.
- Rejects the unauthenticated sentinel token `0000000000000000` as `ErrAuth`.
- Transparent re-login: if the device returns 401 mid-request, the client
  re-authenticates once and retries the original call.
- `Logout` clears the CSRF token even on network errors; safe to call multiple
  times.

## TLS

- `WithInsecureTLS()` disables certificate verification for appliances with
  self-signed certificates.
- `WithX509NegativeSerial()` sets the Go `x509negativeserial=1` GODEBUG flag
  for FortiGate certificates with negative serial numbers.
- TLS errors surface as `ErrCertificate` through `errors.Is`.
- `WithTransport` and `WithHTTPClient` let callers inject their own HTTP
  plumbing. Precedence: `WithHTTPClient` beats `WithTransport` beats the
  default.

## VDOMs

- `ListVDOMs(ctx)` reads `/api/v2/cmdb/system/vdom`; no VDOM parameter is
  required.
- Every per-VDOM list method validates the VDOM name (alphanumeric, `-`, `_`,
  `.` only) to prevent query-parameter injection.

## Resources

Every list endpoint is VDOM-scoped and paginated unless noted. IP/mask fields
are normalized to CIDR at the SDK boundary.

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

## Parsing & Normalization

- `spaceSubnetToCIDR` converts FortiGate space-mask strings to CIDR and strips
  `/32` host masks.
- `zeroIPToEmpty` turns FortiGate unnumbered placeholders into empty strings.
- `namesOf` flattens reference arrays into `[]string` for policy and group
  members.
- `isEnabled` maps raw `enable` / `disable` strings to Go `bool`.
- `vipMappedIP` joins VirtualIP `mappedip` range entries.
- `splitAllowAccess` parses interface `allowaccess` into `[]string`.
- Sensitive config material returned by FortiGate, such as shared secrets,
  passwords, private keys, and certificate bodies, is intentionally omitted
  from public SDK models.
- Recurring schedule `day` values are accepted as either FortiGate's
  space-separated string form or a JSON string array and returned as
  `[]string`.
- Static route destinations are converted from space-mask notation to CIDR.
- `SystemInfo.Timezone` is intentionally a `string`; FortiGate returns it as a
  numeric string.

## Typed Enum Constants

`enums.go` exports named constants for every enum field the SDK returns so
consumers can switch or filter without stringly typed literals:

- Address types (`ipmask`, `iprange`, `fqdn`, and related values).
- Policy actions and log-traffic modes.
- Enable/disable status values.
- Interface types, roles, modes, and operational status.
- Service protocol categories.
- VIP protocols and IP pool types.
- VDOM operating modes.

## Pagination

- `?start=N&count=pageSize` against every list endpoint.
- Default page size is 1000; override per call with `WithPageSize(n)`.
- Valid page-size range is 1..10000.
- `WithPageCallback(func(fetched, page int))` fires after each page.
- The paginator terminates on short page, over-large page, exact-multiple
  boundary after an empty probe, or a 10000-iteration safety cap.
- Transparent re-login works mid-pagination: if a page fails with 401, the
  client re-authenticates and re-issues that page before continuing.

## Errors

Sentinel errors for `errors.Is` matching:

- `ErrAuth` - login failed or device returned the zero CSRF token.
- `ErrPermission` - 403 from the API after login.
- `ErrCertificate` - TLS verification failure.
- `ErrNotLoggedIn` - called a list method without `Login()` first.
- `ErrNotFound` - 404 for the requested resource.
- `ErrInvalidName` - rejected unsafe VDOM name.
- `ErrSessionExpired` - 401 mid-request, usually auto-retried.

Non-sentinel failures surface as `*APIError{HTTPStatus, Code, Message}`.

## Client Options

| Option | Purpose |
|---|---|
| `WithCredentials(user, pass)` | Required session auth |
| `WithInsecureTLS()` | Skip TLS verification |
| `WithTimeout(d)` | HTTP client timeout, default 30s |
| `WithTransport(rt)` | Custom RoundTripper |
| `WithHTTPClient(hc)` | Replace the entire HTTP client |
| `WithUserAgent(ua)` | Override User-Agent header |
| `WithX509NegativeSerial()` | Enable Go's x509negativeserial GODEBUG |

## Testing

- Unit tests use an `httptest` mock that validates the `X-CSRFTOKEN` header on
  every API request.
- The mock exposes knobs to trigger mid-request session expiry so re-login
  paths are covered.
- Pagination boundary cases are exercised by `TestPagination` and
  `TestAutoRelogin`.
- Tests use documentation IP ranges and do not require real device data.
- `smoke.go` connects to a real device using `.fortigate.json` or
  `FORTIGATE_*` environment variables. Local config and captured samples are
  gitignored.
