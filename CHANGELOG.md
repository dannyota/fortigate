# Changelog

## v0.2.1

Repository hygiene release.

### Added

- MIT license file for GitHub and Go documentation license detection.
- README with install, quick start, supported resources, testing, and known
  issues.
- Documentation under `docs/` for architecture, feature coverage, and roadmap.
- Top-level `FEATURES.md` compatibility pointer to `docs/FEATURES.md`.

## v0.2.0

Expanded read-only FortiGate inventory coverage. All additions are
backwards-compatible with v0.1.0 consumers.

### Added

- IPv6 firewall address, address group, virtual IP, and IP pool resources.
- Network inventory for zones, DNS, DHCP, and SD-WAN.
- Routing inventory for static routes, IPv6 routes, policy routes, route maps,
  access lists, prefix lists, AS path lists, community lists, BGP, OSPF, and
  OSPFv6.
- VPN inventory for IPsec phase 1/phase 2, SSL VPN portals, and SSL VPN
  settings.
- User and authentication inventory for local users, groups, LDAP, RADIUS, and
  TACACS+ servers.
- Certificate inventory for local, CA, CRL, and remote certificates.
- Monitor endpoints for system status, policy stats, routes, IPsec tunnels, and
  SSL VPN tunnels.
- Typed enum constants for common FortiOS values.
- Live smoke-test configuration via `.fortigate.json` or `FORTIGATE_*`
  environment variables.

### Changed

- List methods consistently use transparent pagination with per-call page size
  and progress callback options.
- Public models intentionally omit sensitive config material such as secrets,
  passwords, private keys, and certificate bodies.

## v0.1.0

Initial read-only Go SDK for FortiGate REST API v2.

### Added

- Session login/logout with cookie jar and CSRF token extraction.
- Transparent one-time re-login when a session expires mid-request.
- Functional client options for credentials, TLS behavior, timeouts, custom
  transports, custom HTTP clients, user agent, and negative X.509 serial
  support.
- Sentinel errors for authentication, permission, certificate, login state,
  not-found, invalid VDOM names, and expired sessions.
- Core inventory methods for VDOMs, addresses, policies, interfaces, services,
  schedules, virtual IPs, IP pools, system info, and selected VPN resources.
- httptest-based unit coverage for client/session behavior, pagination,
  conversions, and resource mapping.
