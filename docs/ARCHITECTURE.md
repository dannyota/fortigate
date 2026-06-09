# Architecture

Go SDK for FortiGate's REST API v2. The package is intentionally flat and
read-only: it targets inventory, audit, and reporting workflows.

## REST Protocol

### Authentication

FortiGate uses session authentication for the web/REST flow implemented here.

| Step | Endpoint | Details |
|------|----------|---------|
| Login | `POST /logincheck` | URL-encoded `username`, `secretkey`, `ajax=1` |
| Token | Login response cookies | `ccsrftoken` or `ccsrftoken_{port}_{hash}` |
| Requests | `X-CSRFTOKEN` header | CSRF token stripped of surrounding quotes |
| Logout | `POST /logout` | Clears the local token even if the request fails |

The unauthenticated sentinel token `0000000000000000` is rejected as
`ErrAuth`.

### API Endpoints

Most configuration resources use CMDB paths under `/api/v2/cmdb/` with a VDOM
query parameter. Runtime/monitoring resources use `/api/v2/monitor/`.

```http
GET /api/v2/cmdb/firewall/address?vdom=root&start=0&count=1000
X-CSRFTOKEN: <token>
```

Typical response envelope:

```json
{
  "http_status": 200,
  "status": "success",
  "results": []
}
```

`results` can be either an array for list endpoints or an object for singleton
endpoints such as system-global settings.

### Error Mapping

| Condition | SDK Error |
|-----------|-----------|
| Login failed or zero CSRF token | `ErrAuth` |
| 401 mid-request | `ErrSessionExpired`, then one automatic re-login retry |
| 403 | `ErrPermission` |
| 404 | `ErrNotFound` |
| TLS certificate verification failure | `ErrCertificate` |
| Unsafe VDOM name | `ErrInvalidName` |
| Other non-200 API result | `*APIError` |

### Pagination

List endpoints use `start` and `count` query parameters. The SDK fetches pages
until a page returns fewer rows than requested. If an endpoint ignores the range
and returns a non-page-sized result, the SDK stops rather than looping. A
10000-page safety cap guards against broken appliance behavior.

## Package Layout

```text
danny.vn/fortigate/
|-- client.go          # Client, NewClient, Login, Logout, Close
|-- option.go          # Client and list options
|-- request.go         # GET transport, pagination, re-login
|-- response.go        # REST envelope validation
|-- errors.go          # Sentinel errors and APIError
|-- types.go           # Public domain types
|-- enums.go           # Public enum constants
|-- convert.go         # IP, enum, schedule, and reference conversion helpers
|
|-- address.go         # Address and address group resources
|-- policy.go          # Firewall policies
|-- interface.go       # Interfaces
|-- network.go         # Zones, DNS, DHCP, SD-WAN
|-- route.go           # Routes, route maps, BGP, OSPF
|-- service.go         # Service objects
|-- schedule.go        # Schedule objects
|-- virtualip.go       # Virtual IP objects
|-- ippool.go          # IP pool objects
|-- user.go            # Users and auth servers
|-- vpn.go             # IPsec and SSL VPN
|-- certificate.go     # Certificate inventory
|-- monitor.go         # Monitor endpoints
|-- system.go          # System-global settings
|-- vdom.go            # VDOM inventory
|
|-- testhelper_test.go # Shared httptest FortiGate mock
|-- *_test.go          # Unit tests
|-- smoke.go           # Live smoke test, build-tag ignored
```

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Flat package | Single FortiGate client surface with no subpackage ceremony |
| Explicit Login/Logout | No hidden network calls during construction |
| Read-only | Inventory/audit workflows avoid risky undocumented write behavior |
| VDOM validation | Prevent query-parameter injection through VDOM names |
| Generic unmarshalling helpers | Keep resource methods small and type-safe |
| Public clean models | Hide appliance response quirks behind conversion helpers |
| Sentinel errors | Allow callers to use `errors.Is` for common failure classes |
| Transparent pagination | Avoid silent truncation on large policies or object tables |
| Sensitive-field omission | Avoid exposing secrets, keys, password hashes, or certificate bodies |

## TLS

| Issue | Solution |
|-------|----------|
| Self-signed appliance certificate | `WithInsecureTLS()` |
| Negative X.509 serial number | `WithX509NegativeSerial()` |
| Custom transport, proxy, or mTLS | `WithTransport()` or `WithHTTPClient()` |

`WithHTTPClient` takes precedence over `WithTransport`; `WithTransport` takes
precedence over the default client.
