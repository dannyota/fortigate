# fortigate

Unofficial Go SDK for the FortiGate REST API v2.

> Use at your own risk. FortiGate appliances expose REST behavior that can vary
> by FortiOS version, enabled features, VDOM mode, and administrator profile.
> Fortinet does not support or endorse this library.

## When to Use

| Scenario | Recommendation |
|----------|----------------|
| Official Fortinet API docs and support are available | Prefer the official API contract |
| Read-heavy inventory, audit, or reporting tooling | This SDK is a fit |
| Write operations needed | Not supported by this SDK |
| Direct FortiManager inventory needed | Use `danny.vn/fortimgr` instead |

## Install

```bash
go get danny.vn/fortigate
```

Requires Go 1.24+.

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"

	"danny.vn/fortigate"
)

func main() {
	client, err := fortigate.NewClient("https://fortigate.example.com",
		fortigate.WithCredentials("admin", "password"),
		fortigate.WithInsecureTLS(), // self-signed appliance certificate
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()
	if err := client.Login(ctx); err != nil {
		log.Fatal(err)
	}

	vdoms, err := client.ListVDOMs(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if len(vdoms) == 0 {
		log.Fatal("no VDOMs found")
	}

	addrs, err := client.ListAddresses(ctx, vdoms[0].Name)
	if err != nil {
		log.Fatal(err)
	}
	for _, addr := range addrs {
		fmt.Printf("%s %s %s\n", addr.Name, addr.Type, addr.Subnet)
	}
}
```

## Supported Resources

See [FEATURES](docs/FEATURES.md) for the full method and endpoint matrix.

| Category | Resources | Count |
|----------|-----------|:-----:|
| System | System info, runtime system status, VDOMs | 3 |
| Network | Interfaces, zones, DNS, DHCP, SD-WAN | 8 |
| Routing | Static routes, policy routes, route maps, access lists, prefix lists, BGP, OSPF | 14 |
| Firewall Policy | Policies, policy monitor stats | 2 |
| Firewall Objects | Address/VIP/IP pool IPv4+IPv6, services, schedules | 22 |
| User & Auth | Local users, groups, LDAP, RADIUS, TACACS+ | 5 |
| VPN | IPsec, SSL VPN portals/settings, monitor tunnels | 6 |
| Certificates | Local, CA, CRL, remote certificates | 4 |

## Pagination

List methods fetch all pages transparently with `?start=N&count=pageSize`.
The default page size is 1000 rows. Override per call:

```go
policies, err := client.ListPolicies(ctx, "root",
	fortigate.WithPageSize(500),
	fortigate.WithPageCallback(func(fetched, page int) {
		log.Printf("fetched %d policies after page %d", fetched, page)
	}),
)
```

## Testing

```bash
go test ./...
```

Smoke test against a live FortiGate:

```bash
FORTIGATE_ADDRESS=https://fortigate.example.com \
FORTIGATE_USERNAME=admin \
FORTIGATE_PASSWORD=secret \
FORTIGATE_VDOM=root \
go run smoke.go
```

The smoke test can also read `.fortigate.json`; copy the shape from
[`.fortigate.json.example`](.fortigate.json.example). The real config file and
captured samples are gitignored because they may contain local environment
data.

## Known Issues

| Issue | Workaround |
|-------|------------|
| Self-signed appliance certificates | Use `WithInsecureTLS()` |
| Non-RFC 5280 certificates with negative serial numbers | Use `WithX509NegativeSerial()` |
| VDOM-scoped resources require a VDOM query parameter | Discover VDOMs with `ListVDOMs()` first |
| FortiOS response shapes can vary across versions | Keep consumers tolerant of empty fields |

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE](docs/ARCHITECTURE.md) | REST protocol, package layout, design decisions |
| [FEATURES](docs/FEATURES.md) | Resource coverage and method matrix |
| [PLAN](docs/PLAN.md) | Development roadmap |

## License

MIT - see [LICENSE](LICENSE).
