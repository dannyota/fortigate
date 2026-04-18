package fortigate

import (
	"context"
	"testing"
)

func TestUsersAndAuthServers(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/user/local": `[
			{
				"name": "alice",
				"id": 1,
				"status": "enable",
				"type": "password",
				"ldap-server": "",
				"radius-server": "radius1",
				"tacacs+-server": "",
				"two-factor": "disable",
				"two-factor-authentication": "fortitoken",
				"two-factor-notification": "email",
				"fortitoken": "",
				"email-to": "alice@example.test",
				"sms-phone": "",
				"passwd-policy": "policy1",
				"passwd-time": "2026-01-01 00:00:00",
				"authtimeout": 0,
				"username-sensitivity": "disable"
			}
		]`,
		"/api/v2/cmdb/user/group": `[
			{
				"name": "admins",
				"id": 10,
				"group-type": "firewall",
				"member": [{"name": "alice"}, {"name": "ldap1"}],
				"authtimeout": 480,
				"auth-concurrent-override": "enable",
				"auth-concurrent-value": 3,
				"sso-attribute-value": "",
				"expire-type": "never",
				"expire": 0
			}
		]`,
		"/api/v2/cmdb/user/ldap": `[
			{"name": "ldap1", "server": "ldap.example.test", "timeout": 5, "source-ip": "192.0.2.10", "interface-select-method": "auto"}
		]`,
		"/api/v2/cmdb/user/radius": `[
			{"name": "radius1", "server": "radius.example.test", "timeout": 5, "auth-type": "auto", "interface": "wan1"}
		]`,
		"/api/v2/cmdb/user/tacacs+": `[
			{"name": "tacacs1", "server": "tacacs.example.test", "timeout": 5, "auth-type": "pap"}
		]`,
	})

	users, err := client.ListLocalUsers(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Name != "alice" || users[0].RadiusServer != "radius1" {
		t.Errorf("users = %#v", users)
	}

	groups, err := client.ListUserGroups(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0].Members) != 2 || groups[0].Members[0] != "alice" {
		t.Errorf("groups = %#v", groups)
	}

	ldap, err := client.ListLDAPServers(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(ldap) != 1 || ldap[0].Type != "ldap" || ldap[0].Server != "ldap.example.test" {
		t.Errorf("ldap = %#v", ldap)
	}

	radius, err := client.ListRadiusServers(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(radius) != 1 || radius[0].Type != "radius" || radius[0].Interface != "wan1" {
		t.Errorf("radius = %#v", radius)
	}

	tacacs, err := client.ListTACACSServers(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(tacacs) != 1 || tacacs[0].Type != "tacacs+" || tacacs[0].AuthType != "pap" {
		t.Errorf("tacacs = %#v", tacacs)
	}
}
