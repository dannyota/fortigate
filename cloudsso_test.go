package fortigate

import (
	"context"
	"testing"
)

func TestListSSOAdmins(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/system/sso-admin": `[
			{
				"name": "cloud-admin",
				"accprofile": "super_admin",
				"vdom": [{"name": "root"}]
			}
		]`,
	})

	admins, err := client.ListSSOAdmins(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(admins) != 1 {
		t.Fatalf("len = %d, want 1", len(admins))
	}
	a := admins[0]
	if a.Name != "cloud-admin" || a.Accprofile != "super_admin" || len(a.Vdoms) != 1 || a.Vdoms[0] != "root" {
		t.Errorf("sso-admin = %+v", a)
	}
}

func TestListSSOAdminsEmpty(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/system/sso-admin": `[]`,
	})
	admins, err := client.ListSSOAdmins(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(admins) != 0 {
		t.Fatalf("len = %d, want 0", len(admins))
	}
}

func TestGetCentralManagement(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/system/central-management": `{
			"mode": "normal",
			"type": "fortimanager",
			"include-default-servers": "enable",
			"fmg-source-ip": "0.0.0.0",
			"fortigate-cloud-sso-default-profile": "",
			"server-list": []
		}`,
	})

	cm, err := client.GetCentralManagement(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cm.Mode != "normal" || cm.Type != "fortimanager" || cm.IncludeDefaultServers != "enable" {
		t.Errorf("central-management = %+v", cm)
	}
}

func TestGetFortiGuard(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/system/fortiguard": `{
			"auto-join-forticloud": "disable",
			"service-account-id": ""
		}`,
	})

	fg, err := client.GetFortiGuard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fg.AutoJoinForticloud != "disable" {
		t.Errorf("fortiguard = %+v", fg)
	}
}
