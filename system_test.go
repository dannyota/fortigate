package fortigate

import (
	"context"
	"testing"
)

func TestGetSystemInfo(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.GetSystemInfo(context.Background())
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/system/global": `{
				"hostname": "FW-PROD-01",
				"timezone": "53",
				"admin-sport": 443,
				"admin-port": 80
			}`,
		})

		info, err := client.GetSystemInfo(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if info.Hostname != "FW-PROD-01" {
			t.Errorf("Hostname = %q", info.Hostname)
		}
		if info.Timezone != "53" {
			t.Errorf("Timezone = %q", info.Timezone)
		}
		if info.AdminSport != 443 {
			t.Errorf("AdminSport = %d", info.AdminSport)
		}
		if info.AdminPort != 80 {
			t.Errorf("AdminPort = %d", info.AdminPort)
		}
	})
}
