package fortigate

import (
	"context"
	"testing"
)

func TestListVDOMs(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.ListVDOMs(context.Background())
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/system/vdom": `[
				{"name": "root",   "opmode": "nat"},
				{"name": "dmz",    "opmode": "nat"},
				{"name": "guest",  "opmode": "transparent"}
			]`,
		})

		vdoms, err := client.ListVDOMs(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(vdoms) != 3 {
			t.Fatalf("len = %d, want 3", len(vdoms))
		}
		if vdoms[0].Name != "root" || vdoms[0].OpMode != "nat" {
			t.Errorf("vdoms[0] = %+v", vdoms[0])
		}
		if vdoms[2].OpMode != "transparent" {
			t.Errorf("vdoms[2].OpMode = %q, want transparent", vdoms[2].OpMode)
		}
	})
}
