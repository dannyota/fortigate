package fortigate

import (
	"context"
	"testing"
)

// TestAutoRelogin verifies that when the device returns 401 on an API request
// the client transparently re-authenticates and retries once, returning the
// successful result to the caller.
func TestAutoRelogin(t *testing.T) {
	t.Run("retries once on session expiry", func(t *testing.T) {
		client, ts := newTestClientWithServer(t, map[string]string{
			"/api/v2/cmdb/firewall/address": `[{"name":"a","type":"ipmask","subnet":"192.0.2.1 255.255.255.255"}]`,
		})

		// Baseline: one login from newTestClientWithServer.
		if n := ts.logins.Load(); n != 1 {
			t.Fatalf("baseline logins = %d, want 1", n)
		}

		// Arm the server to return 401 on the next API request.
		ts.expireOnce.Store(true)

		addrs, err := client.ListAddresses(context.Background(), "root")
		if err != nil {
			t.Fatalf("ListAddresses after expiry: %v", err)
		}
		if len(addrs) != 1 || addrs[0].Name != "a" {
			t.Errorf("addrs = %+v", addrs)
		}

		// Must have re-logged in exactly once (total 2) and made 2 API calls
		// (the 401 and the successful retry).
		if n := ts.logins.Load(); n != 2 {
			t.Errorf("logins = %d, want 2 (one baseline + one re-login)", n)
		}
		if n := ts.apiCalls.Load(); n != 2 {
			t.Errorf("apiCalls = %d, want 2 (401 + retry)", n)
		}
	})

	t.Run("expiry mid-pagination retries and completes", func(t *testing.T) {
		// 10 items, page size 3: pages fetched at start=0,3,6,9.
		// Trip an expiry on the 2nd page request; the client must re-login
		// and re-issue that same page, then finish pagination normally.
		client, ts := newTestClientWithServer(t, map[string]string{
			"/api/v2/cmdb/test/item": paginationFixture,
		})

		// Allow 1 successful API call (first page), then expire the 2nd.
		ts.expireAfter.Store(1)

		type item struct {
			Name string `json:"name"`
		}
		cfg := buildListConfig([]ListOption{WithPageSize(3)})
		items, err := getPaged[item](context.Background(), client,
			"/api/v2/cmdb/test/item", nil, cfg)
		if err != nil {
			t.Fatalf("getPaged: %v", err)
		}
		if len(items) != 10 {
			t.Errorf("len = %d, want 10", len(items))
		}
		if items[0].Name != "a" || items[9].Name != "j" {
			t.Errorf("wrong items: first=%q last=%q", items[0].Name, items[9].Name)
		}

		// 2 logins total (baseline + re-login mid-pagination).
		if n := ts.logins.Load(); n != 2 {
			t.Errorf("logins = %d, want 2", n)
		}
	})
}
