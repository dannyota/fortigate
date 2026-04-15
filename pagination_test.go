package fortigate

import (
	"context"
	"testing"
)

const paginationFixture = `[
	{"name":"a"},{"name":"b"},{"name":"c"},
	{"name":"d"},{"name":"e"},{"name":"f"},
	{"name":"g"},{"name":"h"},{"name":"i"},
	{"name":"j"}
]`

func TestPagination(t *testing.T) {
	type item struct {
		Name string `json:"name"`
	}

	t.Run("under-full first page returns all", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/test/item": paginationFixture,
		})

		cfg := buildListConfig(nil) // default page size 1000
		items, err := getPaged[item](context.Background(), client, "/api/v2/cmdb/test/item", nil, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 10 {
			t.Errorf("len = %d, want 10", len(items))
		}
	})

	t.Run("multi-page with small page size", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/test/item": paginationFixture,
		})

		cfg := buildListConfig([]ListOption{WithPageSize(3)})
		items, err := getPaged[item](context.Background(), client, "/api/v2/cmdb/test/item", nil, cfg)
		if err != nil {
			t.Fatal(err)
		}
		// 10 items, page size 3: pages of 3, 3, 3, 1 → 4 pages total
		if len(items) != 10 {
			t.Errorf("len = %d, want 10", len(items))
		}
		if items[0].Name != "a" || items[9].Name != "j" {
			t.Errorf("wrong items: first=%q last=%q", items[0].Name, items[9].Name)
		}
	})

	t.Run("page callback fires per page", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/test/item": paginationFixture,
		})

		pages := 0
		cfg := buildListConfig([]ListOption{
			WithPageSize(4),
			WithPageCallback(func(fetched, page int) { pages++ }),
		})
		items, err := getPaged[item](context.Background(), client, "/api/v2/cmdb/test/item", nil, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 10 {
			t.Errorf("len = %d, want 10", len(items))
		}
		// pages: 4, 4, 2 → 3 pages
		if pages != 3 {
			t.Errorf("pages = %d, want 3", pages)
		}
	})

	t.Run("empty result", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/test/empty": `[]`,
		})

		cfg := buildListConfig(nil)
		items, err := getPaged[item](context.Background(), client, "/api/v2/cmdb/test/empty", nil, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 0 {
			t.Errorf("len = %d, want 0", len(items))
		}
	})

	t.Run("exact multiple of page size requires one more fetch", func(t *testing.T) {
		// 9 items, page size 3 → pages of 3, 3, 3, then an empty 4th page
		// to confirm the end. Tests the boundary where the last page is
		// exactly full and the pager cannot tell from len alone that
		// there's nothing more.
		fixture := `[
			{"name":"a"},{"name":"b"},{"name":"c"},
			{"name":"d"},{"name":"e"},{"name":"f"},
			{"name":"g"},{"name":"h"},{"name":"i"}
		]`
		client, ts := newTestClientWithServer(t, map[string]string{
			"/api/v2/cmdb/test/item": fixture,
		})

		pages := 0
		cfg := buildListConfig([]ListOption{
			WithPageSize(3),
			WithPageCallback(func(fetched, page int) { pages++ }),
		})
		items, err := getPaged[item](context.Background(), client,
			"/api/v2/cmdb/test/item", nil, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 9 {
			t.Errorf("len = %d, want 9", len(items))
		}
		// 4 API fetches total: 3 full pages + 1 empty probe page.
		if pages != 4 {
			t.Errorf("pages = %d, want 4 (3 full + 1 empty terminator)", pages)
		}
		if n := ts.apiCalls.Load(); n != 4 {
			t.Errorf("apiCalls = %d, want 4", n)
		}
	})
}
