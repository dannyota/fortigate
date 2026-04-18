package fortigate

import (
	"context"
	"testing"
)

func TestListRecurringSchedules(t *testing.T) {
	t.Run("not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		_, err := c.ListRecurringSchedules(context.Background(), "root")
		if err != ErrNotLoggedIn {
			t.Errorf("err = %v, want ErrNotLoggedIn", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/firewall.schedule/recurring": `[
				{
					"name": "business-hours",
					"day": "monday tuesday wednesday thursday friday",
					"start": "08:00",
					"end": "18:00",
					"color": 1
				},
				{
					"name": "weekend",
					"day": ["saturday", "sunday"],
					"start": "00:00",
					"end": "23:59",
					"color": 2
				}
			]`,
		})

		schedules, err := client.ListRecurringSchedules(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(schedules) != 2 {
			t.Fatalf("len = %d, want 2", len(schedules))
		}
		if schedules[0].Name != "business-hours" || len(schedules[0].Days) != 5 || schedules[0].Start != "08:00" {
			t.Errorf("schedule = %+v", schedules[0])
		}
		if len(schedules[1].Days) != 2 || schedules[1].Days[1] != "sunday" {
			t.Errorf("weekend days = %v", schedules[1].Days)
		}
	})
}

func TestListOneTimeSchedules(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/firewall.schedule/onetime": `[
				{
					"name": "maintenance",
					"start": "2026/04/18 01:00",
					"end": "2026/04/18 03:00",
					"start-utc": 1776448800,
					"end-utc": 1776456000,
					"color": 3
				}
			]`,
		})

		schedules, err := client.ListOneTimeSchedules(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(schedules) != 1 {
			t.Fatalf("len = %d, want 1", len(schedules))
		}
		if schedules[0].Name != "maintenance" || schedules[0].StartUTC != 1776448800 {
			t.Errorf("schedule = %+v", schedules[0])
		}
	})
}

func TestListScheduleGroups(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		client := newTestClient(t, map[string]string{
			"/api/v2/cmdb/firewall.schedule/group": `[
				{
					"name": "office-schedules",
					"member": [{"name": "business-hours"}, {"name": "maintenance"}],
					"color": 4
				}
			]`,
		})

		groups, err := client.ListScheduleGroups(context.Background(), "root")
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 1 {
			t.Fatalf("len = %d, want 1", len(groups))
		}
		if groups[0].Name != "office-schedules" || len(groups[0].Members) != 2 || groups[0].Members[0] != "business-hours" {
			t.Errorf("group = %+v", groups[0])
		}
	})
}
