package fortigate

import (
	"context"
	"encoding/json"
	"strings"
)

type stringList []string

func (l *stringList) UnmarshalJSON(data []byte) error {
	var items []string
	if err := json.Unmarshal(data, &items); err == nil {
		*l = items
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*l = strings.Fields(s)
	return nil
}

type apiRecurringSchedule struct {
	Name  string     `json:"name"`
	Days  stringList `json:"day"`
	Start string     `json:"start"`
	End   string     `json:"end"`
	Color int        `json:"color"`
}

type apiOneTimeSchedule struct {
	Name     string `json:"name"`
	Start    string `json:"start"`
	End      string `json:"end"`
	StartUTC int    `json:"start-utc"`
	EndUTC   int    `json:"end-utc"`
	Color    int    `json:"color"`
}

type apiScheduleGroup struct {
	Name   string      `json:"name"`
	Member []namedItem `json:"member"`
	Color  int         `json:"color"`
}

// ListRecurringSchedules retrieves recurring firewall schedules from a VDOM.
func (c *Client) ListRecurringSchedules(ctx context.Context, vdom string, opts ...ListOption) ([]RecurringSchedule, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiRecurringSchedule](ctx, c, "/api/v2/cmdb/firewall.schedule/recurring",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	schedules := make([]RecurringSchedule, len(items))
	for i, s := range items {
		schedules[i] = RecurringSchedule{
			Name:  s.Name,
			Days:  s.Days,
			Start: s.Start,
			End:   s.End,
			Color: s.Color,
		}
	}
	return schedules, nil
}

// ListOneTimeSchedules retrieves one-time firewall schedules from a VDOM.
func (c *Client) ListOneTimeSchedules(ctx context.Context, vdom string, opts ...ListOption) ([]OneTimeSchedule, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiOneTimeSchedule](ctx, c, "/api/v2/cmdb/firewall.schedule/onetime",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	schedules := make([]OneTimeSchedule, len(items))
	for i, s := range items {
		schedules[i] = OneTimeSchedule(s)
	}
	return schedules, nil
}

// ListScheduleGroups retrieves firewall schedule groups from a VDOM.
func (c *Client) ListScheduleGroups(ctx context.Context, vdom string, opts ...ListOption) ([]ScheduleGroup, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	items, err := getPaged[apiScheduleGroup](ctx, c, "/api/v2/cmdb/firewall.schedule/group",
		vdomParams(vdom), buildListConfig(opts))
	if err != nil {
		return nil, err
	}

	groups := make([]ScheduleGroup, len(items))
	for i, g := range items {
		groups[i] = ScheduleGroup{
			Name:    g.Name,
			Members: namesOf(g.Member),
			Color:   g.Color,
		}
	}
	return groups, nil
}
