package fortigate

import "testing"

func TestSpaceSubnetToCIDR(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// Empty.
		{"", ""},
		// Host — /32 stripped.
		{"192.0.2.1 255.255.255.255", "192.0.2.1"},
		// Network.
		{"192.0.2.0 255.255.255.0", "192.0.2.0/24"},
		{"198.51.100.0 255.255.255.128", "198.51.100.0/25"},
		{"198.51.100.0 255.255.0.0", "198.51.100.0/16"},
		{"192.0.2.0 255.0.0.0", "192.0.2.0/8"},
		// "Any" address.
		{"0.0.0.0 0.0.0.0", "0.0.0.0/0"},
		// Single token — pass through (already CIDR or bare IP).
		{"192.0.2.1/24", "192.0.2.1/24"},
		{"192.0.2.1", "192.0.2.1"},
		// Three tokens — pass through unchanged.
		{"bad input here", "bad input here"},
		// Invalid mask — pass through original string unchanged.
		{"192.0.2.0 badmask", "192.0.2.0 badmask"},
	}

	for _, c := range cases {
		got := spaceSubnetToCIDR(c.in)
		if got != c.want {
			t.Errorf("spaceSubnetToCIDR(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestZeroIPToEmpty(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"0.0.0.0", ""},
		{"0.0.0.0/0", ""},
		{"192.0.2.1/24", "192.0.2.1/24"},
		{"192.0.2.1", "192.0.2.1"},
		{"", ""},
	}
	for _, c := range cases {
		got := zeroIPToEmpty(c.in)
		if got != c.want {
			t.Errorf("zeroIPToEmpty(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNamesOf(t *testing.T) {
	got := namesOf([]namedItem{{Name: "a"}, {Name: "b"}, {Name: "c"}})
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("namesOf = %v", got)
	}

	empty := namesOf(nil)
	if len(empty) != 0 {
		t.Errorf("namesOf(nil) = %v, want []", empty)
	}

	empty2 := namesOf([]namedItem{})
	if len(empty2) != 0 {
		t.Errorf("namesOf([]) = %v, want []", empty2)
	}
}

func TestIsEnabled(t *testing.T) {
	if !isEnabled("enable") {
		t.Error("isEnabled(enable) = false")
	}
	if isEnabled("disable") {
		t.Error("isEnabled(disable) = true")
	}
	if isEnabled("") {
		t.Error("isEnabled(\"\") = true")
	}
}

func TestVIPMappedIP(t *testing.T) {
	got := vipMappedIP([]apiVIPMappedIP{{Range: "192.0.2.1"}, {Range: "192.0.2.2"}})
	if got != "192.0.2.1,192.0.2.2" {
		t.Errorf("vipMappedIP = %q, want %q", got, "192.0.2.1,192.0.2.2")
	}
	if vipMappedIP(nil) != "" {
		t.Error("vipMappedIP(nil) != \"\"")
	}
	single := vipMappedIP([]apiVIPMappedIP{{Range: "198.51.100.1"}})
	if single != "198.51.100.1" {
		t.Errorf("vipMappedIP single = %q", single)
	}
}
