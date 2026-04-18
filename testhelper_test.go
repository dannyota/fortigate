package fortigate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
)

const testCSRFToken = "test-csrf-token"

// testServer wraps an httptest.Server with counters and knobs used by tests.
type testServer struct {
	*httptest.Server
	logins      atomic.Int32 // number of /logincheck calls
	apiCalls    atomic.Int32 // number of /api/v2/ calls
	expireOnce  atomic.Bool  // if true, the next API call returns 401 then clears the flag
	expireAfter atomic.Int32 // if >0, expire once after this many successful API calls
}

// newTestServer builds a mock FortiGate server with the given fixtures.
// It validates the CSRF token on API requests (matching real device behavior).
func newTestServer(t *testing.T, fixtures map[string]string) *testServer {
	t.Helper()

	ts := &testServer{}
	mux := http.NewServeMux()

	// Login: set ccsrftoken cookie (with port+hash suffix like real FortiGate).
	mux.HandleFunc("/logincheck", func(w http.ResponseWriter, r *http.Request) {
		ts.logins.Add(1)
		http.SetCookie(w, &http.Cookie{
			Name:  "ccsrftoken_8443_test",
			Value: testCSRFToken,
			Path:  "/",
		})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`1document.location="/";`))
	})

	// Logout.
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// All REST API endpoints.
	mux.HandleFunc("/api/v2/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// CSRF token must be present on every API request.
		if r.Header.Get("X-CSRFTOKEN") != testCSRFToken {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"http_status":403,"status":"error","message":"missing or invalid X-CSRFTOKEN"}`)
			return
		}

		ts.apiCalls.Add(1)

		// Simulate a mid-request session expiry.
		if ts.expireOnce.Load() {
			ts.expireOnce.Store(false)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, `{"http_status":401,"status":"error","message":"session expired"}`)
			return
		}
		if n := ts.expireAfter.Load(); n > 0 && ts.apiCalls.Load() == n+1 {
			ts.expireAfter.Store(0)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, `{"http_status":401,"status":"error","message":"session expired"}`)
			return
		}

		path := r.URL.Path
		data, ok := fixtures[path]
		if !ok {
			_, _ = fmt.Fprintf(w, `{"http_status":404,"status":"error","message":"unknown path: %s"}`, path)
			return
		}

		// Slice the fixture array by start/count for pagination.
		start := queryInt(r, "start", 0)
		count := queryInt(r, "count", 0)
		if count > 0 {
			if sliced, ok := sliceFixture(data, start, count); ok {
				data = sliced
			}
		}

		_, _ = fmt.Fprintf(w, `{"http_status":200,"status":"success","results":%s}`, data)
	})

	ts.Server = httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// newTestClient creates a mock FortiGate REST API server and returns a logged-in
// Client. fixtures maps API path (e.g. "/api/v2/cmdb/firewall/address") to a
// JSON array string that will be served as the results payload.
// The server handles pagination via ?start=N&count=M query params and
// validates the X-CSRFTOKEN header on API requests.
func newTestClient(t *testing.T, fixtures map[string]string) *Client {
	t.Helper()

	ts := newTestServer(t, fixtures)

	client, err := NewClient(ts.URL, WithCredentials("admin", "pass"))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	return client
}

// newTestClientWithServer is like newTestClient but also returns the server
// wrapper so tests can inspect counters or trigger behaviors like session expiry.
func newTestClientWithServer(t *testing.T, fixtures map[string]string) (*Client, *testServer) {
	t.Helper()

	ts := newTestServer(t, fixtures)

	client, err := NewClient(ts.URL, WithCredentials("admin", "pass"))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	return client, ts
}

// sliceFixture parses a JSON array fixture and returns the [start, start+count)
// sub-slice as a JSON string. Returns ("", false) if the fixture is not a valid
// JSON array or if parameters are out of range.
func sliceFixture(fixture string, start, count int) (string, bool) {
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(fixture), &arr); err != nil {
		return "", false
	}
	if start < 0 || count <= 0 {
		return "", false
	}
	if start >= len(arr) {
		return "[]", true
	}
	end := min(start+count, len(arr))
	out, err := json.Marshal(arr[start:end])
	if err != nil {
		return "", false
	}
	return string(out), true
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
