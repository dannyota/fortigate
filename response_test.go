package fortigate

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestCheckResponse(t *testing.T) {
	raw := func(s string) json.RawMessage { return json.RawMessage(s) }

	t.Run("200 returns results", func(t *testing.T) {
		resp := &fgResponse{HTTPStatus: 200, Results: raw(`[1,2,3]`)}
		data, err := checkResponse(resp)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != `[1,2,3]` {
			t.Errorf("data = %s", data)
		}
	})

	t.Run("http_status 0 treated as success", func(t *testing.T) {
		resp := &fgResponse{HTTPStatus: 0, Results: raw(`[]`)}
		_, err := checkResponse(resp)
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
	})

	t.Run("401 → ErrSessionExpired", func(t *testing.T) {
		resp := &fgResponse{HTTPStatus: 401}
		_, err := checkResponse(resp)
		if err != ErrSessionExpired {
			t.Errorf("err = %v, want ErrSessionExpired", err)
		}
	})

	t.Run("403 → ErrPermission", func(t *testing.T) {
		resp := &fgResponse{HTTPStatus: 403, Message: "no access"}
		_, err := checkResponse(resp)
		if !errors.Is(err, ErrPermission) {
			t.Errorf("err = %v, want ErrPermission", err)
		}
	})

	t.Run("404 → ErrNotFound", func(t *testing.T) {
		resp := &fgResponse{HTTPStatus: 404, Message: "not found"}
		_, err := checkResponse(resp)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})

	t.Run("other error → APIError", func(t *testing.T) {
		resp := &fgResponse{HTTPStatus: 500, Error: -99, Message: "internal"}
		_, err := checkResponse(resp)
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("err = %v, want *APIError", err)
		}
		if apiErr.HTTPStatus != 500 || apiErr.Code != -99 {
			t.Errorf("APIError = %+v", apiErr)
		}
	})
}

func TestAPIErrorString(t *testing.T) {
	e := &APIError{HTTPStatus: 400, Code: -2, Message: "bad request"}
	want := "fortigate: API error -2 (HTTP 400): bad request"
	if e.Error() != want {
		t.Errorf("Error() = %q, want %q", e.Error(), want)
	}
}
