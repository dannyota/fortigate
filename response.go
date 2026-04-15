package fortigate

import (
	"encoding/json"
	"fmt"
)

// fgResponse is the JSON envelope from FortiGate REST API v2.
// Results is RawMessage because list endpoints return an array
// while single-object endpoints (e.g. system/global) return an object.
type fgResponse struct {
	HTTPStatus int             `json:"http_status"`
	Status     string          `json:"status"`
	Error      int             `json:"error"`
	Message    string          `json:"message"`
	Results    json.RawMessage `json:"results"`
}

// checkResponse validates the FortiGate REST API response envelope.
// Returns the raw Results payload on success.
func checkResponse(resp *fgResponse) (json.RawMessage, error) {
	// http_status 0 can appear when the outer HTTP response was already 200
	// and the device omits or zeroes the field.
	switch resp.HTTPStatus {
	case 0, 200:
		return resp.Results, nil
	case 401:
		return nil, ErrSessionExpired
	case 403:
		return nil, fmt.Errorf("%w: %s", ErrPermission, resp.Message)
	case 404:
		return nil, fmt.Errorf("%w: %s", ErrNotFound, resp.Message)
	default:
		return nil, &APIError{
			HTTPStatus: resp.HTTPStatus,
			Code:       resp.Error,
			Message:    resp.Message,
		}
	}
}
