package fortigate

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrAuth           = errors.New("fortigate: authentication failed")
	ErrPermission     = errors.New("fortigate: no permission for resource")
	ErrCertificate    = errors.New("fortigate: invalid TLS certificate")
	ErrNotLoggedIn    = errors.New("fortigate: not logged in")
	ErrNotFound       = errors.New("fortigate: resource not found")
	ErrInvalidName    = errors.New("fortigate: invalid VDOM name")
	ErrSessionExpired = errors.New("fortigate: session expired")
)

// APIError represents a non-zero error code from FortiGate REST API.
type APIError struct {
	HTTPStatus int
	Code       int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("fortigate: API error %d (HTTP %d): %s", e.Code, e.HTTPStatus, e.Message)
}

func isCertificateError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "x509:") ||
		strings.Contains(s, "certificate") ||
		strings.Contains(s, "tls:")
}
