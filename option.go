package fortigate

import (
	"net/http"
	"time"
)

const (
	defaultTimeout   = 30 * time.Second
	defaultUserAgent = "fortigate-go/0.1"
)

// ClientOption configures the Client.
type ClientOption interface {
	apply(*clientConfig)
}

// clientConfig holds resolved options.
type clientConfig struct {
	username           string
	password           string
	insecureTLS        bool
	x509NegativeSerial bool
	timeout            time.Duration
	transport          http.RoundTripper
	httpClient         *http.Client
	userAgent          string
}

type clientOptFunc func(*clientConfig)

func (f clientOptFunc) apply(c *clientConfig) { f(c) }

// WithCredentials sets username and password for session auth.
func WithCredentials(username, password string) ClientOption {
	return clientOptFunc(func(c *clientConfig) {
		c.username = username
		c.password = password
	})
}

// WithInsecureTLS disables TLS certificate verification.
func WithInsecureTLS() ClientOption {
	return clientOptFunc(func(c *clientConfig) { c.insecureTLS = true })
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(d time.Duration) ClientOption {
	return clientOptFunc(func(c *clientConfig) { c.timeout = d })
}

// WithTransport sets a custom RoundTripper.
func WithTransport(rt http.RoundTripper) ClientOption {
	return clientOptFunc(func(c *clientConfig) { c.transport = rt })
}

// WithHTTPClient replaces the entire HTTP client.
func WithHTTPClient(hc *http.Client) ClientOption {
	return clientOptFunc(func(c *clientConfig) { c.httpClient = hc })
}

// WithUserAgent overrides the User-Agent header.
func WithUserAgent(ua string) ClientOption {
	return clientOptFunc(func(c *clientConfig) { c.userAgent = ua })
}

// WithX509NegativeSerial enables Go's x509negativeserial GODEBUG flag.
// FortiGate appliances may use TLS certificates with negative serial numbers.
func WithX509NegativeSerial() ClientOption {
	return clientOptFunc(func(c *clientConfig) { c.x509NegativeSerial = true })
}

// listConfig holds resolved pagination options for a single List call.
type listConfig struct {
	pageSize int
	onPage   func(fetched int, page int)
}

// ListOption configures pagination behavior for SDK List* methods.
type ListOption interface {
	applyList(*listConfig)
}

type listOptFunc func(*listConfig)

func (f listOptFunc) applyList(c *listConfig) { f(c) }

// WithPageSize overrides the default page size for a single List call.
// Valid range is 1..10000; values outside that range use the default.
func WithPageSize(n int) ListOption {
	return listOptFunc(func(c *listConfig) {
		if n >= 1 && n <= 10000 {
			c.pageSize = n
		}
	})
}

// WithPageCallback registers a function called after each page is fetched.
// fetched is the cumulative row count; page is the 1-based page number.
func WithPageCallback(fn func(fetched, page int)) ListOption {
	return listOptFunc(func(c *listConfig) { c.onPage = fn })
}
