package fortigate

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
)

// Client communicates with a FortiGate device via the REST API v2.
type Client struct {
	address    string
	config     clientConfig
	httpClient *http.Client
	cookieJar  *cookiejar.Jar
	csrfToken  string
}

// NewClient creates a new FortiGate client.
// address is the base URL (e.g. "https://192.168.1.1").
// At minimum, WithCredentials must be provided.
//
// HTTP client precedence: WithHTTPClient > WithTransport > default.
func NewClient(address string, opts ...ClientOption) (*Client, error) {
	if address == "" {
		return nil, fmt.Errorf("fortigate: address is required")
	}

	cfg := clientConfig{
		timeout:   defaultTimeout,
		userAgent: defaultUserAgent,
	}
	for _, o := range opts {
		o.apply(&cfg)
	}

	if cfg.username == "" || cfg.password == "" {
		return nil, fmt.Errorf("fortigate: credentials are required (use WithCredentials)")
	}

	if cfg.x509NegativeSerial {
		setX509NegativeSerial()
	}

	address = strings.TrimRight(address, "/")

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("fortigate: create cookie jar: %w", err)
	}

	httpClient := buildHTTPClient(cfg, jar)

	return &Client{
		address:    address,
		config:     cfg,
		httpClient: httpClient,
		cookieJar:  jar,
	}, nil
}

// Login authenticates with FortiGate and obtains a session cookie.
func (c *Client) Login(ctx context.Context) error {
	form := url.Values{
		"username":  {c.config.username},
		"secretkey": {c.config.password},
		"ajax":      {"1"},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.address+"/logincheck",
		strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("fortigate: create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.config.userAgent != "" {
		req.Header.Set("User-Agent", c.config.userAgent)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if isCertificateError(err) {
			return fmt.Errorf("%w: %v", ErrCertificate, err)
		}
		return fmt.Errorf("fortigate: login request: %w", err)
	}
	defer resp.Body.Close()

	// ccsrftoken is set by FortiGate on successful login.
	// Its value is wrapped in quotes: "abc123". Strip them before storing.
	parsedURL, err := url.Parse(c.address)
	if err != nil {
		return fmt.Errorf("fortigate: parse address: %w", err)
	}

	// Cookie name is "ccsrftoken" or "ccsrftoken_{port}_{hash}" depending on firmware.
	// Value is wrapped in quotes: "ABC123". Strip them before storing.
	for _, cookie := range c.cookieJar.Cookies(parsedURL) {
		if strings.HasPrefix(cookie.Name, "ccsrftoken") {
			token := strings.Trim(cookie.Value, "\"")
			if token != "" && token != "0000000000000000" {
				c.csrfToken = token
				return nil
			}
		}
	}

	return ErrAuth
}

// Logout terminates the FortiGate session.
// The CSRF token is always cleared, even if the request fails.
func (c *Client) Logout(ctx context.Context) error {
	if c.csrfToken == "" {
		return nil
	}
	defer func() { c.csrfToken = "" }()

	req, err := http.NewRequestWithContext(ctx, "POST", c.address+"/logout", nil)
	if err != nil {
		return fmt.Errorf("fortigate: create logout request: %w", err)
	}

	req.Header.Set("X-CSRFTOKEN", c.csrfToken)
	if c.config.userAgent != "" {
		req.Header.Set("User-Agent", c.config.userAgent)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fortigate: logout request: %w", err)
	}
	resp.Body.Close()

	return nil
}

// Close logs out and releases resources.
func (c *Client) Close() error {
	return c.Logout(context.Background())
}

// LoggedIn returns true if the client has an active session.
func (c *Client) LoggedIn() bool {
	return c.csrfToken != ""
}

// buildHTTPClient resolves the HTTP client to use from the client options.
// Precedence: WithHTTPClient > WithTransport > default.
func buildHTTPClient(cfg clientConfig, jar *cookiejar.Jar) *http.Client {
	if cfg.httpClient != nil {
		cfg.httpClient.Jar = jar
		return cfg.httpClient
	}
	transport := cfg.transport
	if transport == nil {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.insecureTLS},
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   cfg.timeout,
		Jar:       jar,
	}
}

var x509NegativeSerialOnce sync.Once

func setX509NegativeSerial() {
	x509NegativeSerialOnce.Do(func() {
		current := os.Getenv("GODEBUG")
		if strings.Contains(current, "x509negativeserial=1") {
			return
		}
		if current != "" {
			current += ","
		}
		os.Setenv("GODEBUG", current+"x509negativeserial=1")
	})
}

// validName checks that a VDOM name contains only safe characters.
func validName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

// requireVDOM returns an error if the client is not logged in or the vdom
// name is unsafe. Used as a precondition check by VDOM-scoped List methods.
func (c *Client) requireVDOM(vdom string) error {
	if !c.LoggedIn() {
		return ErrNotLoggedIn
	}
	if !validName(vdom) {
		return fmt.Errorf("%w: %q", ErrInvalidName, vdom)
	}
	return nil
}
