package fortigate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

const (
	defaultPageSize    = 1000
	maxPagedIterations = 10000
)

// buildListConfig applies ListOptions to a fresh listConfig.
func buildListConfig(opts []ListOption) listConfig {
	cfg := listConfig{pageSize: defaultPageSize}
	for _, o := range opts {
		if o != nil {
			o.applyList(&cfg)
		}
	}
	if cfg.pageSize < 1 || cfg.pageSize > 10000 {
		cfg.pageSize = defaultPageSize
	}
	return cfg
}

// fetchJSON performs a GET and transparently re-authenticates once if the
// session has expired. Returns the raw JSON payload from the results field.
func (c *Client) fetchJSON(ctx context.Context, path string, params url.Values) (json.RawMessage, error) {
	data, err := c.doGet(ctx, path, params)
	if !errors.Is(err, ErrSessionExpired) {
		return data, err
	}
	if loginErr := c.Login(ctx); loginErr != nil {
		return nil, fmt.Errorf("fortigate: re-login after session expired: %w", loginErr)
	}
	return c.doGet(ctx, path, params)
}

// get fetches a REST API list endpoint and returns the results as []T.
func get[T any](ctx context.Context, c *Client, path string, params url.Values) ([]T, error) {
	data, err := c.fetchJSON(ctx, path, params)
	if err != nil {
		return nil, err
	}
	var items []T
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("fortigate: unmarshal response: %w", err)
	}
	return items, nil
}

// getOne fetches a single-object REST API endpoint and returns T.
// Used for endpoints like /api/v2/cmdb/system/global that return an object.
func getOne[T any](ctx context.Context, c *Client, path string, params url.Values) (T, error) {
	var item T
	data, err := c.fetchJSON(ctx, path, params)
	if err != nil {
		return item, err
	}
	if err := json.Unmarshal(data, &item); err != nil {
		return item, fmt.Errorf("fortigate: unmarshal response: %w", err)
	}
	return item, nil
}

func getVDOMPaged[T any](ctx context.Context, c *Client, vdom, path string, opts []ListOption) ([]T, error) {
	if err := c.requireVDOM(vdom); err != nil {
		return nil, err
	}
	return getPaged[T](ctx, c, path, vdomParams(vdom), buildListConfig(opts))
}

// doGet performs a single GET request to the REST API without retry.
func (c *Client) doGet(ctx context.Context, path string, params url.Values) (json.RawMessage, error) {
	fullURL := c.address + path
	if len(params) > 0 {
		fullURL += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fortigate: create request: %w", err)
	}

	req.Header.Set("X-CSRFTOKEN", c.csrfToken)
	if c.config.userAgent != "" {
		req.Header.Set("User-Agent", c.config.userAgent)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if isCertificateError(err) {
			return nil, fmt.Errorf("%w: %v", ErrCertificate, err)
		}
		return nil, fmt.Errorf("fortigate: send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("fortigate: read response: %w", err)
	}

	var result fgResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("fortigate: parse response: %w", err)
	}

	// If the device returned a non-200 HTTP status but the JSON envelope
	// didn't include http_status, fall back to the HTTP response code.
	if result.HTTPStatus == 0 && resp.StatusCode != 200 {
		result.HTTPStatus = resp.StatusCode
	}

	return checkResponse(&result)
}

// getPaged fetches every page of a list endpoint and concatenates results.
//
// Pagination uses ?start=N&count=pageSize query params. Any page whose row
// count differs from pageSize terminates (either the final short page, or a
// page where the endpoint ignored the range). A safety cap prevents infinite
// loops if the device keeps returning exactly pageSize rows.
func getPaged[T any](ctx context.Context, c *Client, path string, params url.Values, cfg listConfig) ([]T, error) {
	var all []T
	for page := 1; page <= maxPagedIterations; page++ {
		p := cloneParams(params)
		p.Set("start", strconv.Itoa((page-1)*cfg.pageSize))
		p.Set("count", strconv.Itoa(cfg.pageSize))

		items, err := get[T](ctx, c, path, p)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)

		if cfg.onPage != nil {
			cfg.onPage(len(all), page)
		}
		if len(items) != cfg.pageSize {
			return all, nil
		}
	}
	return nil, fmt.Errorf("fortigate: pagination exceeded safety cap of %d iterations at %s — endpoint may be broken or dataset is impossibly large", maxPagedIterations, path)
}

// cloneParams copies a url.Values map so pagination state doesn't bleed between pages.
func cloneParams(src url.Values) url.Values {
	out := make(url.Values, len(src)+2)
	for k, v := range src {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// vdomParams builds base query params for a VDOM-scoped request.
func vdomParams(vdom string) url.Values {
	return url.Values{"vdom": {vdom}}
}
