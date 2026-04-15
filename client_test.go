package fortigate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	t.Run("empty address", func(t *testing.T) {
		_, err := NewClient("", WithCredentials("u", "p"))
		if err == nil {
			t.Error("expected error for empty address")
		}
	})

	t.Run("no credentials", func(t *testing.T) {
		_, err := NewClient("https://example.com")
		if err == nil {
			t.Error("expected error for missing credentials")
		}
	})

	t.Run("trailing slash stripped", func(t *testing.T) {
		c, err := NewClient("https://example.com///", WithCredentials("u", "p"))
		if err != nil {
			t.Fatal(err)
		}
		if c.address != "https://example.com" {
			t.Errorf("address = %q, want %q", c.address, "https://example.com")
		}
	})

	t.Run("not logged in by default", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		if c.LoggedIn() {
			t.Error("LoggedIn() = true before Login()")
		}
	})
}

func TestLogin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/logincheck" {
				http.SetCookie(w, &http.Cookie{
					Name:  "ccsrftoken_443_abc",
					Value: "\"mytoken123\"",
					Path:  "/",
				})
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		c, _ := NewClient(server.URL, WithCredentials("admin", "pass"))
		if err := c.Login(context.Background()); err != nil {
			t.Fatalf("Login: %v", err)
		}
		if !c.LoggedIn() {
			t.Error("LoggedIn() = false after success")
		}
		if c.csrfToken != "mytoken123" {
			t.Errorf("csrfToken = %q, want %q", c.csrfToken, "mytoken123")
		}
	})

	t.Run("no csrf cookie → ErrAuth", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK) // no cookie
		}))
		defer server.Close()

		c, _ := NewClient(server.URL, WithCredentials("admin", "wrongpass"))
		err := c.Login(context.Background())
		if err != ErrAuth {
			t.Errorf("err = %v, want ErrAuth", err)
		}
		if c.LoggedIn() {
			t.Error("LoggedIn() = true after failed login")
		}
	})

	t.Run("zeroed token → ErrAuth", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{
				Name:  "ccsrftoken_test",
				Value: "\"0000000000000000\"",
				Path:  "/",
			})
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		c, _ := NewClient(server.URL, WithCredentials("admin", "pass"))
		err := c.Login(context.Background())
		if err != ErrAuth {
			t.Errorf("err = %v, want ErrAuth", err)
		}
	})

	t.Run("self-signed cert without WithInsecureTLS → ErrCertificate", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{
				Name:  "ccsrftoken_443_abc",
				Value: "\"tok\"",
				Path:  "/",
			})
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		c, _ := NewClient(server.URL, WithCredentials("admin", "pass"))
		err := c.Login(context.Background())
		if !errors.Is(err, ErrCertificate) {
			t.Errorf("err = %v, want ErrCertificate", err)
		}
	})

	t.Run("self-signed cert with WithInsecureTLS → success", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{
				Name:  "ccsrftoken_443_abc",
				Value: "\"tok\"",
				Path:  "/",
			})
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		c, _ := NewClient(server.URL, WithCredentials("admin", "pass"), WithInsecureTLS())
		if err := c.Login(context.Background()); err != nil {
			t.Errorf("Login with InsecureTLS: %v", err)
		}
	})

	t.Run("cookie without port suffix", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{
				Name:  "ccsrftoken",
				Value: "\"abc123\"",
				Path:  "/",
			})
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		c, _ := NewClient(server.URL, WithCredentials("admin", "pass"))
		if err := c.Login(context.Background()); err != nil {
			t.Fatalf("Login: %v", err)
		}
		if c.csrfToken != "abc123" {
			t.Errorf("csrfToken = %q", c.csrfToken)
		}
	})
}

func TestLogout(t *testing.T) {
	t.Run("clears token", func(t *testing.T) {
		c := newTestClient(t, nil)
		if err := c.Logout(context.Background()); err != nil {
			t.Fatal(err)
		}
		if c.LoggedIn() {
			t.Error("LoggedIn() = true after Logout()")
		}
	})

	t.Run("noop when not logged in", func(t *testing.T) {
		c, _ := NewClient("https://example.com", WithCredentials("u", "p"))
		if err := c.Logout(context.Background()); err != nil {
			t.Errorf("Logout on non-logged-in client: %v", err)
		}
	})
}

func TestValidName(t *testing.T) {
	valid := []string{"root", "Root", "vdom-1", "vdom_2", "vdom.3", "VDOM123"}
	for _, v := range valid {
		if !validName(v) {
			t.Errorf("validName(%q) = false, want true", v)
		}
	}
	invalid := []string{"", "a b", "a/b", "../etc", "vdom!"}
	for _, v := range invalid {
		if validName(v) {
			t.Errorf("validName(%q) = true, want false", v)
		}
	}
}
