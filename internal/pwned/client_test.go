package pwned

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClientValidation(t *testing.T) {
	if _, err := NewClient("", "agent", time.Second); err == nil {
		t.Fatalf("expected error for empty base url")
	}
	if _, err := NewClient("https://example.com", "", time.Second); err == nil {
		t.Fatalf("expected error for empty user agent")
	}
	if _, err := NewClient("https://example.com", "agent", 0); err == nil {
		t.Fatalf("expected error for non-positive timeout")
	}
}

func TestClientIsBreached(t *testing.T) {
	password := "Password123!"
	hash := sha1.Sum([]byte(password))
	hashStr := strings.ToUpper(hex.EncodeToString(hash[:]))
	prefix := hashStr[:5]
	suffix := hashStr[5:]

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, prefix) {
			t.Fatalf("expected prefix %s in path, got %s", prefix, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(suffix + ":5\r\n"))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "test-agent", time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	client.httpClient = server.Client()

	breached, err := client.IsBreached(context.Background(), password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !breached {
		t.Fatalf("expected password to be marked as breached")
	}
}

func TestClientNotBreached(t *testing.T) {
	password := "AnotherPassword123!"
	hash := sha1.Sum([]byte(password))
	hashStr := strings.ToUpper(hex.EncodeToString(hash[:]))
	prefix := hashStr[:5]

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, prefix) {
			t.Fatalf("expected prefix %s in path, got %s", prefix, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OTHERHASH:10\r\n"))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "test-agent", time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	client.httpClient = server.Client()

	breached, err := client.IsBreached(context.Background(), password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if breached {
		t.Fatalf("expected password to be not breached")
	}
}

func TestClientHandlesRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "test-agent", time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	client.httpClient = server.Client()

	if _, err := client.IsBreached(context.Background(), "Password123!"); err == nil {
		t.Fatalf("expected error when rate limited")
	}
}
