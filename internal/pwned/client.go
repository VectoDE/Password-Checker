package pwned

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client interacts with the Have I Been Pwned password API using the k-anonymity model.
type Client struct {
	baseURL    string
	httpClient *http.Client
	userAgent  string
	name       string
}

// NewClient constructs a Client with the supplied configuration.
func NewClient(baseURL, userAgent string, timeout time.Duration) (*Client, error) {
	if baseURL == "" {
		return nil, errors.New("baseURL cannot be empty")
	}
	if timeout <= 0 {
		return nil, errors.New("timeout must be greater than zero")
	}
	if userAgent == "" {
		return nil, errors.New("userAgent cannot be empty")
	}

	trimmedBase := strings.TrimRight(baseURL, "/")

	return &Client{
		baseURL: trimmedBase,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		userAgent: userAgent,
		name:      "Have I Been Pwned",
	}, nil
}

// IsBreached determines if the password has been exposed in known data breaches.
func (c *Client) IsBreached(ctx context.Context, password string) (bool, error) {
	if password == "" {
		return false, errors.New("password must not be empty")
	}

	hash := sha1.Sum([]byte(password))
	hexHash := strings.ToUpper(hex.EncodeToString(hash[:]))
	prefix := hexHash[:5]
	suffix := hexHash[5:]

	url := fmt.Sprintf("%s/%s", c.baseURL, prefix)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to query hibp api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return false, fmt.Errorf("hibp rate limit exceeded: %s", resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected hibp response: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read hibp response: %w", err)
	}

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, suffix) {
			return true, nil
		}
	}

	return false, nil
}

// Name returns the human-friendly identifier of the breach provider.
func (c *Client) Name() string {
	return c.name
}
