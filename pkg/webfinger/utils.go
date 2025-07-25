package webfinger

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// NormalizeResource ensures a resource has the proper format
func NormalizeResource(resource string) string {
	// If it looks like an email without acct: prefix, add it
	if strings.Contains(resource, "@") && !strings.Contains(resource, "://") && !strings.HasPrefix(resource, "acct:") {
		return "acct:" + resource
	}
	return resource
}

// ExtractHost extracts the host from a resource identifier
func ExtractHost(resource string) (string, error) {
	// Handle acct: scheme
	if strings.HasPrefix(resource, "acct:") {
		parts := strings.Split(strings.TrimPrefix(resource, "acct:"), "@")
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid acct resource format")
		}
		return parts[1], nil
	}
	
	// Handle user@host format
	if strings.Contains(resource, "@") && !strings.Contains(resource, "://") {
		parts := strings.Split(resource, "@")
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid email-like resource format")
		}
		return parts[1], nil
	}
	
	// Handle HTTP(S) URLs
	if strings.HasPrefix(resource, "http://") || strings.HasPrefix(resource, "https://") {
		u, err := url.Parse(resource)
		if err != nil {
			return "", err
		}
		return u.Host, nil
	}
	
	return "", fmt.Errorf("unsupported resource format")
}

// BuildURL constructs a WebFinger URL for the given host and resource
func BuildURL(host, resource string) string {
	u := &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   "/.well-known/webfinger",
	}
	q := u.Query()
	q.Set("resource", resource)
	u.RawQuery = q.Encode()
	return u.String()
}

// ParseResponse parses a WebFinger response from a byte slice
func ParseResponse(data []byte) (*Response, error) {
	var resp Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &resp, nil
}