package rsclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/webfinger"
)

// DiscoverRaw performs RemoteStorage discovery and returns the raw JSON response
func DiscoverRaw(ctx context.Context, userAddress string, client *http.Client) (json.RawMessage, error) {
	if client == nil {
		client = http.DefaultClient
	}

	// Normalize and extract host
	resource := webfinger.NormalizeResource(userAddress)
	host, err := webfinger.ExtractHost(resource)
	if err != nil {
		return nil, fmt.Errorf("failed to extract host: %w", err)
	}

	// Build WebFinger URL
	webfingerURL := webfinger.BuildURL(host, resource)

	// Make request
	req, err := http.NewRequestWithContext(ctx, "GET", webfingerURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/jrd+json, application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("webfinger request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("webfinger request returned status %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return json.RawMessage(body), nil
}

// Discover performs RemoteStorage discovery with context
func Discover(ctx context.Context, userAddress string, client *http.Client) (*rs.StorageInfo, error) {
	// Get raw response
	rawResponse, err := DiscoverRaw(ctx, userAddress, client)
	if err != nil {
		return nil, err
	}

	// Extract host to build discovery URL
	resource := webfinger.NormalizeResource(userAddress)
	host, err := webfinger.ExtractHost(resource)
	if err != nil {
		return nil, fmt.Errorf("failed to extract host: %w", err)
	}
	discoveryURL := webfinger.BuildURL(host, resource)

	// Parse response and convert to StorageInfo
	return ParseDiscoveryResponse([]byte(rawResponse), discoveryURL)
}

// ParseDiscoveryResponse parses a WebFinger response body and converts it to StorageInfo
func ParseDiscoveryResponse(body []byte, discoveryURL string) (*rs.StorageInfo, error) {
	// Parse WebFinger response
	wfResp, err := webfinger.ParseResponse(body)
	if err != nil {
		return nil, err
	}

	// Find RemoteStorage link
	link := FindRemoteStorageLink(wfResp)
	if link == nil {
		return nil, fmt.Errorf("no RemoteStorage link found in webfinger response")
	}

	if link.Href == "" {
		return nil, fmt.Errorf("RemoteStorage link has no href")
	}

	// Properties are already map[string]any in webfinger.Link
	return &rs.StorageInfo{
		Href:         link.Href,
		Rel:          link.Rel,
		Properties:   link.Properties,
		DiscoveryURL: discoveryURL,
	}, nil
}

// GetAuthURL extracts the OAuth authorization URL from storage info
func GetAuthURL(storageInfo *rs.StorageInfo) (string, error) {
	if storageInfo.Properties == nil {
		return "", fmt.Errorf("no properties in storage info")
	}
	
	authEndpoint, ok := storageInfo.Properties["http://tools.ietf.org/html/rfc6749#section-4.2"].(string)
	if !ok || authEndpoint == "" {
		authEndpoint, ok = storageInfo.Properties["auth-endpoint"].(string)
		if !ok || authEndpoint == "" {
			return "", fmt.Errorf("no auth endpoint found in properties")
		}
	}
	
	return authEndpoint, nil
}


// FindRemoteStorageLink finds the RemoteStorage link in a WebFinger response
func FindRemoteStorageLink(resp *webfinger.Response) *webfinger.Link {
	for i := range resp.Links {
		if resp.Links[i].Rel == rs.RemoteStorageRel || resp.Links[i].Rel == webfinger.RelRemoteStorage {
			return &resp.Links[i]
		}
	}
	return nil
}