package rsclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"anime.bike/remotestorage/pkg/rs"
)

// Client is a RemoteStorage client
type Client struct {
	HTTPClient  *http.Client
	StorageRoot string
	TokenSource oauth2.TokenSource
}

// New creates a new RemoteStorage client
func New(storageRoot string, tokenSource oauth2.TokenSource) *Client {
	return &Client{
		HTTPClient:  http.DefaultClient,
		StorageRoot: strings.TrimSuffix(storageRoot, "/"),
		TokenSource: tokenSource,
	}
}

// NewWithToken creates a new RemoteStorage client with a static token
func NewWithToken(storageRoot string, token string) *Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: token,
		TokenType:   "Bearer",
	})
	return New(storageRoot, ts)
}

// Get retrieves a document or folder listing
func (c *Client) Get(path string) (*http.Response, error) {
	req, err := http.NewRequest("GET", c.StorageRoot+path, nil)
	if err != nil {
		return nil, err
	}
	
	if err := c.setAuth(req); err != nil {
		return nil, err
	}
	
	
	return c.HTTPClient.Do(req)
}

// Put stores a document
func (c *Client) Put(path string, body io.Reader, contentType string, etag string) (*http.Response, error) {
	req, err := http.NewRequest("PUT", c.StorageRoot+path, body)
	if err != nil {
		return nil, err
	}
	
	if err := c.setAuth(req); err != nil {
		return nil, err
	}
	
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	
	if etag != "" {
		req.Header.Set("If-Match", etag)
	}
	
	return c.HTTPClient.Do(req)
}

// Delete removes a document
func (c *Client) Delete(path string, etag string) (*http.Response, error) {
	req, err := http.NewRequest("DELETE", c.StorageRoot+path, nil)
	if err != nil {
		return nil, err
	}
	
	if err := c.setAuth(req); err != nil {
		return nil, err
	}
	
	if etag != "" {
		req.Header.Set("If-Match", etag)
	}
	
	return c.HTTPClient.Do(req)
}

// Head retrieves document metadata
func (c *Client) Head(path string) (*http.Response, error) {
	req, err := http.NewRequest("HEAD", c.StorageRoot+path, nil)
	if err != nil {
		return nil, err
	}
	
	if err := c.setAuth(req); err != nil {
		return nil, err
	}
	
	return c.HTTPClient.Do(req)
}

func (c *Client) setAuth(req *http.Request) error {
	if c.TokenSource == nil {
		return nil
	}
	
	token, err := c.TokenSource.Token()
	if err != nil {
		return err
	}
	
	token.SetAuthHeader(req)
	return nil
}

// ParseFolderListing parses a folder listing response
func ParseFolderListing(resp *http.Response, path string) (*rs.FolderListing, error) {
	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/ld+json") && !strings.HasPrefix(contentType, "application/json") {
		return nil, fmt.Errorf("expected application/ld+json or application/json, got %s", contentType)
	}
	
	var listing rs.FolderListing
	err := json.NewDecoder(resp.Body).Decode(&listing)
	if err != nil {
		return nil, err
	}
	
	// Extract folder name from path
	name := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		name = path[idx+1:]
	}
	
	// Set metadata
	listing.Metadata = rs.Metadata{
		Path:     path,
		Name:     name,
		ETag:     resp.Header.Get("ETag"),
		IsFolder: true,
	}
	
	return &listing, nil
}