package rsclient

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"anime.bike/remotestorage/pkg/rs"
)

// DownloadFile downloads a file from RemoteStorage to a local path
func (c *Client) DownloadFile(remotePath, localPath string) error {
	resp, err := c.Get(remotePath)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	// Create directory if needed
	dir := filepath.Dir(localPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Create local file
	file, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Copy content
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// UploadFile uploads a local file to RemoteStorage
func (c *Client) UploadFile(localPath, remotePath string, contentType string) (string, error) {
	// Open local file
	file, err := os.Open(localPath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Detect content type if not provided
	if contentType == "" {
		contentType = detectContentType(localPath)
	}

	// Upload file
	resp, err := c.Put(remotePath, file, contentType, "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server returned status %d: %s", resp.StatusCode, body)
	}

	return resp.Header.Get("ETag"), nil
}

// ListDirectory lists the contents of a directory
func (c *Client) ListDirectory(path string) (*rs.FolderListing, error) {
	// Ensure path ends with /
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	resp, err := c.Get(path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("unauthorized (401): check your authentication")
		}
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, body)
	}

	return ParseFolderListing(resp, path)
}

// DeleteFile deletes a file from RemoteStorage
func (c *Client) DeleteFile(path string, etag string) error {
	resp, err := c.Delete(path, etag)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, body)
	}

	return nil
}

// GetFileInfo retrieves metadata for a file
func (c *Client) GetFileInfo(path string) (*rs.Metadata, error) {
	resp, err := c.Head(path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	// Extract metadata from response headers
	metadata := &rs.Metadata{
		Path:        path,
		Name:        filepath.Base(path),
		ContentType: resp.Header.Get("Content-Type"),
		ETag:        resp.Header.Get("ETag"),
		Size:        resp.ContentLength,
	}

	// Parse Last-Modified
	if lastMod := resp.Header.Get("Last-Modified"); lastMod != "" {
		if t, err := http.ParseTime(lastMod); err == nil {
			metadata.LastModified = t
		}
	}

	return metadata, nil
}

func detectContentType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".txt":
		return "text/plain"
	case ".html", ".htm":
		return "text/html"
	case ".json":
		return "application/json"
	case ".xml":
		return "application/xml"
	case ".pdf":
		return "application/pdf"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".js":
		return "application/javascript"
	case ".css":
		return "text/css"
	default:
		return "application/octet-stream"
	}
}