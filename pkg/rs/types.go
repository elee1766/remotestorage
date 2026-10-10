package rs

import (
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// StorageInfo contains RemoteStorage discovery information
type StorageInfo struct {
	Href         string                 `json:"href"`
	Rel          string                 `json:"rel"`
	Properties   map[string]interface{} `json:"properties"`
	DiscoveryURL string                 `json:"discovery_url,omitempty"`
}

// Metadata describes a document or folder.
// ETag values never include the surrounding double quotes.
type Metadata struct {
	Path         string // Full path including name. Folder paths end in "/".
	Name         string // Just the item name
	ContentType  string
	ETag         string
	LastModified time.Time
	Size         int64
	IsFolder     bool
}

// Document represents a document in RemoteStorage.
// If Body implements io.Seeker the server can answer Range requests.
type Document struct {
	Metadata Metadata
	Body     io.ReadCloser
}

// FolderListing is the JSON-LD folder description returned for folder GETs.
type FolderListing struct {
	LDContext interface{}           `json:"@context"`
	Metadata  Metadata              `json:"-"`
	Items     map[string]FolderItem `json:"items"`
}

// FolderItem is one entry of a folder listing. Documents carry all four
// fields; folders (names ending in "/") carry only ETag.
type FolderItem struct {
	ETag          string `json:"ETag"`
	ContentType   string `json:"Content-Type,omitempty"`
	ContentLength int64  `json:"Content-Length,omitempty"`
	LastModified  string `json:"Last-Modified,omitempty"`
	// IsFolder selects the folder description encoding.
	IsFolder bool `json:"-"`
}

// MarshalJSON always emits Content-Length for documents, including 0.
func (f FolderItem) MarshalJSON() ([]byte, error) {
	if f.IsFolder {
		return json.Marshal(struct {
			ETag string `json:"ETag"`
		}{f.ETag})
	}
	return json.Marshal(struct {
		ETag          string `json:"ETag"`
		ContentType   string `json:"Content-Type"`
		ContentLength int64  `json:"Content-Length"`
		LastModified  string `json:"Last-Modified"`
	}{f.ETag, f.ContentType, f.ContentLength, f.LastModified})
}

// DocumentItem builds the folder listing entry for a document.
func DocumentItem(m Metadata) FolderItem {
	return FolderItem{
		ETag:          m.ETag,
		ContentType:   m.ContentType,
		ContentLength: m.Size,
		LastModified:  FormatHTTPDate(m.LastModified),
	}
}

// FolderEntry builds the folder listing entry for a subfolder.
func FolderEntry(etag string) FolderItem {
	return FolderItem{ETag: etag, IsFolder: true}
}

// FormatHTTPDate formats t as an HTTP-date (RFC 9110 section 5.6.7).
func FormatHTTPDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(http.TimeFormat)
}

// VersionName represents a RemoteStorage protocol version
type VersionName string

// Constants for RemoteStorage protocol
const (
	RemoteStorageRel = "http://tools.ietf.org/id/draft-dejong-remotestorage"
	PublicModule     = "public"

	// FolderDescriptionContext is the required @context of folder listings.
	FolderDescriptionContext = "http://remotestorage.io/spec/folder-description"

	// Version constants
	VersionDraftDejongRemoteStorage27 VersionName = "draft-dejong-remotestorage-27"

	// The only version we support
	SupportedVersion = VersionDraftDejongRemoteStorage27
)
