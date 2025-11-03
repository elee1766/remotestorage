package rs

import (
	"io"
	"time"
)

// StorageInfo contains RemoteStorage discovery information
type StorageInfo struct {
	Href         string                 `json:"href"`
	Rel          string                 `json:"rel"`
	Properties   map[string]interface{} `json:"properties"`
	DiscoveryURL string                 `json:"discovery_url,omitempty"`
}

// Metadata represents document or folder metadata
type Metadata struct {
	Path         string // Full path including name
	Name         string // Just the item name
	ContentType  string
	ETag         string
	LastModified time.Time
	Size         int64
	IsFolder     bool
}

// Document represents a document in RemoteStorage
type Document struct {
	Metadata Metadata
	Body     io.ReadCloser
}

// FolderListing represents a folder's contents in JSON-LD format
type FolderListing struct {
	LDContext interface{}           `json:"@context"`
	Metadata  Metadata              `json:"-"`
	Items     map[string]FolderItem `json:"items"`
}

// FolderItem represents an item in a folder listing
type FolderItem struct {
	ETag          string `json:"ETag,omitempty"`
	ContentType   string `json:"Content-Type,omitempty"`
	ContentLength int64  `json:"Content-Length,omitempty"`
	LastModified  string `json:"Last-Modified,omitempty"`
}

// Scope represents an access scope for RemoteStorage
type Scope struct {
	Module string
	Access AccessLevel
}

// AccessLevel represents read or read/write access
type AccessLevel string

const (
	ReadAccess      AccessLevel = "r"
	ReadWriteAccess AccessLevel = "rw"
)

// VersionName represents a RemoteStorage protocol version
type VersionName string

// Constants for RemoteStorage protocol
const (
	RemoteStorageRel = "http://tools.ietf.org/id/draft-dejong-remotestorage"
	PublicModule     = "public"

	// Version constants
	VersionDraftDejongRemoteStorage25 VersionName = "draft-dejong-remotestorage-25"

	// The only version we support
	SupportedVersion = VersionDraftDejongRemoteStorage25
)

// CheckScopeAccess implements RemoteStorage-compliant scope checking
// according to the specification at https://remotestorage.io/spec/
func CheckScopeAccess(scopes []Scope, module string, isRead bool) bool {
	// Special case: public module is always readable without authentication
	if module == PublicModule && isRead {
		return true
	}

	// Check each scope for access
	for _, scope := range scopes {
		// '*:rw' grants any request
		if scope.Module == "*" && scope.Access == ReadWriteAccess {
			return true
		}

		// '*:r' grants any read request
		if scope.Module == "*" && scope.Access == ReadAccess && isRead {
			return true
		}

		// Module-specific access
		if scope.Module == module {
			// '<module>:rw' grants any request to the module
			if scope.Access == ReadWriteAccess {
				return true
			}

			// '<module>:r' grants read requests to the module
			if scope.Access == ReadAccess && isRead {
				return true
			}
		}
	}

	return false
}
