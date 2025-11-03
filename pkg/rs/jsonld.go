package rs

// GetFolderListingContext returns the JSON-LD context for folder listings
func GetFolderListingContext() interface{} {
	return map[string]interface{}{
		"@vocab": "http://remotestorage.io/spec/folder-listing#",
		"items": map[string]interface{}{
			"@container": "@index",
		},
		"ETag":           "http://www.w3.org/2011/http-headers#etag",
		"Content-Type":   "http://www.w3.org/2011/http-headers#content-type",
		"Content-Length": "http://www.w3.org/2011/http-headers#content-length",
	}
}

// NewFolderListing creates a new folder listing with the appropriate JSON-LD context
func NewFolderListing(metadata Metadata) *FolderListing {
	return &FolderListing{
		LDContext: GetFolderListingContext(),
		Metadata:  metadata,
		Items:     make(map[string]FolderItem),
	}
}
