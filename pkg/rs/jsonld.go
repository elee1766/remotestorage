package rs

// GetFolderListingContext returns the @context value of folder listings.
func GetFolderListingContext() interface{} {
	return FolderDescriptionContext
}

// NewFolderListing creates an empty folder listing.
func NewFolderListing(metadata Metadata) *FolderListing {
	return &FolderListing{
		LDContext: FolderDescriptionContext,
		Metadata:  metadata,
		Items:     make(map[string]FolderItem),
	}
}
