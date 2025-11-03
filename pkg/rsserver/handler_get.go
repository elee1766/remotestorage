package rsserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"anime.bike/remotestorage/pkg/rs"
)

func (s *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	// Resolve resource location from URL
	resourceRef, err := s.resourceResolver.ResolveResource(r)
	if err != nil {
		handleHTTPError(w, err)
		return
	}

	// Build resource request with operation type
	req := &ResourceRequest{
		Resource: resourceRef,
		IsWrite:  false,
	}

	// Authenticate - validate token and get user identity
	token := extractBearerToken(r)
	authInfo, err := s.authenticator.Authenticate(r, token)
	if err != nil {
		handleHTTPError(w, err)
		return
	}

	// Authorize - check if user has permission to access this resource
	if err := s.authorizer.Authorize(authInfo, req); err != nil {
		handleHTTPError(w, err)
		return
	}

	// Call optional BeforeRead hook
	if err := s.hooks.callBeforeRead(r, authInfo, req); err != nil {
		handleHTTPError(w, err)
		return
	}

	// Get storage backend
	storage, err := s.storageProvider.GetStorage(r.Context(), authInfo, req)
	if err != nil {
		handleHTTPError(w, err)
		return
	}

	// Store auth info in context for potential use by backend (nil is okay for public reads)
	ctx := WithAuthInfo(r.Context(), authInfo)

	// Dispatch based on request type
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		// Range request - partial content
		s.handleGetRange(w, r, ctx, storage, authInfo, req, rangeHeader)
	} else {
		// Full request
		s.handleGetFull(w, r, ctx, storage, authInfo, req)
	}
}

// handleGetRange handles GET requests with Range header (partial content)
func (s *Handler) handleGetRange(w http.ResponseWriter, r *http.Request, ctx context.Context, storage StorageBackend, authInfo *AuthInfo, req *ResourceRequest, rangeHeader string) {
	// First, get metadata to check If-None-Match before retrieving document body
	metadata, err := storage.Head(ctx, req.Resource.Path)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Check If-None-Match early to avoid retrieving document body
	if checkIfNoneMatch(r, metadata.ETag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	// Parse Range header
	httpRange, err := parseRange(rangeHeader, 0)
	if err != nil {
		handleHTTPError(w, err)
		return
	}

	// Check if storage supports range requests
	rangeStorage, supportsRange := storage.(StorageBackendRange)
	if !supportsRange {
		http.Error(w, "Range requests not supported", http.StatusNotImplemented)
		return
	}

	// Get the document with range
	doc, err := rangeStorage.GetRange(ctx, req.Resource.Path, httpRange.Start, httpRange.End)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if doc == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Calculate actual range bounds for Content-Range header
	start := httpRange.Start
	end := httpRange.End
	total := doc.Metadata.Size

	// Handle suffix range (last N bytes)
	if start == -1 {
		start = total - end
		end = total - 1
	} else if end == -1 {
		// Open-ended range
		end = total - 1
	}

	// Write partial content response
	writeDocumentHeaders(w, &doc.Metadata)
	w.Header().Set("Content-Range", formatContentRange(start, end, total))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", end-start+1))
	w.WriteHeader(http.StatusPartialContent)

	if doc.Body != nil {
		defer doc.Body.Close()
		io.Copy(w, doc.Body)
	}
}

// handleGetFull handles full (non-range) GET requests
func (s *Handler) handleGetFull(w http.ResponseWriter, r *http.Request, ctx context.Context, storage StorageBackend, authInfo *AuthInfo, req *ResourceRequest) {
	// First, get metadata to check If-None-Match before retrieving document body
	metadata, err := storage.Head(ctx, req.Resource.Path)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Check If-None-Match early to avoid retrieving document body
	if checkIfNoneMatch(r, metadata.ETag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	// Now retrieve the full document/listing
	doc, listing, err := storage.Get(ctx, req.Resource.Path)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if listing == nil && doc == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if listing != nil {
		s.respondWithFolderListing(w, r, listing)
	} else if doc != nil {
		s.respondWithDocument(w, r, doc)
	} else {
		panic("unreachable")
	}
}

// respondWithFolderListing writes a folder listing response
func (s *Handler) respondWithFolderListing(w http.ResponseWriter, r *http.Request, listing *rs.FolderListing) {
	// Return folder listing as JSON-LD
	w.Header().Set("Content-Type", "application/ld+json")
	w.Header().Set("Cache-Control", "no-cache")
	if listing.Metadata.ETag != "" {
		w.Header().Set("ETag", listing.Metadata.ETag)
	}

	// Ensure we have the JSON-LD context
	if listing.LDContext == nil {
		listing.LDContext = rs.GetFolderListingContext()
	}

	json.NewEncoder(w).Encode(listing)
}

// respondWithDocument writes a document response
func (s *Handler) respondWithDocument(w http.ResponseWriter, r *http.Request, doc *rs.Document) {
	// Return document
	writeDocumentHeaders(w, &doc.Metadata)
	if doc.Metadata.Size > 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", doc.Metadata.Size))
	}

	if doc.Body != nil {
		defer doc.Body.Close()
		io.Copy(w, doc.Body)
	}
}

// writeDocumentHeaders writes common document headers
func writeDocumentHeaders(w http.ResponseWriter, metadata *rs.Metadata) {
	w.Header().Set("Cache-Control", "no-cache")
	if metadata.ContentType != "" {
		w.Header().Set("Content-Type", metadata.ContentType)
	}
	if metadata.ETag != "" {
		w.Header().Set("ETag", metadata.ETag)
	}
	if !metadata.LastModified.IsZero() {
		w.Header().Set("Last-Modified", metadata.LastModified.UTC().Format(http.TimeFormat))
	}
}
