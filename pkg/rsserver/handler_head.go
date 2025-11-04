package rsserver

import (
	"fmt"
	"net/http"
)

func (s *Handler) handleHead(w http.ResponseWriter, r *http.Request) {
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

	// Store auth info in context
	ctx := WithAuthInfo(r.Context(), authInfo)
	path := resourceRef.Path
	metadata, err := storage.Head(ctx, path)
	if err != nil {
		handleHTTPError(w, handleStorageError(err))
		return
	}

	// Per spec: public folders (not documents) require authentication
	if metadata.IsFolder && authInfo == nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if metadata.ContentType != "" {
		w.Header().Set("Content-Type", metadata.ContentType)
	}
	if metadata.ETag != "" {
		w.Header().Set("ETag", metadata.ETag)
	}
	if !metadata.LastModified.IsZero() {
		w.Header().Set("Last-Modified", metadata.LastModified.UTC().Format(http.TimeFormat))
	}
	if metadata.Size > 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", metadata.Size))
	}

	w.WriteHeader(http.StatusOK)
	s.hooks.callAfterRead(r, authInfo, req)
}
