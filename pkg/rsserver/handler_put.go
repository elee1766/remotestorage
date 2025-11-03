package rsserver

import (
	"errors"
	"net/http"

	"anime.bike/remotestorage/pkg/rs"
)

func (s *Handler) handlePut(w http.ResponseWriter, r *http.Request) {
	// Resolve resource location from URL
	resourceRef, err := s.resourceResolver.ResolveResource(r)
	if err != nil {
		handleHTTPError(w, err)
		return
	}

	// Build resource request with operation type
	req := &ResourceRequest{
		Resource: resourceRef,
		IsWrite:  true,
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

	// Call optional BeforeWrite hook (validate, wrap body stream, check quotas, etc.)
	if err := s.hooks.callBeforeWrite(r, authInfo, req); err != nil {
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

	defer r.Body.Close()

	contentType := r.Header.Get("Content-Type")
	ifMatch := r.Header.Get("If-Match")
	ifNoneMatch := r.Header.Get("If-None-Match")

	var etag string

	// Validate If-None-Match: spec only defines "*" for PUT requests
	if ifNoneMatch != "" && ifNoneMatch != "*" {
		http.Error(w, "Bad Request: If-None-Match must be '*' for PUT requests", http.StatusBadRequest)
		return
	}

	// If-Match header means update existing document
	if ifMatch != "" {
		etag, err = storage.Update(ctx, path, r.Body, contentType, ifMatch)
		if err != nil {
			if errors.Is(err, rs.ErrNotFound) {
				http.Error(w, "Not found", http.StatusNotFound)
			} else if errors.Is(err, rs.ErrPreconditionFailed) {
				http.Error(w, "Precondition Failed", http.StatusPreconditionFailed)
			} else {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
			return
		}
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
		s.hooks.callAfterWrite(r, authInfo, req, etag)
		return
	}

	// Otherwise (If-None-Match: * or no precondition) - create only
	// Per spec: If-None-Match: * MUST fail if document exists
	// Our interpretation: no precondition also creates only (strict mode)
	etag, err = storage.Create(ctx, path, r.Body, contentType)
	if err != nil {
		if errors.Is(err, rs.ErrAlreadyExists) {
			// Per spec: include current ETag in 412 response so client knows what exists
			if meta, err := storage.Head(ctx, path); err == nil && meta.ETag != "" {
				w.Header().Set("ETag", meta.ETag)
			}
			http.Error(w, "Precondition Failed", http.StatusPreconditionFailed)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusCreated)
	s.hooks.callAfterWrite(r, authInfo, req, etag)
}
