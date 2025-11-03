package rsserver

import (
	"net/http"
)

func (s *Handler) handleDelete(w http.ResponseWriter, r *http.Request) {
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

	// Call optional BeforeDelete hook
	if err := s.hooks.callBeforeDelete(r, authInfo, req); err != nil {
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

	ifMatch := r.Header.Get("If-Match")

	err = storage.Delete(ctx, path, ifMatch)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	s.hooks.callAfterDelete(r, authInfo, req)
}
