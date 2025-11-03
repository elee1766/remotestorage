package rsserver

import (
	"errors"
	"net/http"
)

// ServerHooks provides optional callbacks for various server lifecycle events
// All hooks are optional - nil hooks will be skipped
type ServerHooks struct {
	// BeforeWrite is called after authentication but before processing PUT requests
	// Can validate AND modify the request (e.g., check quotas, rate limits)
	// Return HTTPError with appropriate status code if validation fails
	BeforeWrite func(r *http.Request, authInfo *AuthInfo, req *ResourceRequest) error

	// BeforeRead is called after authentication but before processing GET/HEAD requests
	// Can be used for access logging, analytics, etc.
	BeforeRead func(r *http.Request, authInfo *AuthInfo, req *ResourceRequest) error

	// BeforeDelete is called after authentication but before processing DELETE requests
	// Can be used for additional validation, soft deletes, etc.
	BeforeDelete func(r *http.Request, authInfo *AuthInfo, req *ResourceRequest) error

	// AfterWrite is called after successfully processing a PUT request
	// Can be used for logging, cache invalidation, webhooks, etc.
	// Errors from this hook are logged but don't affect the response
	AfterWrite func(r *http.Request, authInfo *AuthInfo, req *ResourceRequest, etag string)

	// AfterRead is called after successfully processing a GET/HEAD request
	// Can be used for access analytics, usage tracking, etc.
	// Errors from this hook are logged but don't affect the response
	AfterRead func(r *http.Request, authInfo *AuthInfo, req *ResourceRequest)

	// AfterDelete is called after successfully processing a DELETE request
	// Can be used for cleanup, logging, webhooks, etc.
	// Errors from this hook are logged but don't affect the response
	AfterDelete func(r *http.Request, authInfo *AuthInfo, req *ResourceRequest)
}

// callBeforeWrite calls the BeforeWrite hook if it exists
func (h ServerHooks) callBeforeWrite(r *http.Request, authInfo *AuthInfo, req *ResourceRequest) error {
	if h.BeforeWrite != nil {
		return h.BeforeWrite(r, authInfo, req)
	}
	return nil
}

// callBeforeRead calls the BeforeRead hook if it exists
func (h ServerHooks) callBeforeRead(r *http.Request, authInfo *AuthInfo, req *ResourceRequest) error {
	if h.BeforeRead != nil {
		return h.BeforeRead(r, authInfo, req)
	}
	return nil
}

// callBeforeDelete calls the BeforeDelete hook if it exists
func (h ServerHooks) callBeforeDelete(r *http.Request, authInfo *AuthInfo, req *ResourceRequest) error {
	if h.BeforeDelete != nil {
		return h.BeforeDelete(r, authInfo, req)
	}
	return nil
}

// callAfterWrite calls the AfterWrite hook if it exists
func (h ServerHooks) callAfterWrite(r *http.Request, authInfo *AuthInfo, req *ResourceRequest, etag string) {
	if h.AfterWrite != nil {
		h.AfterWrite(r, authInfo, req, etag)
	}
}

// callAfterRead calls the AfterRead hook if it exists
func (h ServerHooks) callAfterRead(r *http.Request, authInfo *AuthInfo, req *ResourceRequest) {
	if h.AfterRead != nil {
		h.AfterRead(r, authInfo, req)
	}
}

// callAfterDelete calls the AfterDelete hook if it exists
func (h ServerHooks) callAfterDelete(r *http.Request, authInfo *AuthInfo, req *ResourceRequest) {
	if h.AfterDelete != nil {
		h.AfterDelete(r, authInfo, req)
	}
}

// handleHTTPError handles an error by checking if it's an HTTPError and responding appropriately
// Returns true if the error was handled, false otherwise
func handleHTTPError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}

	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		if httpErr.StatusCode == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", "Bearer")
		}
		http.Error(w, httpErr.Message, httpErr.StatusCode)
		return true
	}

	// Not an HTTPError, return generic error
	http.Error(w, "Internal server error", http.StatusInternalServerError)
	return true
}
