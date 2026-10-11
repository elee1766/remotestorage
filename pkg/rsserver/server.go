package rsserver

import (
	"net/http"
)

// Handler implements the remoteStorage protocol (draft-dejong-remotestorage-27).
// Mount it at the storage root prefix with http.StripPrefix if needed; the
// ResourceResolver sees the stripped request.
//
// Create one with the Builder:
//
//	handler := rsserver.NewBuilder().
//	    WithResourceResolver(resolver).
//	    WithAuthenticator(authenticator).
//	    WithAuthorizer(rsserver.NewScopeCheckingAuthorizer()).
//	    WithStorageProvider(provider).
//	    MustBuild()
type Handler struct {
	resourceResolver ResourceResolver
	authenticator    Authenticator
	authorizer       Authorizer
	storageProvider  StorageProvider
	hooks            ServerHooks
	maxDocumentSize  int64
	queryToken       bool
	cacheControl     func(ref *ResourceRef) string
	errorLog         func(r *http.Request, err error)
	mux              *http.ServeMux
}
