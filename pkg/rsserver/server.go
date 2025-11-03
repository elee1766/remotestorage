package rsserver

import (
	"net/http"
)

// Handler implements the RemoteStorage server protocol.
//
// To create a Handler, use the Builder:
//
//	handler := rsserver.NewBuilder().
//	    WithResourceResolver(resolver).
//	    WithAuthenticator(authenticator).
//	    WithAuthorizer(authorizer).
//	    WithStorageProvider(provider).
//	    WithHooks(hooks).
//	    Build()
type Handler struct {
	resourceResolver ResourceResolver
	authenticator    Authenticator
	authorizer       Authorizer
	storageProvider  StorageProvider
	hooks            ServerHooks
	mux              *http.ServeMux
}

// ServeHTTP implements http.Handler
func (s *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// registerRoutes sets up the HTTP routes for the handler
func (s *Handler) registerRoutes() {
	s.mux.HandleFunc("GET /{path...}", s.handleGet)
	s.mux.HandleFunc("PUT /{path...}", s.handlePut)
	s.mux.HandleFunc("DELETE /{path...}", s.handleDelete)
	s.mux.HandleFunc("HEAD /{path...}", s.handleHead)
}
