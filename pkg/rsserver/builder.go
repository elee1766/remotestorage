package rsserver

import (
	"fmt"
	"net/http"
)

// Builder provides a fluent API for constructing a Handler
type Builder struct {
	resourceResolver ResourceResolver
	authenticator    Authenticator
	authorizer       Authorizer
	storageProvider  StorageProvider
	hooks            ServerHooks
}

// NewBuilder creates a new Builder
func NewBuilder() *Builder {
	return &Builder{
		hooks: ServerHooks{}, // Always initialized
	}
}

// WithResourceResolver sets the resource resolver
func (b *Builder) WithResourceResolver(r ResourceResolver) *Builder {
	b.resourceResolver = r
	return b
}

// WithAuthenticator sets the authenticator
func (b *Builder) WithAuthenticator(a Authenticator) *Builder {
	b.authenticator = a
	return b
}

// WithAuthorizer sets the authorizer
func (b *Builder) WithAuthorizer(a Authorizer) *Builder {
	b.authorizer = a
	return b
}

// WithStorageProvider sets the storage provider
func (b *Builder) WithStorageProvider(s StorageProvider) *Builder {
	b.storageProvider = s
	return b
}

// WithHooks sets the optional hooks
func (b *Builder) WithHooks(h ServerHooks) *Builder {
	b.hooks = h
	return b
}

// Build creates and returns a Handler
// Returns an error if required components are missing
func (b *Builder) Build() (*Handler, error) {
	// Validate required components
	if b.resourceResolver == nil {
		return nil, fmt.Errorf("ResourceResolver is required")
	}
	if b.authenticator == nil {
		return nil, fmt.Errorf("Authenticator is required")
	}
	if b.authorizer == nil {
		return nil, fmt.Errorf("Authorizer is required")
	}
	if b.storageProvider == nil {
		return nil, fmt.Errorf("StorageProvider is required")
	}

	h := &Handler{
		resourceResolver: b.resourceResolver,
		authenticator:    b.authenticator,
		authorizer:       b.authorizer,
		storageProvider:  b.storageProvider,
		hooks:            b.hooks,
		mux:              http.NewServeMux(),
	}

	h.registerRoutes()

	return h, nil
}

// MustBuild creates and returns a Handler, panicking if there's an error
// Use this when you're confident all required components are set
func (b *Builder) MustBuild() *Handler {
	handler, err := b.Build()
	if err != nil {
		panic(fmt.Sprintf("failed to build Handler: %v", err))
	}
	return handler
}
