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
	maxDocumentSize  int64
	queryToken       bool
	cacheControl     func(ref *ResourceRef) string
	errorLog         func(r *http.Request, err error)
}

// NewBuilder creates a new Builder
func NewBuilder() *Builder {
	return &Builder{}
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

// WithMaxDocumentSize rejects documents larger than n bytes with 413. 0 means no limit.
func (b *Builder) WithMaxDocumentSize(n int64) *Builder {
	b.maxDocumentSize = n
	return b
}

// WithQueryToken accepts the bearer token in the access_token query
// parameter on GET requests (RFC 6750 section 2.3). Advertise it in WebFinger
// when enabled.
func (b *Builder) WithQueryToken(enabled bool) *Builder {
	b.queryToken = enabled
	return b
}

// WithCacheControl sets the Cache-Control value for GET and HEAD responses.
// Defaults to DefaultCacheControl. The value must include no-cache (spec section 4).
func (b *Builder) WithCacheControl(f func(ref *ResourceRef) string) *Builder {
	b.cacheControl = f
	return b
}

// WithErrorLog sets the function called for unexpected (500) errors.
// The default logs with slog.
func (b *Builder) WithErrorLog(f func(r *http.Request, err error)) *Builder {
	b.errorLog = f
	return b
}

// Build creates and returns a Handler
// Returns an error if required components are missing
func (b *Builder) Build() (*Handler, error) {
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
		maxDocumentSize:  b.maxDocumentSize,
		queryToken:       b.queryToken,
		cacheControl:     b.cacheControl,
		errorLog:         b.errorLog,
		mux:              http.NewServeMux(),
	}
	if h.cacheControl == nil {
		h.cacheControl = DefaultCacheControl
	}
	h.registerRoutes()
	return h, nil
}

// MustBuild creates and returns a Handler, panicking if there's an error
func (b *Builder) MustBuild() *Handler {
	handler, err := b.Build()
	if err != nil {
		panic(fmt.Sprintf("failed to build Handler: %v", err))
	}
	return handler
}
