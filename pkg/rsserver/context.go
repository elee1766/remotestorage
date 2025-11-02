package rsserver

import (
	"context"
)

// Context keys for RemoteStorage request values
type contextKey string

const (
	authInfoKey contextKey = "rs:auth_info"
)

// WithAuthInfo adds the authentication info to the context
func WithAuthInfo(ctx context.Context, authInfo *AuthInfo) context.Context {
	return context.WithValue(ctx, authInfoKey, authInfo)
}

// AuthInfoFromContext retrieves the authentication info from the context
func AuthInfoFromContext(ctx context.Context) (*AuthInfo, bool) {
	authInfo, ok := ctx.Value(authInfoKey).(*AuthInfo)
	return authInfo, ok
}

