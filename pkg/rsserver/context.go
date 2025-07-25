package rsserver

import (
	"context"

	"anime.bike/remotestorage/pkg/rs"
)

// Context keys for RemoteStorage request values
type contextKey string

const (
	userIDKey contextKey = "rs:user_id"
	scopesKey contextKey = "rs:scopes"
)

// WithUserID adds the user ID to the context
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// UserIDFromContext retrieves the user ID from the context
func UserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(userIDKey).(string)
	return userID, ok
}

// WithScopes adds the scopes to the context
func WithScopes(ctx context.Context, scopes []rs.Scope) context.Context {
	return context.WithValue(ctx, scopesKey, scopes)
}

// ScopesFromContext retrieves the scopes from the context
func ScopesFromContext(ctx context.Context) ([]rs.Scope, bool) {
	scopes, ok := ctx.Value(scopesKey).([]rs.Scope)
	return scopes, ok
}

