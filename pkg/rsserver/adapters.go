package rsserver

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"anime.bike/remotestorage/pkg/rs"
)

// AuthenticatorFunc adapts a function to Authenticator.
type AuthenticatorFunc func(r *http.Request, token string) (*AuthInfo, error)

func (f AuthenticatorFunc) Authenticate(r *http.Request, token string) (*AuthInfo, error) {
	return f(r, token)
}

// StorageProviderFunc adapts a function to StorageProvider.
type StorageProviderFunc func(ctx context.Context, authInfo *AuthInfo, req *ResourceRequest) (StorageBackend, error)

func (f StorageProviderFunc) GetStorage(ctx context.Context, authInfo *AuthInfo, req *ResourceRequest) (StorageBackend, error) {
	return f(ctx, authInfo, req)
}

// UnescapePath decodes an escaped URL path segment by segment. Encoded
// slashes ("%2F") are rejected because item names must not contain "/".
func UnescapePath(escaped string) (string, error) {
	segs := strings.Split(escaped, "/")
	for i, s := range segs {
		u, err := url.PathUnescape(s)
		if err != nil || strings.Contains(u, "/") {
			return "", NewHTTPError(http.StatusBadRequest, "Invalid path")
		}
		segs[i] = u
	}
	p := strings.Join(segs, "/")
	if err := rs.ValidatePath(p); err != nil {
		return "", NewHTTPError(http.StatusBadRequest, "Invalid path")
	}
	return p, nil
}
