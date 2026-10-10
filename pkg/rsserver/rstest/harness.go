package rstest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"
)

// Harness serves rsserver.Handler with path-based users (/<user>/<path>) and
// an in-memory token table, so a StorageBackend can be tested with Run.
type Harness struct {
	Server *httptest.Server
	mu     sync.Mutex
	tokens map[string]*rsserver.AuthInfo
}

// NewHarness starts a test server. storage returns the backend of a user.
func NewHarness(t *testing.T, storage func(user string) (rsserver.StorageBackend, error), opts ...func(*rsserver.Builder)) *Harness {
	h := &Harness{tokens: map[string]*rsserver.AuthInfo{}}
	b := rsserver.NewBuilder().
		WithResourceResolver(PathResolver{}).
		WithAuthenticator(rsserver.AuthenticatorFunc(h.authenticate)).
		WithAuthorizer(rsserver.NewScopeCheckingAuthorizer()).
		WithStorageProvider(rsserver.StorageProviderFunc(func(_ context.Context, _ *rsserver.AuthInfo, req *rsserver.ResourceRequest) (rsserver.StorageBackend, error) {
			return storage(req.Resource.RequestedUser)
		}))
	for _, o := range opts {
		o(b)
	}
	h.Server = httptest.NewServer(b.MustBuild())
	t.Cleanup(h.Server.Close)
	return h
}

func (h *Harness) authenticate(_ *http.Request, token string) (*rsserver.AuthInfo, error) {
	if token == "" {
		return nil, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	a, ok := h.tokens[token]
	if !ok {
		return nil, rsserver.NewHTTPError(http.StatusUnauthorized, "Invalid token")
	}
	return a, nil
}

// Token issues a token for user with the given scopes.
func (h *Harness) Token(user string, scopes ...string) string {
	var parsed []rs.Scope
	for _, s := range scopes {
		sc, err := rs.ParseScope(s)
		if err != nil {
			panic(err)
		}
		parsed = append(parsed, sc)
	}
	var b [16]byte
	rand.Read(b[:])
	tok := hex.EncodeToString(b[:])
	h.mu.Lock()
	h.tokens[tok] = &rsserver.AuthInfo{UserID: user, Username: user, Scopes: parsed}
	h.mu.Unlock()
	return tok
}

// Target returns a Target for user, with "other-"+user as the isolation user.
func (h *Harness) Target(user string) Target {
	return Target{
		StorageRoot:   h.Server.URL + "/" + user,
		OtherUserRoot: h.Server.URL + "/other-" + user,
		Token: func(_ *testing.T, scopes ...string) string {
			return h.Token(user, scopes...)
		},
	}
}

// PathResolver maps /<user>/<path> to a resource. The raw (escaped) path is
// used so encoded slashes are not mistaken for separators.
type PathResolver struct{}

func (PathResolver) ResolveResource(r *http.Request) (*rsserver.ResourceRef, error) {
	raw := r.URL.EscapedPath()
	rest := strings.TrimPrefix(raw, "/")
	user, p, ok := strings.Cut(rest, "/")
	if !ok || user == "" {
		return nil, rsserver.NewHTTPError(http.StatusNotFound, "Not found")
	}
	path, err := rsserver.UnescapePath("/" + p)
	if err != nil {
		return nil, err
	}
	return &rsserver.ResourceRef{RequestedUser: user, Path: path}, nil
}
