package rsclient_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsclient"
	"anime.bike/remotestorage/pkg/rsserver"
	"anime.bike/remotestorage/pkg/rsserver/rstest"
	"anime.bike/remotestorage/pkg/webfinger"
)

// server is a TLS remoteStorage server built from the real rsserver handler,
// rstest.MemoryStorage and webfinger.Server. The default HTTP client does not
// trust its certificate, so requests only succeed through WithClient.
type server struct {
	*httptest.Server
	mu     sync.Mutex
	tokens map[string]*rsserver.AuthInfo
}

func newServer(t *testing.T) *server {
	t.Helper()
	s := &server{tokens: map[string]*rsserver.AuthInfo{}}
	var smu sync.Mutex
	stores := map[string]*rstest.MemoryStorage{}

	storage := rsserver.NewBuilder().
		WithResourceResolver(rstest.PathResolver{}).
		WithAuthenticator(rsserver.AuthenticatorFunc(func(_ *http.Request, token string) (*rsserver.AuthInfo, error) {
			if token == "" {
				return nil, nil
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if a, ok := s.tokens[token]; ok {
				return a, nil
			}
			return nil, rsserver.NewHTTPError(http.StatusUnauthorized, "Invalid token")
		})).
		WithAuthorizer(rsserver.NewScopeCheckingAuthorizer()).
		WithStorageProvider(rsserver.StorageProviderFunc(func(_ context.Context, _ *rsserver.AuthInfo, req *rsserver.ResourceRequest) (rsserver.StorageBackend, error) {
			smu.Lock()
			defer smu.Unlock()
			u := req.Resource.RequestedUser
			if stores[u] == nil {
				stores[u] = rstest.NewMemoryStorage()
			}
			return stores[u], nil
		})).
		MustBuild()

	mux := http.NewServeMux()
	mux.Handle("/", storage)
	s.Server = httptest.NewUnstartedServer(mux)
	s.StartTLS()
	t.Cleanup(s.Close)

	host := strings.TrimPrefix(s.URL, "https://")
	mux.Handle("/.well-known/webfinger", webfinger.NewServer(host, webfinger.StorageResolverFunc(func(user string) (*webfinger.UserStorageInfo, error) {
		if user != "alice" {
			return nil, nil
		}
		return &webfinger.UserStorageInfo{
			StorageRoot:   s.URL + "/alice",
			AuthEndpoint:  new(s.URL + "/oauth/authorize"),
			TokenEndpoint: s.URL + "/oauth/token",
		}, nil
	})))
	return s
}

func (s *server) token(t *testing.T, scopes ...string) string {
	t.Helper()
	var parsed []rs.Scope
	for _, sc := range scopes {
		p, err := rs.ParseScope(sc)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, p)
	}
	var b [16]byte
	rand.Read(b[:])
	tok := hex.EncodeToString(b[:])
	s.mu.Lock()
	s.tokens[tok] = &rsserver.AuthInfo{UserID: "alice", Username: "alice", Scopes: parsed}
	s.mu.Unlock()
	return tok
}

func TestDiscover(t *testing.T) {
	s := newServer(t)
	addr := "alice@" + strings.TrimPrefix(s.URL, "https://")

	if _, err := rsclient.Discover(context.Background(), addr, nil); err == nil {
		t.Fatal("discovery with the default client trusted the test certificate")
	}

	info, err := rsclient.Discover(context.Background(), addr, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	if info.Href != s.URL+"/alice" {
		t.Fatalf("Href %q", info.Href)
	}
	props := rs.NewRemoteStorageProperties(info.Properties)
	if props.GetVersion() != string(rs.SupportedVersion) {
		t.Fatalf("version %q", props.GetVersion())
	}
	if auth, err := rsclient.GetAuthURL(info); err != nil || auth != s.URL+"/oauth/authorize" {
		t.Fatalf("GetAuthURL %q %v", auth, err)
	}
	authz, tok, ok := rsclient.GetPKCEEndpoints(info)
	if !ok || authz != s.URL+"/oauth/authorize" || tok != s.URL+"/oauth/token" {
		t.Fatalf("GetPKCEEndpoints %q %q %v", authz, tok, ok)
	}

	if _, err := rsclient.Discover(context.Background(), "bob@"+strings.TrimPrefix(s.URL, "https://"), s.Client()); err == nil {
		t.Fatal("unknown user discovered")
	}
}

func TestWithClient(t *testing.T) {
	s := newServer(t)
	c := rsclient.NewWithToken(s.URL+"/alice", s.token(t, "notes:rw"))

	if c.HTTPClient() != http.DefaultClient {
		t.Fatal("default HTTP client not used when none is set")
	}
	if _, err := c.Get("/notes/"); err == nil {
		t.Fatal("request succeeded without the TLS-trusting client")
	}

	var n int
	hc := s.Client()
	base := hc.Transport
	hc.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		n++
		return base.RoundTrip(r)
	})
	c.WithClient(hc)

	dir := t.TempDir()
	local := filepath.Join(dir, "a.txt")
	os.WriteFile(local, []byte("hi"), 0o644)
	if _, err := c.UploadFile(local, "/notes/a.txt", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetFileInfo("/notes/a.txt"); err != nil {
		t.Fatal(err)
	}
	if err := c.DownloadFile("/notes/a.txt", filepath.Join(dir, "b.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListDirectory("/notes"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteFile("/notes/a.txt", ""); err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("attached client saw %d requests, want 5", n)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFileLifecycle(t *testing.T) {
	s := newServer(t)
	c := rsclient.NewWithToken(s.URL+"/alice/", s.token(t, "notes:rw")).WithClient(s.Client())
	dir := t.TempDir()

	content := []byte(`{"title":"first"}`)
	local := filepath.Join(dir, "note.json")
	os.WriteFile(local, content, 0o644)
	etag, err := c.UploadFile(local, "/notes/2026/note.json", "")
	if err != nil {
		t.Fatal(err)
	}
	if etag == "" {
		t.Fatal("upload returned no ETag")
	}

	info, err := c.GetFileInfo("/notes/2026/note.json")
	if err != nil {
		t.Fatal(err)
	}
	if info.ETag != etag || info.ContentType != "application/json" || info.Size != int64(len(content)) || info.Name != "note.json" {
		t.Fatalf("info %+v, upload ETag %q", info, etag)
	}
	if info.LastModified.IsZero() {
		t.Fatal("no Last-Modified")
	}

	out := filepath.Join(dir, "sub", "copy.json")
	if err := c.DownloadFile("/notes/2026/note.json", out); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, content) {
		t.Fatalf("downloaded %q", got)
	}

	root, err := c.ListDirectory("/notes/")
	if err != nil {
		t.Fatal(err)
	}
	if root.Metadata.ETag == "" || !root.Metadata.IsFolder {
		t.Fatalf("root listing metadata %+v", root.Metadata)
	}
	if _, ok := root.Items["2026/"]; !ok || len(root.Items) != 1 {
		t.Fatalf("root items %v", root.Items)
	}
	sub, err := c.ListDirectory("/notes/2026")
	if err != nil {
		t.Fatal(err)
	}
	item, ok := sub.Items["note.json"]
	if !ok || item.ETag != strings.Trim(etag, `"`) || item.ContentLength != int64(len(content)) || item.ContentType != "application/json" {
		t.Fatalf("listing item %+v (upload ETag %s)", item, etag)
	}

	// Conditional update through the raw Put.
	resp, err := c.Put("/notes/2026/note.json", strings.NewReader(`{"title":"x"}`), "application/json", `"stale"`)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match: %d", resp.StatusCode)
	}
	resp, err = c.Put("/notes/2026/note.json", strings.NewReader(`{"title":"second"}`), "application/json", etag)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	newETag := resp.Header.Get("ETag")
	if resp.StatusCode != http.StatusOK || newETag == "" || newETag == etag {
		t.Fatalf("matching If-Match: %d, ETag %q", resp.StatusCode, newETag)
	}
	after, err := c.ListDirectory("/notes/")
	if err != nil {
		t.Fatal(err)
	}
	if after.Metadata.ETag == root.Metadata.ETag {
		t.Fatal("folder ETag unchanged after update")
	}

	if err := c.DeleteFile("/notes/2026/note.json", etag); err == nil {
		t.Fatal("delete with stale ETag succeeded")
	}
	if err := c.DeleteFile("/notes/2026/note.json", newETag); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetFileInfo("/notes/2026/note.json"); err == nil {
		t.Fatal("deleted document still has info")
	}
	if err := c.DownloadFile("/notes/2026/note.json", filepath.Join(dir, "gone")); err == nil {
		t.Fatal("deleted document downloaded")
	}
	empty, err := c.ListDirectory("/notes/")
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Items) != 0 {
		t.Fatalf("emptied folder lists %v", empty.Items)
	}
}

func TestAccessControl(t *testing.T) {
	s := newServer(t)
	writer := rsclient.NewWithToken(s.URL+"/alice", s.token(t, "notes:rw")).WithClient(s.Client())
	reader := rsclient.NewWithToken(s.URL+"/alice", s.token(t, "notes:r")).WithClient(s.Client())
	anon := rsclient.New(s.URL+"/alice", nil).WithClient(s.Client())
	bad := rsclient.NewWithToken(s.URL+"/alice", "not-a-token").WithClient(s.Client())

	local := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(local, []byte("x"), 0o644)
	if _, err := writer.UploadFile(local, "/notes/x.txt", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.UploadFile(local, "/public/notes/x.txt", ""); err != nil {
		t.Fatal(err)
	}

	if _, err := reader.GetFileInfo("/notes/x.txt"); err != nil {
		t.Fatalf("read-only token cannot read: %v", err)
	}
	if _, err := reader.UploadFile(local, "/notes/y.txt", ""); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("read-only upload: %v", err)
	}
	if err := reader.DeleteFile("/notes/x.txt", ""); err == nil {
		t.Fatal("read-only token deleted a document")
	}
	if _, err := writer.UploadFile(local, "/other/x.txt", ""); err == nil {
		t.Fatal("token wrote outside its scope")
	}

	if _, err := anon.ListDirectory("/notes/"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("anonymous listing: %v", err)
	}
	if _, err := bad.GetFileInfo("/notes/x.txt"); err == nil {
		t.Fatal("invalid token read a document")
	}
	if _, err := anon.GetFileInfo("/public/notes/x.txt"); err != nil {
		t.Fatalf("anonymous public read: %v", err)
	}
	if _, err := anon.ListDirectory("/public/notes/"); err == nil {
		t.Fatal("anonymous client listed a public folder")
	}
}
