// Package rstest is a black-box conformance suite for remoteStorage servers
// (draft-dejong-remotestorage-27). It talks HTTP only, so it can test any
// server, including ones not built on rsserver.
package rstest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"anime.bike/remotestorage/pkg/rs"
)

// Target describes the server under test.
type Target struct {
	// StorageRoot is the storage root URL without trailing slash, e.g. https://host/storage/alice.
	StorageRoot string
	// Token returns a bearer token for the user with exactly the given scopes.
	Token func(t *testing.T, scopes ...string) string
	// OtherUserRoot is the storage root of a second user, used to test isolation. Optional.
	OtherUserRoot string
	// MaxDocumentSize, if > 0, is the configured upload limit.
	MaxDocumentSize int64
	// PrivateCaching checks that authenticated responses are "private" and public
	// documents "public" (rsserver.DefaultCacheControl). Otherwise only no-cache is required.
	PrivateCaching bool
	// Client defaults to http.DefaultClient.
	Client *http.Client
}

// Run runs the whole suite. Each run uses a fresh random module so suites can
// share a server.
func Run(t *testing.T, tg Target) {
	c := &client{t: t, tg: tg, http: tg.Client}
	if c.http == nil {
		c.http = http.DefaultClient
	}
	mod := fmt.Sprintf("rstest%d", time.Now().UnixNano())
	full := tg.Token(t, mod+":rw")
	c.mod, c.tok = mod, full

	t.Run("CORS", c.testCORS)
	t.Run("Auth", c.testAuth)
	t.Run("Documents", c.testDocuments)
	t.Run("Folders", c.testFolders)
	t.Run("Versioning", c.testVersioning)
	t.Run("Conditional", c.testConditional)
	t.Run("Conflicts", c.testConflicts)
	t.Run("Paths", c.testPaths)
	t.Run("Public", c.testPublic)
	t.Run("Range", c.testRange)
	t.Run("Chunked", c.testChunked)
	if tg.MaxDocumentSize > 0 {
		t.Run("TooLarge", c.testTooLarge)
	}
	if tg.OtherUserRoot != "" {
		t.Run("Isolation", c.testIsolation)
	}
}

type client struct {
	t    *testing.T
	tg   Target
	http *http.Client
	mod  string
	tok  string
}

type resp struct {
	*http.Response
	body []byte
}

func (c *client) do(t *testing.T, method, url, token string, body io.Reader, hdr ...string) *resp {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "text/plain")
	}
	res, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return &resp{Response: res, body: b}
}

func (c *client) url(p string) string { return c.tg.StorageRoot + p }

func (c *client) put(t *testing.T, p, body string, hdr ...string) *resp {
	t.Helper()
	return c.do(t, "PUT", c.url(p), c.tok, strings.NewReader(body), hdr...)
}

func (c *client) get(t *testing.T, p string, hdr ...string) *resp {
	t.Helper()
	return c.do(t, "GET", c.url(p), c.tok, nil, hdr...)
}

func (c *client) del(t *testing.T, p string, hdr ...string) *resp {
	t.Helper()
	return c.do(t, "DELETE", c.url(p), c.tok, nil, hdr...)
}

func expect(t *testing.T, r *resp, status int, what string) {
	t.Helper()
	if r.StatusCode != status {
		t.Fatalf("%s: %s %s: got %d, want %d; body %q", what, r.Request.Method, r.Request.URL.Path, r.StatusCode, status, truncate(r.body))
	}
}

func truncate(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}

// etag returns the unquoted strong ETag of a response and checks its form.
func etag(t *testing.T, r *resp) string {
	t.Helper()
	v := r.Header.Get("ETag")
	if v == "" {
		t.Fatalf("%s %s: missing ETag header", r.Request.Method, r.Request.URL.Path)
	}
	if strings.HasPrefix(v, "W/") || len(v) < 3 || v[0] != '"' || v[len(v)-1] != '"' {
		t.Fatalf("%s %s: ETag %q is not a quoted strong validator", r.Request.Method, r.Request.URL.Path, v)
	}
	return v[1 : len(v)-1]
}

type listing struct {
	Context string                     `json:"@context"`
	Items   map[string]json.RawMessage `json:"items"`
}

type docDesc struct {
	ETag          *string `json:"ETag"`
	ContentType   *string `json:"Content-Type"`
	ContentLength *int64  `json:"Content-Length"`
	LastModified  *string `json:"Last-Modified"`
}

func (c *client) list(t *testing.T, p string) (listing, string) {
	t.Helper()
	r := c.get(t, p)
	expect(t, r, 200, "folder GET")
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/ld+json") {
		t.Fatalf("folder %s: Content-Type %q, want application/ld+json", p, ct)
	}
	if cc := r.Header.Get("Cache-Control"); !strings.Contains(cc, "no-cache") {
		t.Fatalf("folder %s: Cache-Control %q, want no-cache", p, cc)
	}
	var l listing
	if err := json.Unmarshal(r.body, &l); err != nil {
		t.Fatalf("folder %s: invalid JSON: %v", p, err)
	}
	if l.Context != rs.FolderDescriptionContext {
		t.Fatalf("folder %s: @context %q", p, l.Context)
	}
	if l.Items == nil {
		t.Fatalf("folder %s: items missing", p)
	}
	return l, etag(t, r)
}

func (c *client) testCORS(t *testing.T) {
	r := c.do(t, "OPTIONS", c.url("/"+c.mod+"/x"), "", nil,
		"Origin", "https://app.example", "Access-Control-Request-Method", "PUT",
		"Access-Control-Request-Headers", "authorization,content-type,if-match,if-none-match")
	if r.StatusCode < 200 || r.StatusCode > 299 {
		t.Fatalf("preflight: status %d", r.StatusCode)
	}
	if r.Header.Get("Access-Control-Allow-Origin") == "" {
		t.Fatal("preflight: no Access-Control-Allow-Origin")
	}
	methods := strings.ToUpper(r.Header.Get("Access-Control-Allow-Methods"))
	for _, m := range []string{"GET", "PUT", "DELETE", "HEAD"} {
		if !strings.Contains(methods, m) {
			t.Fatalf("preflight: Allow-Methods %q lacks %s", methods, m)
		}
	}
	headers := strings.ToLower(r.Header.Get("Access-Control-Allow-Headers"))
	for _, h := range []string{"authorization", "content-type", "if-match", "if-none-match"} {
		if !strings.Contains(headers, h) && headers != "*" {
			t.Fatalf("preflight: Allow-Headers %q lacks %s", headers, h)
		}
	}
	// Normal and error responses carry CORS headers and expose ETag.
	for _, r := range []*resp{
		c.get(t, "/"+c.mod+"/", "Origin", "https://app.example"),
		c.do(t, "GET", c.url("/"+c.mod+"/missing"), "", nil, "Origin", "https://app.example"),
	} {
		if r.Header.Get("Access-Control-Allow-Origin") == "" {
			t.Fatalf("%d response: no Access-Control-Allow-Origin", r.StatusCode)
		}
		if !strings.Contains(strings.ToLower(r.Header.Get("Access-Control-Expose-Headers")), "etag") {
			t.Fatalf("%d response: ETag not exposed", r.StatusCode)
		}
	}
}

func (c *client) testAuth(t *testing.T) {
	p := "/" + c.mod + "/auth.txt"
	expect(t, c.put(t, p, "a"), 201, "create")

	expect(t, c.do(t, "GET", c.url(p), "", nil), 401, "no token")
	if r := c.do(t, "GET", c.url(p), "", nil); r.Header.Get("WWW-Authenticate") == "" {
		t.Fatal("401 without WWW-Authenticate")
	}
	expect(t, c.do(t, "GET", c.url(p), "not-a-valid-token", nil), 401, "bad token")
	expect(t, c.do(t, "PUT", c.url(p), "", strings.NewReader("x"), "Content-Type", "text/plain"), 401, "PUT no token")

	ro := c.tg.Token(t, c.mod+":r")
	expect(t, c.do(t, "GET", c.url(p), ro, nil), 200, "read scope GET")
	expect(t, c.do(t, "GET", c.url("/"+c.mod+"/"), ro, nil), 200, "read scope folder")
	expect(t, c.do(t, "PUT", c.url(p), ro, strings.NewReader("x"), "Content-Type", "text/plain"), 403, "read scope PUT")
	expect(t, c.do(t, "DELETE", c.url(p), ro, nil), 403, "read scope DELETE")

	other := c.tg.Token(t, "othermodule:rw")
	expect(t, c.do(t, "GET", c.url(p), other, nil), 403, "other module")
	expect(t, c.do(t, "GET", c.url("/"), other, nil), 403, "root folder needs *")

	all := c.tg.Token(t, "*:r")
	expect(t, c.do(t, "GET", c.url(p), all, nil), 200, "*:r GET")
	expect(t, c.do(t, "GET", c.url("/"), all, nil), 200, "*:r root")
	expect(t, c.do(t, "PUT", c.url(p), all, strings.NewReader("x"), "Content-Type", "text/plain"), 403, "*:r PUT")

	// A module scope also covers /public/<module>/.
	pub := "/public/" + c.mod + "/auth.txt"
	expect(t, c.put(t, pub, "p"), 201, "rw scope covers public module")
	expect(t, c.do(t, "PUT", c.url("/public/othermodule/x"), c.tok, strings.NewReader("x"), "Content-Type", "text/plain"), 403, "public other module")
	expect(t, c.del(t, pub), 200, "cleanup")
	expect(t, c.del(t, p), 200, "cleanup")
}

func (c *client) testDocuments(t *testing.T) {
	p := "/" + c.mod + "/docs/hello.json"
	body := `{"hello":"world"}`
	r := c.put(t, p, body, "Content-Type", "application/json")
	expect(t, r, 201, "create")
	e1 := etag(t, r)

	r = c.get(t, p)
	expect(t, r, 200, "GET")
	if string(r.body) != body {
		t.Fatalf("body %q", r.body)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type %q, want application/json", ct)
	}
	if cl := r.Header.Get("Content-Length"); cl != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length %q", cl)
	}
	if got := etag(t, r); got != e1 {
		t.Fatalf("GET ETag %q, PUT returned %q", got, e1)
	}
	c.checkCache(t, r, "document", "private")
	if lm := r.Header.Get("Last-Modified"); lm != "" {
		if _, err := http.ParseTime(lm); err != nil {
			t.Fatalf("Last-Modified %q is not an HTTP-date", lm)
		}
	}

	h := c.do(t, "HEAD", c.url(p), c.tok, nil)
	expect(t, h, 200, "HEAD")
	if etag(t, h) != e1 || len(h.body) != 0 || h.Header.Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Fatalf("HEAD headers do not match GET")
	}

	// Overwrite without conditions.
	r = c.put(t, p, `{"v":2}`, "Content-Type", "application/json")
	if r.StatusCode != 200 && r.StatusCode != 201 {
		t.Fatalf("overwrite: status %d", r.StatusCode)
	}
	e2 := etag(t, r)
	if e2 == e1 {
		t.Fatal("ETag did not change after overwrite")
	}
	if g := c.get(t, p); string(g.body) != `{"v":2}` {
		t.Fatalf("after overwrite: %q", g.body)
	}

	// Content-Type is stored as sent.
	r = c.put(t, p, "plain", "Content-Type", "text/plain; charset=utf-8")
	if g := c.get(t, p); g.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type not stored: %q", g.Header.Get("Content-Type"))
	}

	// Empty document.
	e := "/" + c.mod + "/docs/empty"
	expect(t, c.put(t, e, ""), 201, "create empty")
	g := c.get(t, e)
	expect(t, g, 200, "get empty")
	if len(g.body) != 0 || g.Header.Get("Content-Length") != "0" {
		t.Fatalf("empty document: len %d, Content-Length %q", len(g.body), g.Header.Get("Content-Length"))
	}

	// Binary content round trip.
	bin := make([]byte, 256)
	for i := range bin {
		bin[i] = byte(i)
	}
	bp := "/" + c.mod + "/docs/bin"
	expect(t, c.do(t, "PUT", c.url(bp), c.tok, bytes.NewReader(bin), "Content-Type", "application/octet-stream"), 201, "binary")
	if g := c.get(t, bp); !bytes.Equal(g.body, bin) {
		t.Fatal("binary content changed")
	}

	r = c.del(t, p)
	expect(t, r, 200, "DELETE")
	expect(t, c.get(t, p), 404, "GET after delete")
	expect(t, c.do(t, "HEAD", c.url(p), c.tok, nil), 404, "HEAD after delete")
	expect(t, c.del(t, p), 404, "DELETE missing")
	for _, q := range []string{e, bp} {
		expect(t, c.del(t, q), 200, "cleanup")
	}
}

func (c *client) testFolders(t *testing.T) {
	base := "/" + c.mod + "/f/"
	// A folder that never existed is empty, not 404.
	l, _ := c.list(t, base)
	if len(l.Items) != 0 {
		t.Fatalf("new folder has items: %v", l.Items)
	}

	expect(t, c.put(t, base+"a/b/c.txt", "abc", "Content-Type", "text/plain"), 201, "deep create")
	expect(t, c.put(t, base+"top.txt", "t", "Content-Type", "text/plain"), 201, "create")

	l, _ = c.list(t, base)
	if len(l.Items) != 2 {
		t.Fatalf("items %v, want a/ and top.txt", keys(l.Items))
	}
	var fd map[string]json.RawMessage
	json.Unmarshal(l.Items["a/"], &fd)
	if len(fd) != 1 || fd["ETag"] == nil {
		t.Fatalf("folder description %s, want only ETag", l.Items["a/"])
	}
	var dd docDesc
	json.Unmarshal(l.Items["top.txt"], &dd)
	if dd.ETag == nil || dd.ContentType == nil || dd.ContentLength == nil || dd.LastModified == nil {
		t.Fatalf("document description %s lacks fields", l.Items["top.txt"])
	}
	if *dd.ContentType != "text/plain" || *dd.ContentLength != 1 {
		t.Fatalf("document description %s", l.Items["top.txt"])
	}
	if _, err := http.ParseTime(*dd.LastModified); err != nil {
		t.Fatalf("Last-Modified %q is not an HTTP-date", *dd.LastModified)
	}
	if strings.Contains(*dd.ETag, `"`) {
		t.Fatalf("ETag in listing %q contains quotes", *dd.ETag)
	}
	if h := c.do(t, "HEAD", c.url(base+"top.txt"), c.tok, nil); etag(t, h) != *dd.ETag {
		t.Fatalf("listing ETag %q != document ETag %q", *dd.ETag, etag(t, h))
	}

	// Zero-length document lists Content-Length 0.
	expect(t, c.put(t, base+"zero", ""), 201, "create")
	l, _ = c.list(t, base)
	json.Unmarshal(l.Items["zero"], &dd)
	if dd.ContentLength == nil || *dd.ContentLength != 0 {
		t.Fatalf("zero-length doc listing %s", l.Items["zero"])
	}
	expect(t, c.del(t, base+"zero"), 200, "cleanup")

	// Deleting the last document removes empty ancestors from listings.
	expect(t, c.del(t, base+"a/b/c.txt"), 200, "delete deep")
	l, _ = c.list(t, base)
	if _, ok := l.Items["a/"]; ok {
		t.Fatalf("empty folder still listed: %v", keys(l.Items))
	}
	l, _ = c.list(t, base+"a/")
	if len(l.Items) != 0 {
		t.Fatalf("emptied folder has items: %v", keys(l.Items))
	}

	// Folder HEAD.
	h := c.do(t, "HEAD", c.url(base), c.tok, nil)
	expect(t, h, 200, "folder HEAD")
	etag(t, h)

	// PUT and DELETE to folders are rejected.
	if r := c.put(t, base, "x"); r.StatusCode < 400 || r.StatusCode > 499 {
		t.Fatalf("PUT to folder: status %d, want 4xx", r.StatusCode)
	}
	if r := c.del(t, base); r.StatusCode < 400 || r.StatusCode > 499 {
		t.Fatalf("DELETE folder: status %d, want 4xx", r.StatusCode)
	}
	expect(t, c.del(t, base+"top.txt"), 200, "cleanup")
}

func (c *client) testVersioning(t *testing.T) {
	base := "/" + c.mod + "/v/"
	expect(t, c.put(t, base+"x/y/doc", "1"), 201, "create")
	_, root1 := c.list(t, "/"+c.mod+"/")
	_, v1 := c.list(t, base)
	_, x1 := c.list(t, base+"x/")
	expect(t, c.put(t, base+"other", "o"), 201, "sibling")
	_, x2 := c.list(t, base+"x/")
	if x2 != x1 {
		t.Fatal("unrelated write changed folder ETag")
	}
	_, v2 := c.list(t, base)
	if v2 == v1 {
		t.Fatal("parent folder ETag did not change after child PUT")
	}

	expect(t, c.put(t, base+"x/y/doc", "2"), 200, "update")
	_, root3 := c.list(t, "/"+c.mod+"/")
	_, v3 := c.list(t, base)
	_, x3 := c.list(t, base+"x/")
	if root3 == root1 || v3 == v2 || x3 == x2 {
		t.Fatal("ancestor folder ETags did not all change after document update")
	}

	// Listings report the ETags returned by the child folders themselves.
	l, _ := c.list(t, base)
	var fd struct{ ETag string }
	json.Unmarshal(l.Items["x/"], &fd)
	if fd.ETag != x3 {
		t.Fatalf("listed folder ETag %q, folder GET ETag %q", fd.ETag, x3)
	}

	expect(t, c.del(t, base+"x/y/doc"), 200, "delete")
	_, v4 := c.list(t, base)
	if v4 == v3 {
		t.Fatal("parent folder ETag did not change after DELETE")
	}

	// If-None-Match on GET.
	r := c.get(t, base, "If-None-Match", `"`+v4+`"`)
	expect(t, r, 304, "folder If-None-Match")
	r = c.get(t, base, "If-None-Match", `"nope", "`+v4+`"`)
	expect(t, r, 304, "folder If-None-Match list")
	pr := c.put(t, base+"doc", "d")
	de := etag(t, pr)
	expect(t, c.get(t, base+"doc", "If-None-Match", `"`+de+`"`), 304, "document If-None-Match")
	expect(t, c.get(t, base+"doc", "If-None-Match", `"stale"`), 200, "document If-None-Match stale")
	for _, q := range []string{base + "doc", base + "other"} {
		expect(t, c.del(t, q), 200, "cleanup")
	}
}

func (c *client) testConditional(t *testing.T) {
	p := "/" + c.mod + "/cond/doc"
	expect(t, c.put(t, p, "1", "If-None-Match", "*"), 201, "If-None-Match * create")
	e1 := etag(t, c.get(t, p))
	r := c.put(t, p, "x", "If-None-Match", "*")
	expect(t, r, 412, "If-None-Match * on existing")
	if g := c.get(t, p); string(g.body) != "1" {
		t.Fatal("failed PUT changed the document")
	}

	expect(t, c.put(t, p, "2", "If-Match", `"wrong"`), 412, "If-Match mismatch")
	r = c.put(t, p, "2", "If-Match", `"`+e1+`"`)
	expect(t, r, 200, "If-Match")
	e2 := etag(t, r)
	expect(t, c.put(t, p, "3", "If-Match", `"`+e1+`"`), 412, "If-Match stale")
	expect(t, c.put(t, "/"+c.mod+"/cond/missing", "x", "If-Match", `"`+e2+`"`), 412, "If-Match on missing")

	expect(t, c.del(t, p, "If-Match", `"`+e1+`"`), 412, "DELETE If-Match stale")
	r = c.del(t, p, "If-Match", `"`+e2+`"`)
	expect(t, r, 200, "DELETE If-Match")
	if r.Header.Get("ETag") != "" && etag(t, r) != e2 {
		t.Fatalf("DELETE returned ETag %q, want deleted version %q", etag(t, r), e2)
	}
}

func (c *client) testConflicts(t *testing.T) {
	base := "/" + c.mod + "/conflict/"
	expect(t, c.put(t, base+"doc", "d"), 201, "create")
	expect(t, c.put(t, base+"doc/child", "c"), 409, "document used as folder")
	expect(t, c.put(t, base+"dir/child", "c"), 201, "create folder")
	expect(t, c.put(t, base+"dir", "d"), 409, "document over folder")
	for _, q := range []string{base + "doc", base + "dir/child"} {
		expect(t, c.del(t, q), 200, "cleanup")
	}
	// After the folder is empty, the name is free for a document.
	expect(t, c.put(t, base+"dir", "now a doc"), 201, "name reuse after folder emptied")
	expect(t, c.del(t, base+"dir"), 200, "cleanup")
}

func (c *client) testPaths(t *testing.T) {
	base := "/" + c.mod + "/paths/"
	names := []string{"with space", "üñíçødé", "a+b", "semi;colon", "q?mark", "hash#tag", "pct%41", "it's"}
	for _, n := range names {
		u := c.url(base) + escape(n)
		r := c.do(t, "PUT", u, c.tok, strings.NewReader(n), "Content-Type", "text/plain")
		expect(t, r, 201, "PUT "+n)
		if g := c.do(t, "GET", u, c.tok, nil); string(g.body) != n {
			t.Fatalf("GET %q: %q", n, g.body)
		}
	}
	l, _ := c.list(t, base)
	for _, n := range names {
		if _, ok := l.Items[n]; !ok {
			t.Fatalf("listing lacks %q: %v", n, keys(l.Items))
		}
	}
	for _, n := range names {
		expect(t, c.do(t, "DELETE", c.url(base)+escape(n), c.tok, nil), 200, "cleanup")
	}
	for _, bad := range []string{base + "a//b", base + "./x", base + "../x", base + "%2e%2e/x"} {
		r := c.do(t, "PUT", c.url(bad), c.tok, strings.NewReader("x"), "Content-Type", "text/plain")
		if r.StatusCode < 400 || r.StatusCode > 499 {
			t.Fatalf("PUT %s: status %d, want 4xx", bad, r.StatusCode)
		}
	}
}

func escape(name string) string {
	var b strings.Builder
	for _, c := range []byte(name) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// checkCache requires no-cache, and with PrivateCaching also the given
// visibility ("private" or "public") and not the other one.
func (c *client) checkCache(t *testing.T, r *resp, what, visibility string) {
	t.Helper()
	cc := r.Header.Get("Cache-Control")
	if !strings.Contains(cc, "no-cache") {
		t.Fatalf("%s Cache-Control %q, want no-cache", what, cc)
	}
	if !c.tg.PrivateCaching {
		return
	}
	other := map[string]string{"private": "public", "public": "private"}[visibility]
	if !strings.Contains(cc, visibility) || strings.Contains(cc, other) {
		t.Fatalf("%s Cache-Control %q, want no-cache, %s", what, cc, visibility)
	}
}

func (c *client) testPublic(t *testing.T) {
	p := "/public/" + c.mod + "/pub.txt"
	expect(t, c.put(t, p, "public!", "Content-Type", "text/plain"), 201, "create public")
	r := c.do(t, "GET", c.url(p), "", nil)
	expect(t, r, 200, "public GET without token")
	if string(r.body) != "public!" {
		t.Fatalf("public body %q", r.body)
	}
	c.checkCache(t, r, "public document", "public")
	// Public documents are opened directly in browsers; stored HTML must not
	// run as active content on the storage origin.
	html := "/public/" + c.mod + "/page.html"
	expect(t, c.put(t, html, "<script>alert(1)</script>", "Content-Type", "text/html"), 201, "create public html")
	r = c.do(t, "GET", c.url(html), "", nil)
	if r.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("public document without X-Content-Type-Options: nosniff")
	}
	if csp := r.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "sandbox") {
		t.Fatalf("public HTML served without a sandbox CSP (got %q)", csp)
	}
	expect(t, c.del(t, html), 200, "cleanup")
	expect(t, c.do(t, "HEAD", c.url(p), "", nil), 200, "public HEAD without token")
	expect(t, c.do(t, "GET", c.url(p), "garbage-token", nil), 200, "public GET with invalid token")
	expect(t, c.do(t, "GET", c.url("/public/"+c.mod+"/"), "", nil), 401, "public folder without token")
	folder := c.do(t, "GET", c.url("/public/"+c.mod+"/"), c.tok, nil)
	expect(t, folder, 200, "authenticated public folder GET")
	c.checkCache(t, folder, "public folder", "private")
	expect(t, c.do(t, "GET", c.url("/public/"+c.mod+"/missing"), "", nil), 404, "public missing document")
	expect(t, c.do(t, "PUT", c.url(p), "", strings.NewReader("x"), "Content-Type", "text/plain"), 401, "public PUT without token")
	expect(t, c.do(t, "DELETE", c.url(p), "", nil), 401, "public DELETE without token")
	expect(t, c.del(t, p), 200, "cleanup")
}

func (c *client) testRange(t *testing.T) {
	p := "/" + c.mod + "/range"
	expect(t, c.put(t, p, "0123456789"), 201, "create")
	r := c.get(t, p, "Range", "bytes=2-5")
	if r.StatusCode == 200 {
		t.Skip("server does not support Range")
	}
	expect(t, r, 206, "range")
	if string(r.body) != "2345" || r.Header.Get("Content-Range") != "bytes 2-5/10" {
		t.Fatalf("range: %q %q", r.body, r.Header.Get("Content-Range"))
	}
	if r := c.get(t, p, "Range", "bytes=-3"); string(r.body) != "789" {
		t.Fatalf("suffix range: %q", r.body)
	}
	if r := c.get(t, p, "Range", "bytes=7-"); string(r.body) != "789" {
		t.Fatalf("open range: %q", r.body)
	}
	expect(t, c.get(t, p, "Range", "bytes=20-30"), 416, "unsatisfiable range")
	expect(t, c.del(t, p), 200, "cleanup")
}

func (c *client) testChunked(t *testing.T) {
	p := "/" + c.mod + "/chunked"
	// A reader without a known length makes net/http use chunked encoding.
	body := struct{ io.Reader }{strings.NewReader(strings.Repeat("chunk", 1000))}
	r := c.do(t, "PUT", c.url(p), c.tok, body, "Content-Type", "text/plain")
	expect(t, r, 201, "chunked PUT")
	if g := c.get(t, p); len(g.body) != 5000 {
		t.Fatalf("chunked body length %d", len(g.body))
	}
	expect(t, c.del(t, p), 200, "cleanup")
}

func (c *client) testTooLarge(t *testing.T) {
	p := "/" + c.mod + "/big"
	big := strings.Repeat("x", int(c.tg.MaxDocumentSize)+1)
	expect(t, c.put(t, p, big), 413, "oversized")
	body := struct{ io.Reader }{strings.NewReader(big)}
	expect(t, c.do(t, "PUT", c.url(p), c.tok, body, "Content-Type", "text/plain"), 413, "oversized chunked")
	expect(t, c.get(t, p), 404, "oversized document not stored")
}

func (c *client) testIsolation(t *testing.T) {
	p := "/" + c.mod + "/iso"
	expect(t, c.do(t, "GET", c.tg.OtherUserRoot+p, c.tok, nil), 403, "other user's storage")
	expect(t, c.do(t, "PUT", c.tg.OtherUserRoot+p, c.tok, strings.NewReader("x"), "Content-Type", "text/plain"), 403, "write other user's storage")
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
