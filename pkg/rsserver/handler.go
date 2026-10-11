package rsserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"anime.bike/remotestorage/pkg/rs"
)

// EmptyFolderETag is sent for folders that have no documents.
const EmptyFolderETag = "empty"

const (
	corsAllowMethods  = "GET, HEAD, PUT, DELETE, OPTIONS"
	corsAllowHeaders  = "Authorization, Content-Type, Content-Length, If-Match, If-None-Match, Origin, X-Requested-With, Range"
	corsExposeHeaders = "ETag, Content-Type, Content-Length, Content-Range, Last-Modified, Accept-Ranges, WWW-Authenticate"
)

func (s *Handler) registerRoutes() {}

// ServeHTTP implements http.Handler. Every response carries CORS headers (spec section 7).
// Requests are dispatched on the method only: http.ServeMux would redirect
// paths with empty or dot segments instead of rejecting them.
func (s *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Expose-Headers", corsExposeHeaders)
	switch r.Method {
	case http.MethodOptions:
		s.handleOptions(w, r)
	case http.MethodGet, http.MethodHead:
		s.handleRead(w, r)
	case http.MethodPut:
		s.handlePut(w, r)
	case http.MethodDelete:
		s.handleDelete(w, r)
	default:
		h.Set("Allow", corsAllowMethods)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Handler) handleOptions(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Methods", corsAllowMethods)
	h.Set("Access-Control-Allow-Headers", corsAllowHeaders)
	h.Set("Access-Control-Max-Age", "86400")
	h.Set("Allow", corsAllowMethods)
	w.WriteHeader(http.StatusNoContent)
}

// prepare resolves, authenticates and authorizes a request.
func (s *Handler) prepare(w http.ResponseWriter, r *http.Request, isWrite bool) (*AuthInfo, *ResourceRequest, StorageBackend, bool) {
	ref, err := s.resourceResolver.ResolveResource(r)
	if err != nil {
		s.writeError(w, r, err)
		return nil, nil, nil, false
	}
	if err := rs.ValidatePath(ref.Path); err != nil {
		s.writeError(w, r, NewHTTPError(http.StatusBadRequest, "Invalid path"))
		return nil, nil, nil, false
	}
	ref.Module, ref.IsPublic = rs.SplitModule(ref.Path)
	req := &ResourceRequest{Resource: ref, IsWrite: isWrite}

	token := extractBearerToken(r)
	if token == "" && s.queryToken && r.Method == http.MethodGet {
		token = r.URL.Query().Get("access_token")
	}
	authInfo, err := s.authenticator.Authenticate(r, token)
	if err != nil {
		// An invalid token must not block public document reads.
		if !(ref.IsPublic && !isWrite && !ref.IsFolder()) {
			s.writeError(w, r, err)
			return nil, nil, nil, false
		}
		authInfo = nil
	}
	if err := s.authorizer.Authorize(authInfo, req); err != nil {
		s.writeError(w, r, err)
		return nil, nil, nil, false
	}
	var hookErr error
	switch {
	case r.Method == http.MethodPut:
		hookErr = s.hooks.callBeforeWrite(r, authInfo, req)
	case r.Method == http.MethodDelete:
		hookErr = s.hooks.callBeforeDelete(r, authInfo, req)
	default:
		hookErr = s.hooks.callBeforeRead(r, authInfo, req)
	}
	if hookErr != nil {
		s.writeError(w, r, hookErr)
		return nil, nil, nil, false
	}
	storage, err := s.storageProvider.GetStorage(r.Context(), authInfo, req)
	if err != nil {
		s.writeError(w, r, err)
		return nil, nil, nil, false
	}
	return authInfo, req, storage, true
}

// DefaultCacheControl marks public documents "no-cache, public" and everything
// else "private, no-cache", so shared caches do not store authenticated responses.
func DefaultCacheControl(ref *ResourceRef) string {
	if ref.IsPublic && !ref.IsFolder() {
		return "no-cache, public"
	}
	return "private, no-cache"
}

// PlainCacheControl sends exactly "no-cache", the literal value in the spec.
// Some conformance suites (e.g. 0dataapp/spec-check) compare the header verbatim.
func PlainCacheControl(*ResourceRef) string { return "no-cache" }

func (s *Handler) handleRead(w http.ResponseWriter, r *http.Request) {
	authInfo, req, storage, ok := s.prepare(w, r, false)
	if !ok {
		return
	}
	ctx := WithAuthInfo(r.Context(), authInfo)
	ref := req.Resource
	h := w.Header()
	h.Set("Cache-Control", s.cacheControl(ref))

	if ref.IsFolder() {
		s.readFolder(w, r, ctx, storage, req)
	} else {
		s.readDocument(w, r, ctx, storage, req)
	}
}

func (s *Handler) readFolder(w http.ResponseWriter, r *http.Request, ctx context.Context, storage StorageBackend, req *ResourceRequest) {
	ref := req.Resource
	if meta, err := storage.Head(ctx, ref.Path); err == nil && meta.ETag != "" && etagListMatches(r.Header.Get("If-None-Match"), meta.ETag) {
		w.Header().Set("ETag", quoteETag(meta.ETag))
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, listing, err := storage.Get(ctx, ref.Path)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if listing == nil {
		listing = rs.NewFolderListing(rs.Metadata{Path: ref.Path, IsFolder: true})
	}
	if listing.Items == nil {
		listing.Items = map[string]rs.FolderItem{}
	}
	listing.LDContext = rs.FolderDescriptionContext
	etag := listing.Metadata.ETag
	if etag == "" {
		etag = EmptyFolderETag
	}
	if etagListMatches(r.Header.Get("If-None-Match"), etag) {
		w.Header().Set("ETag", quoteETag(etag))
		w.WriteHeader(http.StatusNotModified)
		return
	}
	body, err := json.Marshal(listing)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/ld+json")
	h.Set("ETag", quoteETag(etag))
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
	s.hooks.callAfterRead(r, AuthInfoFromRequest(ctx), req)
}

func (s *Handler) readDocument(w http.ResponseWriter, r *http.Request, ctx context.Context, storage StorageBackend, req *ResourceRequest) {
	ref := req.Resource
	meta, err := storage.Head(ctx, ref.Path)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if meta.IsFolder {
		s.writeError(w, r, rs.ErrNotFound)
		return
	}
	h := w.Header()
	h.Set("ETag", quoteETag(meta.ETag))
	if etagListMatches(r.Header.Get("If-None-Match"), meta.ETag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeDocumentHeaders(w, meta)
	if r.Method == http.MethodHead {
		h.Set("Content-Length", strconv.FormatInt(meta.Size, 10))
		w.WriteHeader(http.StatusOK)
		s.hooks.callAfterRead(r, AuthInfoFromRequest(ctx), req)
		return
	}

	doc, _, err := storage.Get(ctx, ref.Path)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if doc == nil {
		s.writeError(w, r, rs.ErrNotFound)
		return
	}
	defer doc.Body.Close()
	// The document may have changed between Head and Get.
	writeDocumentHeaders(w, &doc.Metadata)
	h.Set("ETag", quoteETag(doc.Metadata.ETag))

	if seeker, ok := doc.Body.(io.ReadSeeker); ok {
		h.Set("Accept-Ranges", "bytes")
		// Conditional headers were handled above; ServeContent only does ranges.
		r2 := r.Clone(ctx)
		for _, k := range []string{"If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since"} {
			r2.Header.Del(k)
		}
		http.ServeContent(w, r2, "", doc.Metadata.LastModified, seeker)
	} else {
		h.Set("Content-Length", strconv.FormatInt(doc.Metadata.Size, 10))
		w.WriteHeader(http.StatusOK)
		io.Copy(w, doc.Body)
	}
	s.hooks.callAfterRead(r, AuthInfoFromRequest(ctx), req)
}

// DocumentCSP is sent with every document. Documents are app data, so a
// stored HTML or SVG file opened directly in a browser must not run scripts
// with the storage origin.
const DocumentCSP = "sandbox; default-src 'none'"

func writeDocumentHeaders(w http.ResponseWriter, m *rs.Metadata) {
	h := w.Header()
	ct := m.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	h.Set("Content-Type", ct)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", DocumentCSP)
	if !m.LastModified.IsZero() {
		h.Set("Last-Modified", rs.FormatHTTPDate(m.LastModified))
	}
}

func (s *Handler) handlePut(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	authInfo, req, storage, ok := s.prepare(w, r, true)
	if !ok {
		return
	}
	ref := req.Resource
	if ref.IsFolder() {
		s.writeError(w, r, NewHTTPError(http.StatusBadRequest, "PUT requests can only be made to documents"))
		return
	}
	if r.Header.Get("Content-Range") != "" {
		s.writeError(w, r, NewHTTPError(http.StatusBadRequest, "Content-Range is not allowed on PUT"))
		return
	}
	cond, err := parseConditions(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	size := r.ContentLength
	var body io.Reader = r.Body
	if s.maxDocumentSize > 0 {
		if size > s.maxDocumentSize {
			s.writeError(w, r, rs.ErrTooLarge)
			return
		}
		body = http.MaxBytesReader(w, r.Body, s.maxDocumentSize)
	}
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	ctx := WithAuthInfo(r.Context(), authInfo)
	res, err := storage.Put(ctx, ref.Path, body, size, contentType, cond)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			err = rs.ErrTooLarge
		}
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteETag(res.ETag))
	if res.Created {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	s.hooks.callAfterWrite(r, authInfo, req, res.ETag)
}

func (s *Handler) handleDelete(w http.ResponseWriter, r *http.Request) {
	authInfo, req, storage, ok := s.prepare(w, r, true)
	if !ok {
		return
	}
	ref := req.Resource
	if ref.IsFolder() {
		s.writeError(w, r, NewHTTPError(http.StatusBadRequest, "DELETE requests can only be made to documents"))
		return
	}
	cond, err := parseConditions(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	ctx := WithAuthInfo(r.Context(), authInfo)
	etag, err := storage.Delete(ctx, ref.Path, cond)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if etag != "" {
		w.Header().Set("ETag", quoteETag(etag))
	}
	w.WriteHeader(http.StatusOK)
	s.hooks.callAfterDelete(r, authInfo, req)
}

func parseConditions(r *http.Request) (Condition, error) {
	var c Condition
	if v := r.Header.Get("If-Match"); v != "" {
		c.IfMatch = parseETagList(v)
		if len(c.IfMatch) == 0 {
			return c, NewHTTPError(http.StatusBadRequest, "Invalid If-Match header")
		}
	}
	if v := strings.TrimSpace(r.Header.Get("If-None-Match")); v != "" {
		if v != "*" {
			return c, NewHTTPError(http.StatusBadRequest, "If-None-Match on writes must be '*'")
		}
		c.IfNoneMatchAny = true
	}
	return c, nil
}

// quoteETag formats an unquoted ETag for the ETag header.
func quoteETag(etag string) string { return `"` + etag + `"` }

// parseETagList splits an If-Match / If-None-Match value into unquoted ETags.
// Unquoted values are accepted for compatibility with older clients.
func parseETagList(v string) []string {
	var out []string
	for part := range strings.SplitSeq(v, ",") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "W/")
		part = strings.Trim(part, `"`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func etagListMatches(header, etag string) bool {
	if header == "" || etag == "" {
		return false
	}
	if strings.TrimSpace(header) == "*" {
		return true
	}
	for _, e := range parseETagList(header) {
		if e == etag {
			return true
		}
	}
	return false
}

// extractBearerToken returns the token of an "Authorization: Bearer" header.
func extractBearerToken(r *http.Request) string {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

// writeError maps errors from resolvers, authenticators, authorizers, hooks
// and storage backends to responses.
func (s *Handler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	h := w.Header()
	var httpErr *HTTPError
	status, msg := http.StatusInternalServerError, "Internal server error"
	switch {
	case errors.As(err, &httpErr):
		status, msg = httpErr.StatusCode, httpErr.Message
	case errors.Is(err, rs.ErrNotFound):
		status, msg = http.StatusNotFound, "Not found"
	case errors.Is(err, rs.ErrPreconditionFailed), errors.Is(err, rs.ErrAlreadyExists):
		status, msg = http.StatusPreconditionFailed, "Precondition failed"
	case errors.Is(err, rs.ErrConflict):
		status, msg = http.StatusConflict, "Conflict: a folder and a document cannot share a name"
	case errors.Is(err, rs.ErrTooLarge):
		status, msg = http.StatusRequestEntityTooLarge, "Document too large"
	case errors.Is(err, rs.ErrQuotaExceeded):
		status, msg = http.StatusInsufficientStorage, "Storage quota exceeded"
	case errors.Is(err, rs.ErrInvalidPath):
		status, msg = http.StatusBadRequest, "Invalid path"
	case errors.Is(err, context.Canceled):
		return
	default:
		s.logError(r, err)
	}
	switch status {
	case http.StatusUnauthorized:
		h.Set("WWW-Authenticate", `Bearer realm="remoteStorage", error="invalid_token"`)
	case http.StatusForbidden:
		h.Set("WWW-Authenticate", `Bearer realm="remoteStorage", error="insufficient_scope"`)
	}
	h.Del("ETag")
	h.Del("Content-Length")
	http.Error(w, msg, status)
}

func (s *Handler) logError(r *http.Request, err error) {
	if s.errorLog != nil {
		s.errorLog(r, err)
		return
	}
	slog.Error("remotestorage request failed", "method", r.Method, "path", r.URL.Path, "err", err)
}

// AuthInfoFromRequest returns the AuthInfo stored in ctx, or nil.
func AuthInfoFromRequest(ctx context.Context) *AuthInfo {
	a, _ := AuthInfoFromContext(ctx)
	return a
}
