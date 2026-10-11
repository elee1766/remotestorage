package rstest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"
)

type memDoc struct {
	content     []byte
	contentType string
	etag        string
	modified    time.Time
}

// MemoryStorage is an in-memory StorageBackend holding one user's documents.
// It is meant for tests and examples, not production.
type MemoryStorage struct {
	mu   sync.RWMutex
	docs map[string]*memDoc // document path -> doc
	// folders maps each non-empty folder path to its version counter.
	folders map[string]uint64
	seq     uint64
}

// NewMemoryStorage returns an empty storage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{docs: map[string]*memDoc{}, folders: map[string]uint64{}}
}

var _ rsserver.StorageBackend = (*MemoryStorage)(nil)

func (s *MemoryStorage) folderETag(p string) string {
	v, ok := s.folders[p]
	if !ok {
		return ""
	}
	sum := sha256.Sum256([]byte(p + "\x00" + strconv.FormatUint(v, 10)))
	return hex.EncodeToString(sum[:])[:32]
}

// bumpAncestors gives every ancestor folder of p a new version.
func (s *MemoryStorage) bumpAncestors(p string) {
	for dir := rs.ParentPath(p); dir != ""; dir = rs.ParentPath(dir) {
		s.seq++
		s.folders[dir] = s.seq
	}
}

func (s *MemoryStorage) children(dir string) (docs []string, folders []string) {
	seenFolder := map[string]bool{}
	for p := range s.docs {
		if !strings.HasPrefix(p, dir) {
			continue
		}
		rest := p[len(dir):]
		if name, _, isNested := strings.Cut(rest, "/"); isNested {
			if !seenFolder[name] {
				seenFolder[name] = true
				folders = append(folders, dir+name+"/")
			}
		} else {
			docs = append(docs, p)
		}
	}
	sort.Strings(docs)
	sort.Strings(folders)
	return docs, folders
}

func (s *MemoryStorage) meta(p string, d *memDoc) rs.Metadata {
	return rs.Metadata{
		Path:         p,
		Name:         rs.BaseName(p),
		ContentType:  d.contentType,
		ETag:         d.etag,
		LastModified: d.modified,
		Size:         int64(len(d.content)),
	}
}

func (s *MemoryStorage) Get(_ context.Context, p string) (*rs.Document, *rs.FolderListing, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !rs.IsFolderPath(p) {
		d, ok := s.docs[p]
		if !ok {
			return nil, nil, rs.ErrNotFound
		}
		return &rs.Document{Metadata: s.meta(p, d), Body: readSeekNopCloser{bytes.NewReader(d.content)}}, nil, nil
	}
	listing := rs.NewFolderListing(rs.Metadata{Path: p, Name: rs.BaseName(p), ETag: s.folderETag(p), IsFolder: true})
	docs, folders := s.children(p)
	for _, dp := range docs {
		listing.Items[rs.BaseName(dp)] = rs.DocumentItem(s.meta(dp, s.docs[dp]))
	}
	for _, fp := range folders {
		listing.Items[rs.BaseName(fp)] = rs.FolderEntry(s.folderETag(fp))
	}
	return nil, listing, nil
}

func (s *MemoryStorage) Head(_ context.Context, p string) (*rs.Metadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if rs.IsFolderPath(p) {
		return &rs.Metadata{Path: p, Name: rs.BaseName(p), ETag: s.folderETag(p), IsFolder: true}, nil
	}
	d, ok := s.docs[p]
	if !ok {
		return nil, rs.ErrNotFound
	}
	m := s.meta(p, d)
	return &m, nil
}

// conflicts reports whether writing a document at p clashes with existing items.
func (s *MemoryStorage) conflicts(p string) bool {
	if _, isFolder := s.folders[p+"/"]; isFolder {
		return true
	}
	for dir := rs.ParentPath(p); dir != "/" && dir != ""; dir = rs.ParentPath(dir) {
		if _, isDoc := s.docs[strings.TrimSuffix(dir, "/")]; isDoc {
			return true
		}
	}
	return false
}

func (s *MemoryStorage) Put(_ context.Context, p string, body io.Reader, _ int64, contentType string, cond rsserver.Condition) (*rsserver.PutResult, error) {
	content, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, exists := s.docs[p]
	var cur string
	if exists {
		cur = old.etag
	}
	if err := cond.Check(exists, cur); err != nil {
		return nil, err
	}
	if s.conflicts(p) {
		return nil, rs.ErrConflict
	}
	h := sha256.New()
	h.Write([]byte(contentType))
	h.Write([]byte{0})
	h.Write(content)
	etag := hex.EncodeToString(h.Sum(nil))[:32]
	s.docs[p] = &memDoc{content: content, contentType: contentType, etag: etag, modified: time.Now().UTC().Truncate(time.Second)}
	s.bumpAncestors(p)
	return &rsserver.PutResult{ETag: etag, Created: !exists}, nil
}

func (s *MemoryStorage) Delete(_ context.Context, p string, cond rsserver.Condition) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, exists := s.docs[p]
	var cur string
	if exists {
		cur = d.etag
	}
	if err := cond.Check(exists, cur); err != nil {
		return "", err
	}
	if !exists {
		return "", rs.ErrNotFound
	}
	delete(s.docs, p)
	s.bumpAncestors(p)
	// Drop folders whose subtree became empty.
	for dir := rs.ParentPath(p); dir != ""; dir = rs.ParentPath(dir) {
		docs, folders := s.children(dir)
		if len(docs) == 0 && len(folders) == 0 {
			delete(s.folders, dir)
		}
	}
	return d.etag, nil
}

type readSeekNopCloser struct{ *bytes.Reader }

func (readSeekNopCloser) Close() error { return nil }
