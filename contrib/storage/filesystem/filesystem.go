// Package filesystem stores remoteStorage documents in a directory tree.
//
// Layout under the root directory:
//
//	data/<path>   document contents
//	meta/<path>   document metadata (JSON), mirroring data/
//	tmp/          files being written
//
// Folder ETags are derived from the ETags of their children, so they change
// whenever any document in the subtree changes. Computing them walks the
// subtree, which is fine for small trees. Writes are serialized with a mutex,
// so one Storage must not be shared between processes. All access goes
// through an os.Root, so paths cannot escape the directory.
package filesystem

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"
)

// Storage is a StorageBackend for one user, rooted at a directory.
type Storage struct {
	root *os.Root
	mu   sync.RWMutex
}

var _ rsserver.StorageBackend = (*Storage)(nil)

// Open creates dir if needed and returns a storage in it. Close it when done.
func Open(dir string) (*Storage, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return NewFromRoot(root), nil
}

// NewFromRoot returns a storage in root. The storage takes ownership of root.
func NewFromRoot(root *os.Root) *Storage {
	return &Storage{root: root}
}

// Close closes the underlying root.
func (s *Storage) Close() error { return s.root.Close() }

type docMeta struct {
	ContentType string    `json:"content_type"`
	ETag        string    `json:"etag"`
	Size        int64     `json:"size"`
	Modified    time.Time `json:"modified"`
}

// Paths inside an os.Root are relative and slash separated.
func dataPath(p string) string { return path.Join("data", p) }
func metaPath(p string) string { return path.Join("meta", p) }

func (s *Storage) readMeta(p string) (*docMeta, error) {
	// Only a regular file in the data tree is a document. A directory, or a
	// path under a document, is not.
	if !s.isFile(p) {
		return nil, rs.ErrNotFound
	}
	b, err := s.root.ReadFile(metaPath(p))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, rs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var m docMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *docMeta) metadata(p string) rs.Metadata {
	return rs.Metadata{Path: p, Name: rs.BaseName(p), ContentType: m.ContentType, ETag: m.ETag, Size: m.Size, LastModified: m.Modified}
}

// isDir reports whether the data tree has a directory at folder path p.
func (s *Storage) isDir(p string) bool {
	fi, err := s.root.Lstat(dataPath(p))
	return err == nil && fi.IsDir()
}

func (s *Storage) isFile(p string) bool {
	fi, err := s.root.Lstat(dataPath(p))
	return err == nil && fi.Mode().IsRegular()
}

// listDir returns child names of folder p, folders with a trailing "/".
func (s *Storage) listDir(p string) ([]string, error) {
	entries, err := fs.ReadDir(s.root.FS(), dataPath(p))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		switch {
		case e.IsDir():
			names = append(names, e.Name()+"/")
		case e.Type().IsRegular():
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// folderETag hashes the names and ETags of all children. Empty folders have "".
func (s *Storage) folderETag(p string) (string, error) {
	names, err := s.listDir(p)
	if err != nil || len(names) == 0 {
		return "", err
	}
	h := sha256.New()
	for _, n := range names {
		var etag string
		if strings.HasSuffix(n, "/") {
			etag, err = s.folderETag(p + n)
		} else {
			var m *docMeta
			m, err = s.readMeta(p + n)
			if m != nil {
				etag = m.ETag
			}
		}
		if err != nil {
			return "", err
		}
		h.Write([]byte(n + "\x00" + etag + "\x00"))
	}
	return hex.EncodeToString(h.Sum(nil))[:32], nil
}

func (s *Storage) Get(_ context.Context, p string) (*rs.Document, *rs.FolderListing, error) {
	if err := rs.ValidatePath(p); err != nil {
		return nil, nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !rs.IsFolderPath(p) {
		m, err := s.readMeta(p)
		if err != nil {
			return nil, nil, err
		}
		f, err := s.root.Open(dataPath(p))
		if err != nil {
			return nil, nil, err
		}
		return &rs.Document{Metadata: m.metadata(p), Body: f}, nil, nil
	}
	etag, err := s.folderETag(p)
	if err != nil {
		return nil, nil, err
	}
	listing := rs.NewFolderListing(rs.Metadata{Path: p, Name: rs.BaseName(p), ETag: etag, IsFolder: true})
	names, err := s.listDir(p)
	if err != nil {
		return nil, nil, err
	}
	for _, n := range names {
		if strings.HasSuffix(n, "/") {
			fe, err := s.folderETag(p + n)
			if err != nil {
				return nil, nil, err
			}
			listing.Items[n] = rs.FolderEntry(fe)
			continue
		}
		m, err := s.readMeta(p + n)
		if err != nil {
			return nil, nil, err
		}
		listing.Items[n] = rs.DocumentItem(m.metadata(p + n))
	}
	return nil, listing, nil
}

func (s *Storage) Head(_ context.Context, p string) (*rs.Metadata, error) {
	if err := rs.ValidatePath(p); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if rs.IsFolderPath(p) {
		etag, err := s.folderETag(p)
		if err != nil {
			return nil, err
		}
		return &rs.Metadata{Path: p, Name: rs.BaseName(p), ETag: etag, IsFolder: true}, nil
	}
	m, err := s.readMeta(p)
	if err != nil {
		return nil, err
	}
	md := m.metadata(p)
	return &md, nil
}

// conflicts reports whether a document at p would clash with a folder of the
// same name or with a document used as an ancestor folder.
func (s *Storage) conflicts(p string) bool {
	if s.isDir(p + "/") {
		return true
	}
	for dir := rs.ParentPath(p); dir != "/" && dir != ""; dir = rs.ParentPath(dir) {
		if s.isFile(strings.TrimSuffix(dir, "/")) {
			return true
		}
	}
	return false
}

func (s *Storage) writeTemp(r io.Reader) (name string, size int64, sum []byte, err error) {
	if err := s.root.MkdirAll("tmp", 0o755); err != nil {
		return "", 0, nil, err
	}
	var rnd [16]byte
	rand.Read(rnd[:])
	name = "tmp/" + hex.EncodeToString(rnd[:])
	f, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", 0, nil, err
	}
	h := sha256.New()
	size, err = io.Copy(io.MultiWriter(f, h), r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		s.root.Remove(name)
		return "", 0, nil, err
	}
	return name, size, h.Sum(nil), nil
}

func (s *Storage) Put(_ context.Context, p string, body io.Reader, _ int64, contentType string, cond rsserver.Condition) (*rsserver.PutResult, error) {
	if err := rs.ValidatePath(p); err != nil || rs.IsFolderPath(p) {
		return nil, rs.ErrInvalidPath
	}
	// Stream the body to a temp file before taking the lock.
	tmp, size, sum, err := s.writeTemp(body)
	if err != nil {
		return nil, err
	}
	defer s.root.Remove(tmp)

	s.mu.Lock()
	defer s.mu.Unlock()
	old, err := s.readMeta(p)
	if err != nil && !errors.Is(err, rs.ErrNotFound) {
		return nil, err
	}
	var cur string
	if old != nil {
		cur = old.ETag
	}
	if err := cond.Check(old != nil, cur); err != nil {
		return nil, err
	}
	if s.conflicts(p) {
		return nil, rs.ErrConflict
	}
	h := sha256.New()
	h.Write(sum)
	h.Write([]byte(contentType))
	meta := docMeta{
		ContentType: contentType,
		ETag:        hex.EncodeToString(h.Sum(nil))[:32],
		Size:        size,
		Modified:    time.Now().UTC().Truncate(time.Second),
	}
	metaJSON, _ := json.Marshal(meta)
	for _, dir := range []string{path.Dir(dataPath(p)), path.Dir(metaPath(p))} {
		if err := s.root.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	if err := s.root.Rename(tmp, dataPath(p)); err != nil {
		return nil, err
	}
	if err := s.root.WriteFile(tmp, metaJSON, 0o644); err != nil {
		return nil, err
	}
	if err := s.root.Rename(tmp, metaPath(p)); err != nil {
		return nil, err
	}
	return &rsserver.PutResult{ETag: meta.ETag, Created: old == nil}, nil
}

func (s *Storage) Delete(_ context.Context, p string, cond rsserver.Condition) (string, error) {
	if err := rs.ValidatePath(p); err != nil || rs.IsFolderPath(p) {
		return "", rs.ErrInvalidPath
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.readMeta(p)
	if err != nil && !errors.Is(err, rs.ErrNotFound) {
		return "", err
	}
	var cur string
	if m != nil {
		cur = m.ETag
	}
	if err := cond.Check(m != nil, cur); err != nil {
		return "", err
	}
	if m == nil {
		return "", rs.ErrNotFound
	}
	if err := s.root.Remove(dataPath(p)); err != nil {
		return "", err
	}
	if err := s.root.Remove(metaPath(p)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	// Remove folders left empty, in both trees.
	for dir := rs.ParentPath(p); dir != "/" && dir != ""; dir = rs.ParentPath(dir) {
		names, err := s.listDir(dir)
		if err != nil || len(names) > 0 {
			break
		}
		s.root.Remove(dataPath(dir))
		s.root.Remove(metaPath(dir))
	}
	return m.ETag, nil
}

// Multi stores each user in a subdirectory of root.
type Multi struct {
	root  *os.Root
	mu    sync.Mutex
	users map[string]*Storage
}

// OpenMulti creates dir if needed and stores each user in a subdirectory of it.
func OpenMulti(dir string) (*Multi, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Multi{root: root, users: map[string]*Storage{}}, nil
}

// User returns the storage of user. user must be a single path segment.
func (m *Multi) User(user string) (*Storage, error) {
	if user == "" || user == "." || user == ".." || strings.ContainsAny(user, "/\\\x00") {
		return nil, rs.ErrInvalidPath
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.users[user]; ok {
		return s, nil
	}
	if err := m.root.MkdirAll(user, 0o755); err != nil {
		return nil, err
	}
	r, err := m.root.OpenRoot(user)
	if err != nil {
		return nil, err
	}
	s := NewFromRoot(r)
	m.users[user] = s
	return s, nil
}

// Close closes all user storages and the root.
func (m *Multi) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	for _, s := range m.users {
		errs = append(errs, s.Close())
	}
	m.users = map[string]*Storage{}
	errs = append(errs, m.root.Close())
	return errors.Join(errs...)
}
