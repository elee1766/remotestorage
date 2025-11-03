package rsstorage_filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"anime.bike/remotestorage/pkg/rs"
	"github.com/spf13/afero"
)

// FilesystemStorage implements storage using an afero.Fs filesystem
type FilesystemStorage struct {
	fs   afero.Fs
	root string
}

// NewFilesystemStorage creates a new filesystem storage backend
func NewFilesystemStorage(fs afero.Fs, rootDir string) *FilesystemStorage {
	return &FilesystemStorage{
		fs:   fs,
		root: rootDir,
	}
}

// NewOSFilesystemStorage creates a filesystem storage using the OS filesystem
func NewOSFilesystemStorage(rootDir string) *FilesystemStorage {
	return NewFilesystemStorage(afero.NewOsFs(), rootDir)
}

// NewMemoryFilesystemStorage creates a filesystem storage using in-memory filesystem
func NewMemoryFilesystemStorage() *FilesystemStorage {
	return NewFilesystemStorage(afero.NewMemMapFs(), "/")
}

// fileMetadata represents metadata stored alongside files
type fileMetadata struct {
	ContentType  string    `json:"content_type"`
	ETag         string    `json:"etag"`
	LastModified time.Time `json:"last_modified"`
	Size         int64     `json:"size"`
}

// Get retrieves a document or folder listing
func (fs *FilesystemStorage) Get(ctx context.Context, path string) (*rs.Document, *rs.FolderListing, error) {
	fullPath := fs.buildPath(path)

	// Check if path exists and determine type
	info, err := fs.fs.Stat(fullPath)
	if err != nil {
		return nil, nil, rs.ErrNotFound
	}

	if !info.IsDir() {
		// It's a file
		return fs.getDocument(path, fullPath)
	} else {
		// It's a directory
		return fs.getFolderListing(path, fullPath)
	}

	return nil, nil, rs.ErrNotFound
}

// Create stores a new document
func (fs *FilesystemStorage) Create(ctx context.Context, path string, body io.Reader, contentType string) (string, error) {
	fullPath := fs.buildPath(path)

	// Check if file already exists
	if exists, _ := afero.Exists(fs.fs, fullPath); exists {
		return "", rs.ErrAlreadyExists
	}

	return fs.writeFile(fullPath, body, contentType)
}

// Update modifies an existing document
func (fs *FilesystemStorage) Update(ctx context.Context, path string, body io.Reader, contentType string, etag string) (string, error) {
	fullPath := fs.buildPath(path)

	// Check if file exists
	exists, err := afero.Exists(fs.fs, fullPath)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", rs.ErrNotFound
	}

	// Check etag if provided
	if etag != "" {
		currentMeta, err := fs.readMetadata(fullPath)
		if err != nil {
			return "", err
		}
		if currentMeta.ETag != etag {
			return "", rs.ErrPreconditionFailed
		}
	}

	return fs.writeFile(fullPath, body, contentType)
}

// Delete removes a document
func (fs *FilesystemStorage) Delete(ctx context.Context, path string, etag string) error {
	fullPath := fs.buildPath(path)

	// Check if file exists
	exists, err := afero.Exists(fs.fs, fullPath)
	if err != nil {
		return err
	}
	if !exists {
		return rs.ErrNotFound
	}

	// Check etag if provided
	if etag != "" {
		currentMeta, err := fs.readMetadata(fullPath)
		if err != nil {
			return err
		}
		if currentMeta.ETag != etag {
			return rs.ErrPreconditionFailed
		}
	}

	// Remove file and metadata
	if err := fs.fs.Remove(fullPath); err != nil {
		return err
	}

	metaPath := fs.getMetadataPath(fullPath)
	fs.fs.Remove(metaPath) // Ignore error for metadata removal

	// Clean up empty directories
	fs.cleanupEmptyDirs(filepath.Dir(fullPath))

	return nil
}

// Head retrieves document metadata
func (fs *FilesystemStorage) Head(ctx context.Context, path string) (*rs.Metadata, error) {
	fullPath := fs.buildPath(path)

	info, err := fs.fs.Stat(fullPath)
	if err != nil || info.IsDir() {
		return nil, rs.ErrNotFound
	}

	meta, err := fs.readMetadata(fullPath)
	if err != nil {
		return nil, err
	}

	return &rs.Metadata{
		Path:         path,
		Name:         fs.pathName(path),
		ContentType:  meta.ContentType,
		ETag:         meta.ETag,
		LastModified: meta.LastModified,
		Size:         meta.Size,
		IsFolder:     false,
	}, nil
}

// GetRange retrieves a document with a specific byte range
func (fs *FilesystemStorage) GetRange(ctx context.Context, path string, start, end int64) (*rs.Document, error) {
	fullPath := fs.buildPath(path)

	info, err := fs.fs.Stat(fullPath)
	if err != nil || info.IsDir() {
		return nil, rs.ErrNotFound
	}

	meta, err := fs.readMetadata(fullPath)
	if err != nil {
		return nil, err
	}

	// Handle special cases for start and end
	if start == -1 {
		// Last N bytes case: start = -1, end = number of bytes
		if end > meta.Size {
			end = meta.Size
		}
		start = meta.Size - end
		end = meta.Size - 1
	} else if end == -1 {
		// From start to end of file
		end = meta.Size - 1
	}

	// Validate range
	if start < 0 || start >= meta.Size || end < start || end >= meta.Size {
		return nil, fmt.Errorf("invalid range: start=%d, end=%d, content_length=%d", start, end, meta.Size)
	}

	// Open file and seek to start position
	file, err := fs.fs.Open(fullPath)
	if err != nil {
		return nil, err
	}

	// Create a reader that only reads the requested range
	seeker, ok := file.(io.Seeker)
	if !ok {
		file.Close()
		return nil, fmt.Errorf("file does not support seeking")
	}

	if _, err := seeker.Seek(start, io.SeekStart); err != nil {
		file.Close()
		return nil, err
	}

	rangeSize := end - start + 1
	limitedReader := io.LimitReader(file, rangeSize)

	return &rs.Document{
		Metadata: rs.Metadata{
			Path:         path,
			Name:         fs.pathName(path),
			ContentType:  meta.ContentType,
			ETag:         meta.ETag,
			LastModified: meta.LastModified,
			Size:         rangeSize,
			IsFolder:     false,
		},
		Body: &fileCloser{Reader: limitedReader, file: file},
	}, nil
}

// Helper methods

func (fs *FilesystemStorage) buildPath(path string) string {
	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return filepath.Join(fs.root, path)
}

func (fs *FilesystemStorage) pathName(p string) string {
	name := filepath.Base(p)
	if name == "/" || name == "." {
		return ""
	}
	return name
}

func (fs *FilesystemStorage) getMetadataPath(filePath string) string {
	return filePath + ".meta"
}

func (fs *FilesystemStorage) getDocument(path, fullPath string) (*rs.Document, *rs.FolderListing, error) {
	meta, err := fs.readMetadata(fullPath)
	if err != nil {
		return nil, nil, err
	}

	file, err := fs.fs.Open(fullPath)
	if err != nil {
		return nil, nil, err
	}

	return &rs.Document{
		Metadata: rs.Metadata{
			Path:         path,
			Name:         fs.pathName(path),
			ContentType:  meta.ContentType,
			ETag:         meta.ETag,
			LastModified: meta.LastModified,
			Size:         meta.Size,
			IsFolder:     false,
		},
		Body: file,
	}, nil, nil
}

func (fs *FilesystemStorage) getFolderListing(path, fullPath string) (*rs.Document, *rs.FolderListing, error) {
	files, err := afero.ReadDir(fs.fs, fullPath)
	if err != nil {
		return nil, nil, err
	}

	items := make(map[string]rs.FolderItem)

	for _, file := range files {
		fileName := file.Name()

		// Skip metadata files
		if strings.HasSuffix(fileName, ".meta") {
			continue
		}

		if file.IsDir() {
			// Directory entry
			items[fileName+"/"] = rs.FolderItem{
				ETag: "", // Directories don't have meaningful ETags in this implementation
			}
		} else {
			// File entry
			filePath := filepath.Join(fullPath, fileName)
			meta, err := fs.readMetadata(filePath)
			if err != nil {
				// If we can't read metadata, create basic entry
				items[fileName] = rs.FolderItem{
					ETag:          fs.generateEtagFromFileInfo(file),
					ContentType:   "application/octet-stream",
					ContentLength: file.Size(),
					LastModified:  file.ModTime().Format(time.RFC1123),
				}
			} else {
				items[fileName] = rs.FolderItem{
					ETag:          meta.ETag,
					ContentType:   meta.ContentType,
					ContentLength: meta.Size,
					LastModified:  meta.LastModified.Format(time.RFC1123),
				}
			}
		}
	}

	// Calculate folder ETag
	folderEtag := fs.calculateFolderEtag(items)

	listing := &rs.FolderListing{
		LDContext: rs.GetFolderListingContext(),
		Metadata: rs.Metadata{
			Path:     path,
			Name:     fs.pathName(path),
			ETag:     folderEtag,
			IsFolder: true,
		},
		Items: items,
	}

	return nil, listing, nil
}

func (fs *FilesystemStorage) writeFile(fullPath string, body io.Reader, contentType string) (string, error) {
	// Ensure parent directory exists
	if err := fs.fs.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return "", err
	}

	// Read content to calculate ETag and size
	content, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}

	// Generate ETag
	etag := fs.generateEtag(content)

	// Write file
	if err := afero.WriteFile(fs.fs, fullPath, content, 0644); err != nil {
		return "", err
	}

	// Write metadata
	meta := fileMetadata{
		ContentType:  contentType,
		ETag:         etag,
		LastModified: time.Now(),
		Size:         int64(len(content)),
	}

	if err := fs.writeMetadata(fullPath, meta); err != nil {
		// If metadata write fails, remove the file and return error
		fs.fs.Remove(fullPath)
		return "", err
	}

	return etag, nil
}

func (fs *FilesystemStorage) readMetadata(filePath string) (*fileMetadata, error) {
	metaPath := fs.getMetadataPath(filePath)

	data, err := afero.ReadFile(fs.fs, metaPath)
	if err != nil {
		// If metadata doesn't exist, try to create it from file info
		return fs.createMetadataFromFile(filePath)
	}

	var meta fileMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

func (fs *FilesystemStorage) writeMetadata(filePath string, meta fileMetadata) error {
	metaPath := fs.getMetadataPath(filePath)

	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	return afero.WriteFile(fs.fs, metaPath, data, 0644)
}

func (fs *FilesystemStorage) createMetadataFromFile(filePath string) (*fileMetadata, error) {
	info, err := fs.fs.Stat(filePath)
	if err != nil {
		return nil, err
	}

	// Read file to calculate ETag
	content, err := afero.ReadFile(fs.fs, filePath)
	if err != nil {
		return nil, err
	}

	meta := &fileMetadata{
		ContentType:  "application/octet-stream", // Default content type
		ETag:         fs.generateEtag(content),
		LastModified: info.ModTime(),
		Size:         info.Size(),
	}

	// Try to write metadata for future use
	fs.writeMetadata(filePath, *meta)

	return meta, nil
}

func (fs *FilesystemStorage) generateEtag(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])[:16]
}

func (fs *FilesystemStorage) generateEtagFromFileInfo(info os.FileInfo) string {
	// Simple etag based on file size and modification time
	data := fmt.Sprintf("%d-%d", info.Size(), info.ModTime().Unix())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:16]
}

func (fs *FilesystemStorage) calculateFolderEtag(items map[string]rs.FolderItem) string {
	h := sha256.New()
	for name, item := range items {
		h.Write([]byte(name))
		h.Write([]byte(item.ETag))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (fs *FilesystemStorage) cleanupEmptyDirs(dirPath string) {
	// Don't remove the root directory
	if dirPath == fs.root || dirPath == "/" {
		return
	}

	// Check if directory is empty
	files, err := afero.ReadDir(fs.fs, dirPath)
	if err != nil {
		return
	}

	if len(files) == 0 {
		// Directory is empty, remove it
		fs.fs.Remove(dirPath)
		// Recursively check parent
		fs.cleanupEmptyDirs(filepath.Dir(dirPath))
	}
}

// fileCloser wraps a reader and ensures the underlying file is closed
type fileCloser struct {
	io.Reader
	file afero.File
}

func (fc *fileCloser) Close() error {
	return fc.file.Close()
}
