package rsstorage_filesystem

import (
	"context"
	"io"
	"strings"
	"testing"

	"anime.bike/remotestorage/pkg/rs"
)

func TestFilesystemStorage_CreateAndGet(t *testing.T) {
	storage := NewMemoryFilesystemStorage()
	ctx := context.Background()

	// Test creating a file
	content := "Hello, World!"
	etag, err := storage.Create(ctx, "/test.txt", strings.NewReader(content), "text/plain")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if etag == "" {
		t.Fatal("Create should return non-empty etag")
	}

	// Test getting the file
	doc, listing, err := storage.Get(ctx, "/test.txt")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if listing != nil {
		t.Fatal("Get file should not return folder listing")
	}
	if doc == nil {
		t.Fatal("Get file should return document")
	}

	// Verify content
	body, err := io.ReadAll(doc.Body)
	doc.Body.Close()
	if err != nil {
		t.Fatalf("Reading body failed: %v", err)
	}
	if string(body) != content {
		t.Fatalf("Expected content %q, got %q", content, string(body))
	}

	// Verify metadata
	if doc.Metadata.ContentType != "text/plain" {
		t.Fatalf("Expected content type text/plain, got %s", doc.Metadata.ContentType)
	}
	if doc.Metadata.ETag != etag {
		t.Fatalf("Expected etag %s, got %s", etag, doc.Metadata.ETag)
	}
	if doc.Metadata.Size != int64(len(content)) {
		t.Fatalf("Expected size %d, got %d", len(content), doc.Metadata.Size)
	}
}

func TestFilesystemStorage_CreateDuplicate(t *testing.T) {
	storage := NewMemoryFilesystemStorage()
	ctx := context.Background()

	// Create first file
	_, err := storage.Create(ctx, "/test.txt", strings.NewReader("content"), "text/plain")
	if err != nil {
		t.Fatalf("First create failed: %v", err)
	}

	// Try to create duplicate
	_, err = storage.Create(ctx, "/test.txt", strings.NewReader("content2"), "text/plain")
	if err != rs.ErrAlreadyExists {
		t.Fatalf("Expected ErrAlreadyExists, got %v", err)
	}
}

func TestFilesystemStorage_Update(t *testing.T) {
	storage := NewMemoryFilesystemStorage()
	ctx := context.Background()

	// Create file
	etag1, err := storage.Create(ctx, "/test.txt", strings.NewReader("content1"), "text/plain")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Update file
	etag2, err := storage.Update(ctx, "/test.txt", strings.NewReader("content2"), "text/html", etag1)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if etag2 == etag1 {
		t.Fatal("Update should change etag")
	}

	// Verify updated content
	doc, _, err := storage.Get(ctx, "/test.txt")
	if err != nil {
		t.Fatalf("Get after update failed: %v", err)
	}
	body, err := io.ReadAll(doc.Body)
	doc.Body.Close()
	if err != nil {
		t.Fatalf("Reading body failed: %v", err)
	}
	if string(body) != "content2" {
		t.Fatalf("Expected content2, got %s", string(body))
	}
	if doc.Metadata.ContentType != "text/html" {
		t.Fatalf("Expected content type text/html, got %s", doc.Metadata.ContentType)
	}
}

func TestFilesystemStorage_UpdateEtagMismatch(t *testing.T) {
	storage := NewMemoryFilesystemStorage()
	ctx := context.Background()

	// Create file
	_, err := storage.Create(ctx, "/test.txt", strings.NewReader("content"), "text/plain")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Try to update with wrong etag
	_, err = storage.Update(ctx, "/test.txt", strings.NewReader("content2"), "text/plain", "wrong-etag")
	if err != rs.ErrPreconditionFailed {
		t.Fatalf("Expected ErrPreconditionFailed, got %v", err)
	}
}

func TestFilesystemStorage_Delete(t *testing.T) {
	storage := NewMemoryFilesystemStorage()
	ctx := context.Background()

	// Create file
	etag, err := storage.Create(ctx, "/test.txt", strings.NewReader("content"), "text/plain")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Delete file
	err = storage.Delete(ctx, "/test.txt", etag)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify file is gone
	_, _, err = storage.Get(ctx, "/test.txt")
	if err != rs.ErrNotFound {
		t.Fatalf("Expected ErrNotFound after delete, got %v", err)
	}
}

func TestFilesystemStorage_DeleteEtagMismatch(t *testing.T) {
	storage := NewMemoryFilesystemStorage()
	ctx := context.Background()

	// Create file
	_, err := storage.Create(ctx, "/test.txt", strings.NewReader("content"), "text/plain")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Try to delete with wrong etag
	err = storage.Delete(ctx, "/test.txt", "wrong-etag")
	if err != rs.ErrPreconditionFailed {
		t.Fatalf("Expected ErrPreconditionFailed, got %v", err)
	}
}

func TestFilesystemStorage_Head(t *testing.T) {
	storage := NewMemoryFilesystemStorage()
	ctx := context.Background()

	// Create file
	content := "Hello, World!"
	etag, err := storage.Create(ctx, "/test.txt", strings.NewReader(content), "text/plain")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Get head
	meta, err := storage.Head(ctx, "/test.txt")
	if err != nil {
		t.Fatalf("Head failed: %v", err)
	}

	// Verify metadata
	if meta.ContentType != "text/plain" {
		t.Fatalf("Expected content type text/plain, got %s", meta.ContentType)
	}
	if meta.ETag != etag {
		t.Fatalf("Expected etag %s, got %s", etag, meta.ETag)
	}
	if meta.Size != int64(len(content)) {
		t.Fatalf("Expected size %d, got %d", len(content), meta.Size)
	}
	if meta.IsFolder {
		t.Fatal("File should not be marked as folder")
	}
}

func TestFilesystemStorage_FolderListing(t *testing.T) {
	storage := NewMemoryFilesystemStorage()
	ctx := context.Background()

	// Create files in a directory
	_, err := storage.Create(ctx, "/folder/file1.txt", strings.NewReader("content1"), "text/plain")
	if err != nil {
		t.Fatalf("Create file1 failed: %v", err)
	}
	_, err = storage.Create(ctx, "/folder/file2.json", strings.NewReader(`{"key":"value"}`), "application/json")
	if err != nil {
		t.Fatalf("Create file2 failed: %v", err)
	}

	// Create subdirectory
	_, err = storage.Create(ctx, "/folder/subfolder/file3.txt", strings.NewReader("content3"), "text/plain")
	if err != nil {
		t.Fatalf("Create file3 failed: %v", err)
	}

	// Get folder listing
	doc, listing, err := storage.Get(ctx, "/folder/")
	if err != nil {
		t.Fatalf("Get folder failed: %v", err)
	}
	if doc != nil {
		t.Fatal("Get folder should not return document")
	}
	if listing == nil {
		t.Fatal("Get folder should return listing")
	}

	// Verify listing contents
	items := listing.Items
	if len(items) != 3 {
		t.Fatalf("Expected 3 items, got %d", len(items))
	}

	// Check file1.txt
	if item, ok := items["file1.txt"]; !ok {
		t.Fatal("file1.txt not found in listing")
	} else {
		if item.ContentType != "text/plain" {
			t.Fatalf("Expected text/plain for file1, got %s", item.ContentType)
		}
		if item.ContentLength != 8 {
			t.Fatalf("Expected length 8 for file1, got %d", item.ContentLength)
		}
	}

	// Check file2.json
	if item, ok := items["file2.json"]; !ok {
		t.Fatal("file2.json not found in listing")
	} else {
		if item.ContentType != "application/json" {
			t.Fatalf("Expected application/json for file2, got %s", item.ContentType)
		}
	}

	// Check subfolder/
	if _, ok := items["subfolder/"]; !ok {
		t.Fatal("subfolder/ not found in listing")
	}
}

func TestFilesystemStorage_GetRange(t *testing.T) {
	storage := NewMemoryFilesystemStorage()
	ctx := context.Background()

	// Create file with known content
	content := "0123456789abcdef"
	_, err := storage.Create(ctx, "/test.txt", strings.NewReader(content), "text/plain")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Test range request (bytes 5-9)
	doc, err := storage.GetRange(ctx, "/test.txt", 5, 9)
	if err != nil {
		t.Fatalf("GetRange failed: %v", err)
	}

	body, err := io.ReadAll(doc.Body)
	doc.Body.Close()
	if err != nil {
		t.Fatalf("Reading range body failed: %v", err)
	}

	expected := "56789"
	if string(body) != expected {
		t.Fatalf("Expected range content %q, got %q", expected, string(body))
	}
	if doc.Metadata.Size != 5 {
		t.Fatalf("Expected range size 5, got %d", doc.Metadata.Size)
	}
}

func TestFilesystemStorage_GetRangeLastNBytes(t *testing.T) {
	storage := NewMemoryFilesystemStorage()
	ctx := context.Background()

	// Create file with known content
	content := "0123456789"
	_, err := storage.Create(ctx, "/test.txt", strings.NewReader(content), "text/plain")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Test last 3 bytes
	doc, err := storage.GetRange(ctx, "/test.txt", -1, 3)
	if err != nil {
		t.Fatalf("GetRange last N bytes failed: %v", err)
	}

	body, err := io.ReadAll(doc.Body)
	doc.Body.Close()
	if err != nil {
		t.Fatalf("Reading range body failed: %v", err)
	}

	expected := "789"
	if string(body) != expected {
		t.Fatalf("Expected last 3 bytes %q, got %q", expected, string(body))
	}
}

func TestFilesystemStorage_GetRangeFromStart(t *testing.T) {
	storage := NewMemoryFilesystemStorage()
	ctx := context.Background()

	// Create file with known content
	content := "0123456789"
	_, err := storage.Create(ctx, "/test.txt", strings.NewReader(content), "text/plain")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Test from position 3 to end
	doc, err := storage.GetRange(ctx, "/test.txt", 3, -1)
	if err != nil {
		t.Fatalf("GetRange from start failed: %v", err)
	}

	body, err := io.ReadAll(doc.Body)
	doc.Body.Close()
	if err != nil {
		t.Fatalf("Reading range body failed: %v", err)
	}

	expected := "3456789"
	if string(body) != expected {
		t.Fatalf("Expected from position 3 %q, got %q", expected, string(body))
	}
}

func TestFilesystemStorage_OSFilesystem(t *testing.T) {
	// Create a temporary directory for testing with OS filesystem
	tempDir := t.TempDir()
	storage := NewOSFilesystemStorage(tempDir)
	ctx := context.Background()

	// Test basic operations with OS filesystem
	content := "Hello, OS Filesystem!"
	etag, err := storage.Create(ctx, "/test.txt", strings.NewReader(content), "text/plain")
	if err != nil {
		t.Fatalf("Create on OS filesystem failed: %v", err)
	}

	// Verify file exists and content is correct
	doc, _, err := storage.Get(ctx, "/test.txt")
	if err != nil {
		t.Fatalf("Get from OS filesystem failed: %v", err)
	}

	body, err := io.ReadAll(doc.Body)
	doc.Body.Close()
	if err != nil {
		t.Fatalf("Reading body failed: %v", err)
	}

	if string(body) != content {
		t.Fatalf("Expected content %q, got %q", content, string(body))
	}
	if doc.Metadata.ETag != etag {
		t.Fatalf("Expected etag %s, got %s", etag, doc.Metadata.ETag)
	}
}

func TestFilesystemStorage_NotFound(t *testing.T) {
	storage := NewMemoryFilesystemStorage()
	ctx := context.Background()

	// Test getting non-existent file
	_, _, err := storage.Get(ctx, "/nonexistent.txt")
	if err != rs.ErrNotFound {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test head of non-existent file
	_, err = storage.Head(ctx, "/nonexistent.txt")
	if err != rs.ErrNotFound {
		t.Fatalf("Expected ErrNotFound for head, got %v", err)
	}

	// Test update of non-existent file
	_, err = storage.Update(ctx, "/nonexistent.txt", strings.NewReader("content"), "text/plain", "")
	if err != rs.ErrNotFound {
		t.Fatalf("Expected ErrNotFound for update, got %v", err)
	}

	// Test delete of non-existent file
	err = storage.Delete(ctx, "/nonexistent.txt", "")
	if err != rs.ErrNotFound {
		t.Fatalf("Expected ErrNotFound for delete, got %v", err)
	}
}