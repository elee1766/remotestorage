# Filesystem Storage for RemoteStorage

This package provides a filesystem-backed storage implementation for RemoteStorage using [afero.Fs](https://github.com/spf13/afero). It supports multiple filesystem backends including the OS filesystem, in-memory filesystem, and any custom afero.Fs implementation.

## Features

- **Multiple filesystem backends**: OS filesystem, in-memory, or custom afero.Fs
- **Full RemoteStorage protocol support**: All required operations (GET, PUT, DELETE, HEAD)
- **Range request support**: HTTP Range requests for partial file downloads
- **Atomic operations**: ETag-based conditional operations
- **Metadata storage**: Content-Type, ETag, and modification time preservation
- **Multi-user support**: Isolated storage per user/bucket
- **Automatic cleanup**: Empty directories are automatically removed

## Usage

### Basic Filesystem Storage

```go
import "anime.bike/remotestorage/pkg/rsserver/rsstorage/rsstorage_filesystem"

// OS filesystem storage
storage := rsstorage_filesystem.NewOSFilesystemStorage("/path/to/storage")

// In-memory storage (for testing)
storage := rsstorage_filesystem.NewMemoryFilesystemStorage()

// Custom afero.Fs
storage := rsstorage_filesystem.NewFilesystemStorage(customFs, "/root/path")
```

### Bucket Storage (Single User)

```go
// For single-user/bucket scenarios
bucketStorage := rsstorage_filesystem.NewOSBucketFilesystemStorage("/path/to/bucket")
```

### Multi-User Storage

```go
// For multi-user scenarios
multiUserStorage := rsstorage_filesystem.NewOSMultiUserFilesystemStorage("/path/to/root")

// Get storage for a specific user
userStorage := multiUserStorage.GetUserStorage("alice")

// Get bucket storage for a specific bucket
bucketStorage := multiUserStorage.GetBucketStorage("alice_documents")
```

## File Structure

The storage creates the following structure on disk:

```
/storage/root/
├── path/to/file.txt          # Actual file content
├── path/to/file.txt.meta     # Metadata (JSON)
└── path/to/folder/           # Directories
```

### Metadata Format

Each file has an associated `.meta` file containing:

```json
{
  "content_type": "text/plain",
  "etag": "a1b2c3d4e5f6",
  "last_modified": "2023-01-01T12:00:00Z",
  "size": 1024
}
```

## Supported Operations

### StorageBackend Interface

- `Get(path)` - Retrieve document or folder listing
- `Create(path, body, contentType)` - Create new document
- `Update(path, body, contentType, etag)` - Update existing document
- `Delete(path, etag)` - Delete document
- `Head(path)` - Get document metadata

### StorageBackendRange Interface

- `GetRange(path, start, end)` - Retrieve document range

## Error Handling

The implementation returns standard RemoteStorage errors:

- `rs.ErrNotFound` - File or directory not found
- `rs.ErrAlreadyExists` - File already exists (on Create)
- `rs.ErrPreconditionFailed` - ETag mismatch

## Example Server Implementation

```go
package main

import (
    "anime.bike/remotestorage/pkg/rsserver"
    "anime.bike/remotestorage/pkg/rsserver/rsstorage/rsstorage_filesystem"
)

type MyImplementation struct {
    storage *rsstorage_filesystem.MultiUserFilesystemStorage
}

func (impl *MyImplementation) GetStorage(r *http.Request) (*rsserver.StorageResult, error) {
    // Parse username and module from URL path
    // Return appropriate storage for the user
    userStorage := impl.storage.GetBucketStorage(bucketID)
    
    return &rsserver.StorageResult{
        Storage: userStorage,
        Module:  module,
        Path:    filePath,
    }, nil
}

func main() {
    impl := &MyImplementation{
        storage: rsstorage_filesystem.NewOSMultiUserFilesystemStorage("/var/lib/remotestorage"),
    }
    
    storageHandler := rsserver.NewStorageHandler(impl)
    // ... configure and start server
}
```

## Testing

The package includes comprehensive tests covering all operations:

```bash
go test ./pkg/rsserver/rsstorage/rsstorage_filesystem -v
```

## Performance Considerations

- **Metadata overhead**: Each file has a corresponding `.meta` file
- **Directory scanning**: Folder listings require reading directory contents
- **ETag calculation**: ETags are SHA256-based for content integrity
- **Atomic operations**: Metadata is written after successful file operations

## Filesystem Compatibility

Works with any afero.Fs implementation:

- `afero.OsFs` - Operating system filesystem
- `afero.MemMapFs` - In-memory filesystem
- `afero.BasePathFs` - Restricted base path
- `afero.ReadOnlyFs` - Read-only wrapper
- Custom implementations

## Thread Safety

The implementation is thread-safe when used with thread-safe afero.Fs implementations. The OS filesystem (`afero.OsFs`) is thread-safe for concurrent operations.