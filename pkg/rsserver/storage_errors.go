package rsserver

import (
	"errors"
	"fmt"
)

// Common storage errors that backends can return
var (
	// ErrNotFound indicates the requested resource does not exist
	ErrNotFound = errors.New("resource not found")

	// ErrOutOfRange indicates the requested byte range is invalid or unsatisfiable
	// This should be returned when a range request exceeds the file size
	ErrOutOfRange = errors.New("requested range not satisfiable")

	// ErrStorageFailure indicates an internal storage error occurred
	ErrStorageFailure = errors.New("storage operation failed")
)

// StorageError wraps storage errors with additional context
type StorageError struct {
	Op   string // Operation that failed (e.g., "Get", "Put", "Delete")
	Path string // Resource path
	Err  error  // Underlying error
}

func (e *StorageError) Error() string {
	return fmt.Sprintf("storage %s %q: %v", e.Op, e.Path, e.Err)
}

func (e *StorageError) Unwrap() error {
	return e.Err
}

// NewStorageError creates a new StorageError
func NewStorageError(op, path string, err error) *StorageError {
	return &StorageError{
		Op:   op,
		Path: path,
		Err:  err,
	}
}
