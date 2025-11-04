package rsserver

import (
	"errors"
	"fmt"
	"net/http"

	"anime.bike/remotestorage/pkg/rs"
)

// Additional storage errors specific to the server layer
var (
	// ErrOutOfRange indicates the requested byte range is invalid or unsatisfiable
	// This should be returned when a range request exceeds the file size
	ErrOutOfRange = errors.New("requested range not satisfiable")
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

// handleStorageError converts storage errors to appropriate HTTP errors
func handleStorageError(err error) *HTTPError {
	if err == nil {
		return nil
	}

	// Unwrap StorageError to get the underlying error
	if se, ok := err.(*StorageError); ok {
		err = se.Err
	}

	// Check for specific error types from rs package (storage backend errors)
	if errors.Is(err, rs.ErrNotFound) {
		return NewHTTPError(http.StatusNotFound, "Not found")
	}

	if errors.Is(err, rs.ErrAlreadyExists) {
		return NewHTTPError(http.StatusPreconditionFailed, "Precondition Failed")
	}

	if errors.Is(err, rs.ErrPreconditionFailed) {
		return NewHTTPError(http.StatusPreconditionFailed, "Precondition Failed")
	}

	// Check for server-layer errors
	if errors.Is(err, ErrOutOfRange) {
		return NewHTTPError(http.StatusRequestedRangeNotSatisfiable, "Range not satisfiable")
	}

	// Default to internal server error
	return NewHTTPError(http.StatusInternalServerError, "Internal server error")
}
