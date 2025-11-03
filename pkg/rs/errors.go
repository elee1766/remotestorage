package rs

import "errors"

// Common errors for RemoteStorage operations
var (
	// ErrNotFound indicates the requested resource was not found
	ErrNotFound = errors.New("not found")

	// ErrAlreadyExists indicates the resource already exists
	ErrAlreadyExists = errors.New("already exists")

	// ErrPreconditionFailed indicates an etag mismatch
	ErrPreconditionFailed = errors.New("precondition failed")

	// ErrInsufficientScope indicates the token lacks required permissions
	ErrInsufficientScope = errors.New("insufficient scope")
)
