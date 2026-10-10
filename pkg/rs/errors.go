package rs

import "errors"

// Errors returned by storage backends. The server maps them to status codes.
var (
	// ErrNotFound: the document does not exist (404).
	ErrNotFound = errors.New("not found")

	// ErrAlreadyExists is kept for compatibility. Backends should return
	// ErrPreconditionFailed for If-None-Match failures.
	ErrAlreadyExists = errors.New("already exists")

	// ErrPreconditionFailed: If-Match or If-None-Match did not hold (412).
	ErrPreconditionFailed = errors.New("precondition failed")

	// ErrConflict: a folder name clashes with a document name or vice versa (409).
	ErrConflict = errors.New("conflict")

	// ErrTooLarge: the document exceeds the size limit (413).
	ErrTooLarge = errors.New("document too large")

	// ErrQuotaExceeded: the account is over its storage quota (507).
	ErrQuotaExceeded = errors.New("quota exceeded")

	// ErrInsufficientScope indicates the token lacks required permissions
	ErrInsufficientScope = errors.New("insufficient scope")
)
