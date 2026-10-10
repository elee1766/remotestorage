package rsserver

import (
	"slices"

	"anime.bike/remotestorage/pkg/rs"
)

// Check evaluates the condition against the current state of a document.
// exists reports whether the document exists, current is its ETag.
func (c Condition) Check(exists bool, current string) error {
	if len(c.IfMatch) > 0 {
		if !exists {
			return rs.ErrPreconditionFailed
		}
		if !slices.Contains(c.IfMatch, "*") && !slices.Contains(c.IfMatch, current) {
			return rs.ErrPreconditionFailed
		}
	}
	if c.IfNoneMatchAny && exists {
		return rs.ErrPreconditionFailed
	}
	return nil
}
