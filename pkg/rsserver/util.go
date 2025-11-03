package rsserver

import (
	"net/http"
	"strings"
)

// checkIfNoneMatch checks if the If-None-Match header matches the given ETag
// Returns true if the header exists and matches, indicating a 304 should be returned
func checkIfNoneMatch(r *http.Request, currentETag string) bool {
	ifNoneMatch := r.Header.Get("If-None-Match")
	if ifNoneMatch == "" || currentETag == "" {
		return false
	}

	// Parse comma-separated list of ETags
	for etag := range strings.SplitSeq(ifNoneMatch, ",") {
		if strings.TrimSpace(etag) == currentETag {
			return true
		}
	}

	return false
}

// extractBearerToken extracts the bearer token from the Authorization header
// Returns empty string if no bearer token is present
// Per RFC 6750, the check is case-insensitive
func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) {
		return ""
	}

	// Case-insensitive check per RFC 6750
	if !strings.EqualFold(authHeader[:len(bearerPrefix)], bearerPrefix) {
		return ""
	}

	return strings.TrimSpace(authHeader[len(bearerPrefix):])
}
