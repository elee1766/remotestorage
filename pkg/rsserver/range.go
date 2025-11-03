package rsserver

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// HTTPRange represents a parsed HTTP Range header
type HTTPRange struct {
	Start int64
	End   int64 // -1 means "to end of file"
}

// parseRange parses an HTTP Range header value
// Supports formats like:
// - "bytes=0-1023" (specific range)
// - "bytes=1024-" (from offset to end)
// - "bytes=-500" (last N bytes)
// Returns nil if no Range header present or invalid format
func parseRange(rangeHeader string, size int64) (*HTTPRange, error) {
	if rangeHeader == "" {
		return nil, nil
	}

	// Must start with "bytes="
	const prefix = "bytes="
	if !strings.HasPrefix(rangeHeader, prefix) {
		return nil, NewHTTPError(http.StatusBadRequest, "Invalid Range header: must start with 'bytes='")
	}

	rangeSpec := strings.TrimPrefix(rangeHeader, prefix)

	// Only support single range (not multipart ranges)
	if strings.Contains(rangeSpec, ",") {
		return nil, NewHTTPError(http.StatusRequestedRangeNotSatisfiable, "Multiple ranges not supported")
	}

	parts := strings.SplitN(rangeSpec, "-", 2)
	if len(parts) != 2 {
		return nil, NewHTTPError(http.StatusBadRequest, "Invalid Range format")
	}

	startStr, endStr := parts[0], parts[1]

	// Handle suffix range: "bytes=-500" (last 500 bytes)
	if startStr == "" {
		if endStr == "" {
			return nil, NewHTTPError(http.StatusBadRequest, "Invalid Range: both start and end empty")
		}
		suffixLength, err := strconv.ParseInt(endStr, 10, 64)
		if err != nil || suffixLength <= 0 {
			return nil, NewHTTPError(http.StatusBadRequest, "Invalid Range: invalid suffix length")
		}
		// For suffix ranges, start=-1 signals "last N bytes"
		return &HTTPRange{
			Start: -1,
			End:   suffixLength,
		}, nil
	}

	// Parse start
	start, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil || start < 0 {
		return nil, NewHTTPError(http.StatusBadRequest, "Invalid Range: invalid start")
	}

	// Handle open-ended range: "bytes=1024-"
	var end int64
	if endStr == "" {
		end = -1 // -1 means "to end of file"
	} else {
		end, err = strconv.ParseInt(endStr, 10, 64)
		if err != nil || end < start {
			return nil, NewHTTPError(http.StatusBadRequest, "Invalid Range: invalid end")
		}
	}

	// Validate range if size is known
	if size > 0 && start >= size {
		return nil, NewHTTPError(http.StatusRequestedRangeNotSatisfiable, "Range start exceeds file size")
	}

	return &HTTPRange{
		Start: start,
		End:   end,
	}, nil
}

// formatContentRange formats a Content-Range header value
// For example: "bytes 0-1023/2048"
func formatContentRange(start, end, total int64) string {
	return fmt.Sprintf("bytes %d-%d/%d", start, end, total)
}
