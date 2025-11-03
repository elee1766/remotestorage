package rsserver

import (
	"net/http"
	"testing"
)

func TestParseRange(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		size       int64
		wantStart  int64
		wantEnd    int64
		wantErr    bool
		wantStatus int
	}{
		{
			name:      "empty header",
			header:    "",
			size:      1000,
			wantStart: 0,
			wantEnd:   0,
			wantErr:   false,
		},
		{
			name:      "normal range",
			header:    "bytes=0-499",
			size:      1000,
			wantStart: 0,
			wantEnd:   499,
			wantErr:   false,
		},
		{
			name:      "open-ended range",
			header:    "bytes=500-",
			size:      1000,
			wantStart: 500,
			wantEnd:   -1,
			wantErr:   false,
		},
		{
			name:      "suffix range",
			header:    "bytes=-100",
			size:      1000,
			wantStart: -1,
			wantEnd:   100,
			wantErr:   false,
		},
		{
			name:       "invalid prefix",
			header:     "items=0-100",
			size:       1000,
			wantErr:    true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "multiple ranges not supported",
			header:     "bytes=0-100,200-300",
			size:       1000,
			wantErr:    true,
			wantStatus: http.StatusRequestedRangeNotSatisfiable,
		},
		{
			name:       "start beyond size",
			header:     "bytes=2000-3000",
			size:       1000,
			wantErr:    true,
			wantStatus: http.StatusRequestedRangeNotSatisfiable,
		},
		{
			name:       "invalid format",
			header:     "bytes=abc-def",
			size:       1000,
			wantErr:    true,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRange(tt.header, tt.size)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseRange() expected error, got nil")
					return
				}
				if httpErr, ok := err.(*HTTPError); ok {
					if httpErr.StatusCode != tt.wantStatus {
						t.Errorf("parseRange() status = %d, want %d", httpErr.StatusCode, tt.wantStatus)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("parseRange() unexpected error: %v", err)
				return
			}

			if tt.header == "" {
				if got != nil {
					t.Errorf("parseRange() expected nil for empty header, got %+v", got)
				}
				return
			}

			if got == nil {
				t.Errorf("parseRange() got nil, want range")
				return
			}

			if got.Start != tt.wantStart {
				t.Errorf("parseRange() Start = %d, want %d", got.Start, tt.wantStart)
			}
			if got.End != tt.wantEnd {
				t.Errorf("parseRange() End = %d, want %d", got.End, tt.wantEnd)
			}
		})
	}
}

func TestFormatContentRange(t *testing.T) {
	tests := []struct {
		name  string
		start int64
		end   int64
		total int64
		want  string
	}{
		{
			name:  "first 500 bytes",
			start: 0,
			end:   499,
			total: 1000,
			want:  "bytes 0-499/1000",
		},
		{
			name:  "last 500 bytes",
			start: 500,
			end:   999,
			total: 1000,
			want:  "bytes 500-999/1000",
		},
		{
			name:  "middle range",
			start: 200,
			end:   799,
			total: 1000,
			want:  "bytes 200-799/1000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatContentRange(tt.start, tt.end, tt.total)
			if got != tt.want {
				t.Errorf("formatContentRange() = %q, want %q", got, tt.want)
			}
		})
	}
}
