package nullable

import (
	"encoding/json"
	"testing"
)

func TestString_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		ns       String
		expected string
	}{
		{
			name:     "nil value",
			ns:       String{Value: nil},
			expected: "null",
		},
		{
			name:     "empty string",
			ns:       NewString(""),
			expected: `""`,
		},
		{
			name:     "string value",
			ns:       NewString("test"),
			expected: `"test"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.ns)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if string(data) != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, string(data))
			}
		})
	}
}

func TestString_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *string
	}{
		{
			name:     "null value",
			input:    "null",
			expected: nil,
		},
		{
			name:     "empty string",
			input:    `""`,
			expected: stringPtr(""),
		},
		{
			name:     "string value",
			input:    `"test"`,
			expected: stringPtr("test"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ns String
			err := json.Unmarshal([]byte(tt.input), &ns)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if (ns.Value == nil && tt.expected != nil) || (ns.Value != nil && tt.expected == nil) {
				t.Errorf("Expected %v, got %v", tt.expected, ns.Value)
			}
			if ns.Value != nil && tt.expected != nil && *ns.Value != *tt.expected {
				t.Errorf("Expected %s, got %s", *tt.expected, *ns.Value)
			}
		})
	}
}

func TestBool_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		nb       Bool
		expected string
	}{
		{
			name:     "nil value",
			nb:       Bool{Value: nil},
			expected: "null",
		},
		{
			name:     "true value",
			nb:       NewBool(true),
			expected: "true",
		},
		{
			name:     "false value",
			nb:       NewBool(false),
			expected: "false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.nb)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if string(data) != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, string(data))
			}
		})
	}
}

// Helper function for tests
func stringPtr(s string) *string {
	return &s
}
