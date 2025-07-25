package rs

import (
	"encoding/json"
	"strings"
	"testing"

	"anime.bike/remotestorage/pkg/nullable"
)


func TestRemoteStorageProperties_MarshalJSON(t *testing.T) {
	props := &RemoteStorageProperties{
		Version:             SupportedVersion,
		AuthEndpoint:        nullable.NewString("https://example.com/oauth"),
		QueryTokenSupport:   nullable.NewBool(true),
		RangeRequestSupport: nullable.NewString("GET"),
		WebAuthoringDomain:  nullable.String{Value: nil}, // Explicit null
	}

	data, err := json.Marshal(props)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	jsonStr := string(data)
	
	// Check that all fields are present
	expectedFields := []string{
		`"http://remotestorage.io/spec/version":"draft-dejong-remotestorage-25"`,
		`"http://tools.ietf.org/html/rfc6749#section-4.2":"https://example.com/oauth"`,
		`"http://tools.ietf.org/html/rfc6750#section-2.3":true`,
		`"http://tools.ietf.org/html/rfc7233":"GET"`,
		`"http://remotestorage.io/spec/web-authoring":null`,
	}

	for _, field := range expectedFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("Expected JSON to contain %s, but it doesn't: %s", field, jsonStr)
		}
	}
}

