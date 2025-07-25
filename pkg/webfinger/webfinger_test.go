package webfinger

import (
	"encoding/json"
	"testing"

	"anime.bike/remotestorage/pkg/rs"
)

func TestWebFinger_MarshalJSON(t *testing.T) {
	wf := NewWebFinger("user@example.com")
	wf.AddRemoteStorageLinkWithValues(
		"https://storage.example.com",
		string(rs.SupportedVersion),
		"https://example.com/oauth",
		boolPtr(false),
		"", // This should result in null
		"", // This should result in null
	)

	data, err := json.Marshal(wf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Unmarshal to verify structure
	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Check subject
	if result["subject"] != "user@example.com" {
		t.Errorf("Expected subject to be user@example.com, got %v", result["subject"])
	}

	// Check links
	links, ok := result["links"].([]interface{})
	if !ok || len(links) != 1 {
		t.Fatalf("Expected one link, got %v", result["links"])
	}

	link := links[0].(map[string]interface{})
	props := link["properties"].(map[string]interface{})

	// Verify properties
	if props["http://remotestorage.io/spec/version"] != string(rs.SupportedVersion) {
		t.Errorf("Expected version to be %s, got %v", rs.SupportedVersion, props["http://remotestorage.io/spec/version"])
	}

	if props["http://tools.ietf.org/html/rfc6750#section-2.3"] != false {
		t.Errorf("Expected query token support to be false, got %v", props["http://tools.ietf.org/html/rfc6750#section-2.3"])
	}

	// Check that empty strings result in null
	if props["http://tools.ietf.org/html/rfc7233"] != nil {
		t.Errorf("Expected range request support to be null, got %v", props["http://tools.ietf.org/html/rfc7233"])
	}

	if props["http://remotestorage.io/spec/web-authoring"] != nil {
		t.Errorf("Expected web authoring domain to be null, got %v", props["http://remotestorage.io/spec/web-authoring"])
	}
}

func TestWebFinger_WithMapProperties(t *testing.T) {
	wf := NewWebFinger("user@example.com")
	
	// Test adding link with map properties
	link := WebFingLink{
		Rel:  rs.RemoteStorageRel,
		Type: "application/json",
		Href: "https://storage.example.com",
		Properties: map[string]interface{}{
			"http://remotestorage.io/spec/version": string(rs.SupportedVersion),
			"custom-property": "custom-value",
		},
	}
	wf.Links = append(wf.Links, link)

	data, err := json.Marshal(wf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify it marshals correctly
	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	links := result["links"].([]interface{})
	linkMap := links[0].(map[string]interface{})
	props := linkMap["properties"].(map[string]interface{})

	if props["custom-property"] != "custom-value" {
		t.Errorf("Expected custom-property to be custom-value, got %v", props["custom-property"])
	}
}

// Helper functions
func boolPtr(b bool) *bool {
	return &b
}