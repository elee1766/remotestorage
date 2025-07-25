package rs

import (
	"anime.bike/remotestorage/pkg/nullable"
)

// RemoteStorageProperties represents the standardized WebFinger properties for RemoteStorage
type RemoteStorageProperties struct {
	// Version represents the RemoteStorage protocol version
	// Example: "draft-dejong-remotestorage-25"
	Version VersionName `json:"http://remotestorage.io/spec/version"`

	// AuthEndpoint represents the OAuth 2.0 authorization endpoint URL
	// Example: "https://example.com/oauth/auth"
	AuthEndpoint nullable.String `json:"http://tools.ietf.org/html/rfc6749#section-4.2"`

	// QueryTokenSupport indicates if bearer tokens can be passed as query parameters
	// true if supported, false if not supported, null if unspecified
	QueryTokenSupport nullable.Bool `json:"http://tools.ietf.org/html/rfc6750#section-2.3"`

	// RangeRequestSupport indicates if HTTP Range requests are supported
	// "GET" if supported for GET requests, null if not supported
	RangeRequestSupport nullable.String `json:"http://tools.ietf.org/html/rfc7233"`

	// WebAuthoringDomain represents the domain for web authoring content
	// Domain name if web authoring is supported, null if not supported
	WebAuthoringDomain nullable.String `json:"http://remotestorage.io/spec/web-authoring"`
}

// NewRemoteStorageProperties creates RemoteStorageProperties from a map
func NewRemoteStorageProperties(props map[string]interface{}) *RemoteStorageProperties {
	if props == nil {
		return nil
	}

	p := &RemoteStorageProperties{}

	if v, ok := props["http://remotestorage.io/spec/version"].(string); ok {
		version := VersionName(v)
		p.Version = version
	}

	if v, ok := props["http://tools.ietf.org/html/rfc6749#section-4.2"].(string); ok {
		p.AuthEndpoint = nullable.NewString(v)
	}

	if v, ok := props["http://tools.ietf.org/html/rfc6750#section-2.3"].(bool); ok {
		p.QueryTokenSupport = nullable.NewBool(v)
	}

	if v, ok := props["http://tools.ietf.org/html/rfc7233"].(string); ok {
		p.RangeRequestSupport = nullable.NewString(v)
	}

	if v, ok := props["http://remotestorage.io/spec/web-authoring"].(string); ok {
		p.WebAuthoringDomain = nullable.NewString(v)
	}

	return p
}

// GetAuthEndpoint returns the OAuth authorization endpoint URL if available
func (p *RemoteStorageProperties) GetAuthEndpoint() string {
	if p != nil && p.AuthEndpoint.Value != nil {
		return *p.AuthEndpoint.Value
	}
	return ""
}

// GetVersion returns the RemoteStorage protocol version if available
func (p *RemoteStorageProperties) GetVersion() string {
	if p != nil {
		return string(p.Version)
	}
	return ""
}

// SupportsQueryToken returns true if bearer tokens can be passed as query parameters
func (p *RemoteStorageProperties) SupportsQueryToken() bool {
	if p != nil && p.QueryTokenSupport.Value != nil {
		return *p.QueryTokenSupport.Value
	}
	return false
}

// SupportsRangeRequests returns true if HTTP Range requests are supported
func (p *RemoteStorageProperties) SupportsRangeRequests() bool {
	if p != nil && p.RangeRequestSupport.Value != nil {
		return *p.RangeRequestSupport.Value == "GET"
	}
	return false
}

// GetWebAuthoringDomain returns the web authoring domain if available
func (p *RemoteStorageProperties) GetWebAuthoringDomain() string {
	if p != nil && p.WebAuthoringDomain.Value != nil {
		return *p.WebAuthoringDomain.Value
	}
	return ""
}
