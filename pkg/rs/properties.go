package rs

import (
	"strings"

	"anime.bike/remotestorage/pkg/nullable"
)

// WebFinger property keys on the remoteStorage link.
const (
	PropVersion             = "http://remotestorage.io/spec/version"
	PropImplicitAuthDialog  = "http://tools.ietf.org/html/rfc6749#section-4.2"
	PropAuthorizeEndpoint   = "http://tools.ietf.org/html/rfc6749#section-3.1"
	PropTokenEndpoint       = "http://tools.ietf.org/html/rfc6749#section-3.2"
	PropPKCEMethods         = "http://tools.ietf.org/html/rfc7636"
	PropQueryTokenSupport   = "http://tools.ietf.org/html/rfc6750#section-2.3"
	PropRangeRequestSupport = "http://tools.ietf.org/html/rfc7233"
	PropWebAuthoringDomain  = "http://remotestorage.io/spec/web-authoring"
)

// RemoteStorageProperties represents the standardized WebFinger properties for RemoteStorage
type RemoteStorageProperties struct {
	// Version represents the RemoteStorage protocol version
	// Example: "draft-dejong-remotestorage-27"
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

	// Optional PKCE support (spec §10.1). Omitted when unset.
	AuthorizationEndpoint nullable.String `json:"http://tools.ietf.org/html/rfc6749#section-3.1,omitzero"`
	TokenEndpoint         nullable.String `json:"http://tools.ietf.org/html/rfc6749#section-3.2,omitzero"`
	// PKCEMethods lists supported code_challenge methods, e.g. "S256".
	PKCEMethods nullable.String `json:"http://tools.ietf.org/html/rfc7636,omitzero"`
}

// NewRemoteStorageProperties creates RemoteStorageProperties from a map
func NewRemoteStorageProperties(props map[string]interface{}) *RemoteStorageProperties {
	if props == nil {
		return nil
	}

	p := &RemoteStorageProperties{}

	if v, ok := props[PropVersion].(string); ok {
		version := VersionName(v)
		p.Version = version
	}

	if v, ok := props[PropImplicitAuthDialog].(string); ok {
		p.AuthEndpoint = nullable.NewString(v)
	}

	if v, ok := props[PropQueryTokenSupport].(bool); ok {
		p.QueryTokenSupport = nullable.NewBool(v)
	}

	if v, ok := props[PropRangeRequestSupport].(string); ok {
		p.RangeRequestSupport = nullable.NewString(v)
	}

	if v, ok := props[PropWebAuthoringDomain].(string); ok {
		p.WebAuthoringDomain = nullable.NewString(v)
	}

	if v, ok := props[PropAuthorizeEndpoint].(string); ok {
		p.AuthorizationEndpoint = nullable.NewString(v)
	}

	if v, ok := props[PropTokenEndpoint].(string); ok {
		p.TokenEndpoint = nullable.NewString(v)
	}

	if v, ok := props[PropPKCEMethods].(string); ok {
		p.PKCEMethods = nullable.NewString(v)
	}

	return p
}

// SupportsPKCE reports whether the server advertises the §10.1 code flow with S256.
func (p *RemoteStorageProperties) SupportsPKCE() bool {
	if p == nil || p.AuthorizationEndpoint.Value == nil || p.TokenEndpoint.Value == nil || p.PKCEMethods.Value == nil {
		return false
	}
	if *p.AuthorizationEndpoint.Value == "" || *p.TokenEndpoint.Value == "" {
		return false
	}
	for _, m := range strings.FieldsFunc(*p.PKCEMethods.Value, func(r rune) bool { return r == ' ' || r == ',' }) {
		if m == PKCEMethodS256 {
			return true
		}
	}
	return false
}

// GetAuthorizationEndpoint returns the §10.1 authorization endpoint, if advertised.
func (p *RemoteStorageProperties) GetAuthorizationEndpoint() string {
	if p != nil && p.AuthorizationEndpoint.Value != nil {
		return *p.AuthorizationEndpoint.Value
	}
	return ""
}

// GetTokenEndpoint returns the §10.1 token endpoint, if advertised.
func (p *RemoteStorageProperties) GetTokenEndpoint() string {
	if p != nil && p.TokenEndpoint.Value != nil {
		return *p.TokenEndpoint.Value
	}
	return ""
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
