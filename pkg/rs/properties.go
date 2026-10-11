package rs

import "strings"

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

// RemoteStorageProperties represents the standardized WebFinger properties for RemoteStorage.
// Nil pointers encode as JSON null, as in the spec's examples.
type RemoteStorageProperties struct {
	// Version represents the RemoteStorage protocol version
	// Example: "draft-dejong-remotestorage-27"
	Version VersionName `json:"http://remotestorage.io/spec/version"`

	// AuthEndpoint represents the OAuth 2.0 authorization endpoint URL
	// Example: "https://example.com/oauth/auth"
	AuthEndpoint *string `json:"http://tools.ietf.org/html/rfc6749#section-4.2"`

	// QueryTokenSupport indicates if bearer tokens can be passed as query parameters
	// true if supported, false if not supported, null if unspecified
	QueryTokenSupport *bool `json:"http://tools.ietf.org/html/rfc6750#section-2.3"`

	// RangeRequestSupport indicates if HTTP Range requests are supported
	// "GET" if supported for GET requests, null if not supported
	RangeRequestSupport *string `json:"http://tools.ietf.org/html/rfc7233"`

	// WebAuthoringDomain represents the domain for web authoring content
	// Domain name if web authoring is supported, null if not supported
	WebAuthoringDomain *string `json:"http://remotestorage.io/spec/web-authoring"`

	// Optional PKCE support (spec §10.1). Omitted when unset.
	AuthorizationEndpoint *string `json:"http://tools.ietf.org/html/rfc6749#section-3.1,omitempty"`
	TokenEndpoint         *string `json:"http://tools.ietf.org/html/rfc6749#section-3.2,omitempty"`
	// PKCEMethods lists supported code_challenge methods, e.g. "S256".
	PKCEMethods *string `json:"http://tools.ietf.org/html/rfc7636,omitempty"`
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
		p.AuthEndpoint = &v
	}

	if v, ok := props[PropQueryTokenSupport].(bool); ok {
		p.QueryTokenSupport = &v
	}

	if v, ok := props[PropRangeRequestSupport].(string); ok {
		p.RangeRequestSupport = &v
	}

	if v, ok := props[PropWebAuthoringDomain].(string); ok {
		p.WebAuthoringDomain = &v
	}

	if v, ok := props[PropAuthorizeEndpoint].(string); ok {
		p.AuthorizationEndpoint = &v
	}

	if v, ok := props[PropTokenEndpoint].(string); ok {
		p.TokenEndpoint = &v
	}

	if v, ok := props[PropPKCEMethods].(string); ok {
		p.PKCEMethods = &v
	}

	return p
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// SupportsPKCE reports whether the server advertises the §10.1 code flow with S256.
func (p *RemoteStorageProperties) SupportsPKCE() bool {
	if p == nil || deref(p.AuthorizationEndpoint) == "" || deref(p.TokenEndpoint) == "" {
		return false
	}
	for _, m := range strings.FieldsFunc(deref(p.PKCEMethods), func(r rune) bool { return r == ' ' || r == ',' }) {
		if m == PKCEMethodS256 {
			return true
		}
	}
	return false
}

// GetAuthorizationEndpoint returns the §10.1 authorization endpoint, if advertised.
func (p *RemoteStorageProperties) GetAuthorizationEndpoint() string {
	if p == nil {
		return ""
	}
	return deref(p.AuthorizationEndpoint)
}

// GetTokenEndpoint returns the §10.1 token endpoint, if advertised.
func (p *RemoteStorageProperties) GetTokenEndpoint() string {
	if p == nil {
		return ""
	}
	return deref(p.TokenEndpoint)
}

// GetAuthEndpoint returns the OAuth authorization endpoint URL if available
func (p *RemoteStorageProperties) GetAuthEndpoint() string {
	if p == nil {
		return ""
	}
	return deref(p.AuthEndpoint)
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
	return p != nil && deref(p.QueryTokenSupport)
}

// SupportsRangeRequests returns true if HTTP Range requests are supported
func (p *RemoteStorageProperties) SupportsRangeRequests() bool {
	return p != nil && deref(p.RangeRequestSupport) == "GET"
}

// GetWebAuthoringDomain returns the web authoring domain if available
func (p *RemoteStorageProperties) GetWebAuthoringDomain() string {
	if p == nil {
		return ""
	}
	return deref(p.WebAuthoringDomain)
}
