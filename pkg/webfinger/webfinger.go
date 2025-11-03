package webfinger

import (
	"anime.bike/remotestorage/pkg/nullable"
	"anime.bike/remotestorage/pkg/rs"
)

// WebFinger represents a WebFinger record for RemoteStorage discovery
type WebFinger struct {
	Subject string        `json:"subject"`
	Links   []WebFingLink `json:"links"`
}

// WebFingLink represents a link in a RemoteStorage WebFinger record
type WebFingLink struct {
	Rel        string `json:"rel"`
	Type       string `json:"type,omitempty"`
	Href       string `json:"href,omitempty"`
	Properties any    `json:"properties,omitempty"`
}

// NewWebFinger creates a new WebFinger record for the given subject
func NewWebFinger(subject string) *WebFinger {
	return &WebFinger{
		Subject: subject,
		Links:   make([]WebFingLink, 0),
	}
}

// AddRemoteStorageLink adds a RemoteStorage link to the WebFinger record
func (wf *WebFinger) AddRemoteStorageLink(href string, properties *rs.RemoteStorageProperties) {
	link := WebFingLink{
		Rel:        rs.RemoteStorageRel,
		Type:       "application/json",
		Href:       href,
		Properties: properties,
	}
	wf.Links = append(wf.Links, link)
}

// AddRemoteStorageLinkWithValues is a convenience method to add a link with individual property values
func (wf *WebFinger) AddRemoteStorageLinkWithValues(href string, version, authEndpoint string, queryTokenSupport *bool, rangeRequestSupport string, webAuthoringDomain string) {
	props := &rs.RemoteStorageProperties{}

	if version != "" {
		versionName := rs.VersionName(version)
		props.Version = versionName
	}

	if authEndpoint != "" {
		props.AuthEndpoint = nullable.NewString(authEndpoint)
	}

	if queryTokenSupport != nil {
		props.QueryTokenSupport = nullable.NewBoolPtr(queryTokenSupport)
	}

	if rangeRequestSupport != "" {
		props.RangeRequestSupport = nullable.NewString(rangeRequestSupport)
	}

	if webAuthoringDomain != "" {
		props.WebAuthoringDomain = nullable.NewString(webAuthoringDomain)
	}

	wf.AddRemoteStorageLink(href, props)
}

// GetRemoteStorageLink finds and returns the first RemoteStorage link
func (wf *WebFinger) GetRemoteStorageLink() *WebFingLink {
	for i := range wf.Links {
		if wf.Links[i].Rel == rs.RemoteStorageRel || wf.Links[i].Rel == RelRemoteStorage {
			return &wf.Links[i]
		}
	}
	return nil
}
