package webfinger

// Response represents a WebFinger response
type Response struct {
	Subject string `json:"subject"`
	Links   []Link `json:"links"`
}

// Link represents a link in a WebFinger response
type Link struct {
	Rel        string         `json:"rel"`
	Type       string         `json:"type,omitempty"`
	Href       string         `json:"href,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}
