package rsserver

import (
	"net/http"
)

// ServerHooks are optional callbacks around requests. Nil hooks are skipped.
type ServerHooks struct {
	// BeforeWrite runs after authorization of a PUT. It may wrap r.Body or
	// reject the request by returning an HTTPError or an rs error.
	BeforeWrite func(r *http.Request, authInfo *AuthInfo, req *ResourceRequest) error

	// BeforeRead runs after authorization of a GET or HEAD.
	BeforeRead func(r *http.Request, authInfo *AuthInfo, req *ResourceRequest) error

	// BeforeDelete runs after authorization of a DELETE.
	BeforeDelete func(r *http.Request, authInfo *AuthInfo, req *ResourceRequest) error

	// AfterWrite runs after a successful PUT.
	AfterWrite func(r *http.Request, authInfo *AuthInfo, req *ResourceRequest, etag string)

	// AfterRead runs after a successful GET or HEAD.
	AfterRead func(r *http.Request, authInfo *AuthInfo, req *ResourceRequest)

	// AfterDelete runs after a successful DELETE.
	AfterDelete func(r *http.Request, authInfo *AuthInfo, req *ResourceRequest)
}

func (h ServerHooks) callBeforeWrite(r *http.Request, a *AuthInfo, req *ResourceRequest) error {
	if h.BeforeWrite != nil {
		return h.BeforeWrite(r, a, req)
	}
	return nil
}

func (h ServerHooks) callBeforeRead(r *http.Request, a *AuthInfo, req *ResourceRequest) error {
	if h.BeforeRead != nil {
		return h.BeforeRead(r, a, req)
	}
	return nil
}

func (h ServerHooks) callBeforeDelete(r *http.Request, a *AuthInfo, req *ResourceRequest) error {
	if h.BeforeDelete != nil {
		return h.BeforeDelete(r, a, req)
	}
	return nil
}

func (h ServerHooks) callAfterWrite(r *http.Request, a *AuthInfo, req *ResourceRequest, etag string) {
	if h.AfterWrite != nil {
		h.AfterWrite(r, a, req, etag)
	}
}

func (h ServerHooks) callAfterRead(r *http.Request, a *AuthInfo, req *ResourceRequest) {
	if h.AfterRead != nil {
		h.AfterRead(r, a, req)
	}
}

func (h ServerHooks) callAfterDelete(r *http.Request, a *AuthInfo, req *ResourceRequest) {
	if h.AfterDelete != nil {
		h.AfterDelete(r, a, req)
	}
}
