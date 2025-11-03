# WebFinger Server for remoteStorage Discovery

This package provides a configurable WebFinger server for remoteStorage discovery, implementing the WebFinger protocol as specified in [draft-dejong-remotestorage-25](https://datatracker.ietf.org/doc/html/draft-dejong-remotestorage).

## Features

- ✅ Spec-compliant WebFinger responses
- ✅ Callback-based user resolution (pluggable)
- ✅ Supports multiple URL patterns (path-based, subdomain, single-user)
- ✅ CORS headers included
- ✅ Can run on separate domain from storage server
- ✅ Support for all remoteStorage properties (auth endpoint, query token support, range requests, etc.)

## Quick Start

```go
package main

import (
    "net/http"
    "anime.bike/remotestorage/pkg/webfinger"
)

func main() {
    // Create a resolver that looks up user storage information
    resolver := webfinger.StorageResolverFunc(func(userID string) (*webfinger.UserStorageInfo, error) {
        // Look up user in your database/config
        authURL := "https://auth.example.com/oauth"
        return &webfinger.UserStorageInfo{
            StorageRoot:  "https://storage.example.com/" + userID,
            AuthEndpoint: &authURL,
            Version:      "draft-dejong-remotestorage-25",
        }, nil
    })

    // Create WebFinger server
    wfServer := webfinger.NewServer("example.com", resolver)

    // Mount at /.well-known/webfinger
    http.Handle("/.well-known/webfinger", wfServer)
    http.ListenAndServe(":80", nil)
}
```

## Architecture

The WebFinger server is **separate** from the storage server. This is intentional and follows the spec:

```
┌─────────────────┐      WebFinger Query       ┌──────────────────┐
│                 │ ───────────────────────────▶│                  │
│  Client App     │                             │  WebFinger       │
│                 │◀─────────────────────────── │  Server          │
└─────────────────┘  Returns storage_root       │  (example.com)   │
         │                                       └──────────────────┘
         │
         │ Uses storage_root from WebFinger
         ▼
┌─────────────────┐
│  Storage Server │
│  (can be on     │
│   different     │
│   domain!)      │
└─────────────────┘
```

## URL Patterns

The WebFinger endpoint handles queries like:

```
GET /.well-known/webfinger?resource=acct:alice@example.com
GET /.well-known/webfinger?resource=http://example.com/
```

And returns:

```json
{
  "subject": "acct:alice@example.com",
  "links": [{
    "rel": "http://tools.ietf.org/id/draft-dejong-remotestorage",
    "href": "https://storage.example.com/alice",
    "properties": {
      "http://remotestorage.io/spec/version": "draft-dejong-remotestorage-25",
      "http://tools.ietf.org/html/rfc6749#section-4.2": "https://auth.example.com/oauth"
    }
  }]
}
```

## StorageResolver Interface

The `StorageResolver` interface is the key to making this flexible:

```go
type StorageResolver interface {
    ResolveStorage(userID string) (*UserStorageInfo, error)
}
```

### UserStorageInfo

```go
type UserStorageInfo struct {
    StorageRoot         string  // Required: base URL for user's storage
    AuthEndpoint        *string // Optional: OAuth endpoint (nil for Kerberos)
    Version             string  // Optional: defaults to draft-dejong-remotestorage-25
    QueryTokenSupport   *bool   // Optional: nil to omit
    RangeRequestSupport string  // Optional: empty to omit
    WebAuthoringDomain  string  // Optional: empty to omit
}
```

## Examples

### 1. Static User List

```go
users := map[string]string{
    "alice": "https://storage.example.com/alice",
    "bob":   "https://storage.example.com/bob",
}

resolver := webfinger.StorageResolverFunc(func(userID string) (*webfinger.UserStorageInfo, error) {
    storageRoot, exists := users[userID]
    if !exists {
        return nil, nil // User not found
    }

    authURL := "https://auth.example.com/oauth"
    return &webfinger.UserStorageInfo{
        StorageRoot:  storageRoot,
        AuthEndpoint: &authURL,
    }, nil
})
```

### 2. Database Lookup

```go
resolver := webfinger.StorageResolverFunc(func(userID string) (*webfinger.UserStorageInfo, error) {
    user, err := db.FindUserByUsername(userID)
    if err != nil {
        return nil, err
    }
    if user == nil {
        return nil, nil // Not found
    }

    return &webfinger.UserStorageInfo{
        StorageRoot:  user.StorageURL,
        AuthEndpoint: &user.OAuthEndpoint,
    }, nil
})
```

### 3. Subdomain-Based Routing

```go
resolver := webfinger.StorageResolverFunc(func(userID string) (*webfinger.UserStorageInfo, error) {
    // Return subdomain-based storage root
    authURL := "https://auth.example.com/oauth"
    storageRoot := fmt.Sprintf("https://%s.storage.example.com", userID)

    return &webfinger.UserStorageInfo{
        StorageRoot:  storageRoot,
        AuthEndpoint: &authURL,
    }, nil
})
```

### 4. Single-User Server

```go
// Always return the same storage for any user query
resolver := webfinger.StorageResolverFunc(func(userID string) (*webfinger.UserStorageInfo, error) {
    authURL := "https://mydomain.com/oauth"
    return &webfinger.UserStorageInfo{
        StorageRoot:  "https://mydomain.com",
        AuthEndpoint: &authURL,
    }, nil
})
```

### 5. With OIDC Implementation

```go
// Using the OidcBasedImplementation
oidcImpl := impl.NewOidcBasedImplementationWithOAuth(...)
oidcImpl.SetWebfingerUsers([]impl.WebfingerUser{
    {Username: "alice", Sub: "user-123"},
    {Username: "bob", Sub: "user-456"},
})

// Create resolver from OIDC implementation
resolver := oidcImpl.CreateWebFingerResolver(
    "https://storage.example.com",
    "https://auth.example.com/oauth",
)

wfServer := webfinger.NewServer("example.com", resolver)
```

## Separate WebFinger and Storage Servers

The spec **encourages** running WebFinger and storage on different servers:

```go
// Server 1: WebFinger on main domain (example.com)
func runWebFingerServer() {
    resolver := webfinger.StorageResolverFunc(func(userID string) (*webfinger.UserStorageInfo, error) {
        authURL := "https://auth.example.com/oauth"
        return &webfinger.UserStorageInfo{
            // Points to separate storage server!
            StorageRoot:  "https://storage.example.com/" + userID,
            AuthEndpoint: &authURL,
        }, nil
    })

    wfServer := webfinger.NewServer("example.com", resolver)
    http.Handle("/.well-known/webfinger", wfServer)
    http.ListenAndServe(":80", nil)
}

// Server 2: Storage on subdomain (storage.example.com)
func runStorageServer() {
    impl := impl.NewOidcBasedImplementationWithOAuth(...)
    handler := rsserver.NewStorageHandler(impl)
    cors := rsserver.DefaultCORSMiddleware()

    http.Handle("/", cors(handler))
    http.ListenAndServe(":8080", nil)
}
```

## Advanced: Custom Properties

```go
resolver := webfinger.StorageResolverFunc(func(userID string) (*webfinger.UserStorageInfo, error) {
    authURL := "https://auth.example.com/oauth"
    supportsQueryToken := true

    return &webfinger.UserStorageInfo{
        StorageRoot:         "https://storage.example.com/" + userID,
        AuthEndpoint:        &authURL,
        Version:             "draft-dejong-remotestorage-25",
        QueryTokenSupport:   &supportsQueryToken,
        RangeRequestSupport: "GET",
        WebAuthoringDomain:  "blog.example.com",
    }, nil
})
```

## Testing

Test your WebFinger endpoint:

```bash
curl "http://localhost:8080/.well-known/webfinger?resource=acct:alice@example.com"
```

Expected response:

```json
{
  "subject": "acct:alice@example.com",
  "links": [{
    "rel": "http://tools.ietf.org/id/draft-dejong-remotestorage",
    "type": "application/json",
    "href": "https://storage.example.com/alice",
    "properties": {
      "http://remotestorage.io/spec/version": "draft-dejong-remotestorage-25",
      "http://tools.ietf.org/html/rfc6749#section-4.2": "https://auth.example.com/oauth"
    }
  }]
}
```

## Spec Compliance

This implementation is fully compliant with:
- [RFC 7033 - WebFinger](https://tools.ietf.org/html/rfc7033)
- [draft-dejong-remotestorage-25](https://datatracker.ietf.org/doc/html/draft-dejong-remotestorage) Section 10

Key features:
- ✅ Proper `acct:` URI parsing
- ✅ Domain validation
- ✅ CORS headers for cross-origin requests
- ✅ Correct JSON-LD response format
- ✅ Support for all spec properties
