# remotestorage


this is go library to help implement a remotestorage server or client

targets [draft-dejong-remotestorage-27](_doc/draft-dejong-remotestorage-27.txt), including the optional PKCE auth code flow (§10.1).

some simple examples are in the cmd/ directory. these are used to help test and develop the library, and are not production ready tools.

## packages

- `pkg/rs` - shared protocol types, scopes, webfinger properties, pkce helpers
- `pkg/rsserver` - storage http handler
- `pkg/rsclient` - client, discovery, oauth helpers
- `pkg/webfinger` - webfinger server and parsing

## server

`rsserver.Handler` implements the storage protocol: CORS and preflight,
bearer auth with scope checks, public documents, folder listings,
`If-Match`/`If-None-Match`, ranges, and the status codes of the spec.

an implementation provides

- `ResourceResolver` - map a request to a user and a storage path (`rstest.PathResolver` handles `/{user}/{path}`)
- `Authenticator` - validate bearer tokens
- `Authorizer` - `NewScopeCheckingAuthorizer` covers the spec rules
- `StorageProvider` / `StorageBackend` - the storage. backends must implement the storage model: folders exist only while they contain documents, every write changes the ETags of all ancestor folders, conditions are checked atomically. in-memory and filesystem backends are included

oauth itself is left to the implementer. to support pkce, advertise the token endpoint via `webfinger.UserStorageInfo.TokenEndpoint`.

## conformance tests

`pkg/rsserver/rstest` is a black-box HTTP test suite for any remoteStorage
server. `rstest.Run(t, target)` needs a storage root and a function that
issues tokens with given scopes. `rstest.NewHarness` wires a `StorageBackend`
into a test server, see `rstest_test.go`.

## client

`rsclient` does discovery and file operations. for auth, use pkce when the server advertises it (`GetPKCEEndpoints`), otherwise fall back to the implicit grant.

## examples

- `cmd/myrs` - toy server with static users, implicit and pkce oauth
- `cmd/rscli` - cli client (ls, get, put, ...), picks pkce when available
