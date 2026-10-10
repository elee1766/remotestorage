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

the remoteclient server implementation in rsserver is a partial implementation of the remotestorage server.

a fully fledged server must implement these interfaces

- `ResourceResolver` - map a request to a user and path
- `Authenticator` - validate bearer tokens
- `Authorizer` - check scopes (`NewScopeCheckingAuthorizer` covers the spec rules)
- `StorageProvider` / `StorageBackend` - the actual storage. in-memory and filesystem backends are included

oauth itself is left to the implementer. to support pkce, advertise the token endpoint via `webfinger.UserStorageInfo.TokenEndpoint`.

## client

`rsclient` does discovery and file operations. for auth, use pkce when the server advertises it (`GetPKCEEndpoints`), otherwise fall back to the implicit grant.

## examples

- `cmd/myrs` - toy server with static users, implicit and pkce oauth
- `cmd/rscli` - cli client (ls, get, put, ...), picks pkce when available
