# Simple remoteStorage Server

A minimal proof-of-concept remoteStorage server with DIY OAuth 2.0 implementation.

## Features

- Static user configuration (no database)
- In-memory storage
- Built-in OAuth 2.0 provider (implicit grant flow)
- WebFinger support
- Spec-compliant remoteStorage protocol

## Configuration

Create a `config.json` file (see `config.example.json`):

```json
{
  "host": "localhost:8080",
  "users": [
    {
      "username": "alice",
      "password": "password123",
      "scopes": [
        {
          "module": "contacts",
          "access": "rw"
        },
        {
          "module": "calendar",
          "access": "r"
        }
      ]
    }
  ]
}
```

### Configuration Fields

- **host**: Server address (e.g., `localhost:8080`)
- **users**: List of users with credentials and scopes
  - **username**: User identifier
  - **password**: Plain text password (PoC only!)
  - **scopes**: List of allowed module access
    - **module**: Module name (e.g., `contacts`, `calendar`, or `*` for all)
    - **access**: `r` (read-only) or `rw` (read-write)

## Running

```bash
# Copy example config
cp config.example.json config.json

# Edit config with your users
nano config.json

# Build and run
go build
./simple-rs
```

The server will start on http://localhost:8080

## Endpoints

- **WebFinger**: `/.well-known/webfinger?resource=acct:alice@localhost:8080`
- **OAuth Dialog**: `/oauth/authorize`
- **Storage**: `/{username}/{module}/{path}`
  - Example: `/alice/contacts/friends.json`
  - Public: `/alice/public/documents/readme.txt`

## Testing with remoteStorage.js

```javascript
// In your web app
remoteStorage.setApiKeys({
  // Not needed for this server
});

remoteStorage.connect('alice@localhost:8080');
```

When prompted, login with:
- Username: `alice`
- Password: `password123`

## URL Structure

```
/{username}/{module}/{path}           - Private storage
/{username}/public/{module}/{path}    - Public storage (read-only without auth)
```

## Security Notes

⚠️ **This is a PROOF OF CONCEPT**

- Passwords are stored in plain text
- No HTTPS support
- Tokens stored in memory (lost on restart)
- No rate limiting
- No session management

**DO NOT USE IN PRODUCTION!**

## Example Usage

```bash
# Start server
./simple-rs

# Get WebFinger (in another terminal)
curl "http://localhost:8080/.well-known/webfinger?resource=acct:alice@localhost:8080"

# OAuth flow (use browser):
# 1. Visit: http://localhost:8080/oauth/authorize?client_id=test&redirect_uri=http://localhost:3000/callback&scope=contacts:rw%20calendar:r
# 2. Login with alice/password123
# 3. Get redirected with access token in URL fragment

# Use token to access storage (replace TOKEN with your token)
curl -H "Authorization: Bearer TOKEN" http://localhost:8080/alice/contacts/

# Write to storage
curl -X PUT -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -H "If-None-Match: *" \
     -d '{"name": "Alice"}' \
     http://localhost:8080/alice/contacts/me.json

# Read from storage
curl -H "Authorization: Bearer TOKEN" \
     http://localhost:8080/alice/contacts/me.json

# Public read (no auth required for documents)
curl http://localhost:8080/alice/public/documents/readme.txt
```

## Code Size

Approximately 400 lines of Go code total:
- OAuth provider: ~200 lines
- Server implementation: ~130 lines
- Main server: ~130 lines

This is the minimal spec-compliant remoteStorage server!
