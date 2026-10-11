#!/usr/bin/env bash
# Runs 0dataapp/spec-check against cmd/myrs with cache_control=plain.
# Needs go, git, node/npm, curl. Usage: scripts/spec-check.sh [mocha args...]
set -euo pipefail

SPEC_CHECK_REPO=${SPEC_CHECK_REPO:-https://github.com/0dataapp/spec-check}
SPEC_CHECK_REF=${SPEC_CHECK_REF:-e969675}
PORT=${PORT:-18765}

root=$(cd "$(dirname "$0")/.." && pwd)
work=${SPEC_CHECK_DIR:-${TMPDIR:-/tmp}/rs-spec-check}
host=127.0.0.1:$PORT
mkdir -p "$work"

if [ ! -d "$work/spec-check/.git" ]; then
	GIT_TERMINAL_PROMPT=0 git clone -q "$SPEC_CHECK_REPO" "$work/spec-check"
fi
git -C "$work/spec-check" checkout -q "$SPEC_CHECK_REF"
[ -d "$work/spec-check/node_modules" ] || (cd "$work/spec-check" && npm install --silent --no-audit --no-fund)

(cd "$root" && go build -o "$work/myrs" ./cmd/myrs)
cat >"$work/config.json" <<EOF
{
  "host": "$host",
  "cache_control": "plain",
  "users": [{"username": "alice", "password": "pw", "scopes": [{"module": "*", "access": "rw"}]}]
}
EOF

if curl -s -o /dev/null "http://$host/"; then
	echo "something is already listening on $host, set PORT" >&2
	exit 1
fi

"$work/myrs" "$work/config.json" >"$work/myrs.log" 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null' EXIT
for _ in $(seq 50); do
	curl -sf -o /dev/null "http://$host/.well-known/webfinger?resource=acct:alice@127.0.0.1" && break
	kill -0 $pid 2>/dev/null || { cat "$work/myrs.log" >&2; exit 1; }
	sleep 0.1
done

# Implicit grant login; the token comes back in the redirect fragment.
token() {
	curl -s -o /dev/null -w '%{redirect_url}' -X POST "http://$host/oauth/authorize" \
		--data-urlencode response_type=token \
		--data-urlencode client_id=http://localhost \
		--data-urlencode redirect_uri=http://localhost/ \
		--data-urlencode "scope=$1" \
		-d username=alice -d password=pw |
		sed -n 's/.*access_token=\([^&]*\).*/\1/p'
}

cat >"$work/spec-check/.env.myrs" <<EOF
SERVER_URL=http://$host
ACCOUNT_HANDLE=alice
TOKEN_READ_WRITE=$(token api-test-suite:rw)
TOKEN_READ_ONLY=$(token api-test-suite:r)
TOKEN_GLOBAL=$(token '*:rw')
EOF

cd "$work/spec-check"
ENV=myrs npx mocha "$@"
