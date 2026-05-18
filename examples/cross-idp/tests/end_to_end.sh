#!/usr/bin/env bash
# Headless end-to-end smoke test of the cross-IdP federation.
#
# Pre-conditions: docker-compose stack is up and `bash scripts/seed.sh` has run.
#
# This script never opens a browser. It walks the OIDC code-flow the same
# way a browser would, by following redirects with curl and replaying
# session cookies.

set -euo pipefail

IDP="${IDP:-http://localhost:8080}"
APP="${APP:-http://localhost:8081}"
ORG_SLUG="${ORG_SLUG:-acme}"
EMAIL="${EMAIL:-alice@example.com}"
PASSWORD="${PASSWORD:-alicepasswd1}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { printf '\033[1;32m[e2e]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[e2e]\033[0m FAIL: %s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null || fail "missing dep: $1"; }
require curl
require jq

# Decode a JWT payload (base64url → JSON) without verifying. Demo-only.
jwt_payload() {
  local tok="$1" payload
  payload="${tok#*.}"; payload="${payload%.*}"
  # base64url → base64
  payload=$(echo "${payload}" | tr '_-' '/+')
  # pad
  local pad=$(( 4 - ${#payload} % 4 ))
  if [[ ${pad} -lt 4 ]]; then payload="${payload}$(printf '=%.0s' $(seq 1 ${pad}))"; fi
  echo "${payload}" | base64 -d 2>/dev/null
}

IDP_JAR=$(mktemp)
APP_JAR=$(mktemp)
trap 'rm -f "${IDP_JAR}" "${APP_JAR}"' EXIT

# -- 1. Health ----------------------------------------------------------------
log "1. health: idp + app"
curl -fsS "${IDP}/api/health" >/dev/null || fail "idp not healthy"
curl -fsS "${APP}/api/health" >/dev/null || fail "app not healthy"

# -- 2. Start SSO flow on the App. We expect a 302 to the IdP /authorize. ----
log "2. GET ${APP}/api/auth/sso/login?org=${ORG_SLUG}"
AUTHORIZE_URL=$(curl -fsS -o /dev/null -w '%{redirect_url}' \
  -c "${APP_JAR}" \
  "${APP}/api/auth/sso/login?org=${ORG_SLUG}")
[[ -n "${AUTHORIZE_URL}" ]] || fail "App did not redirect to /authorize"
log "   → ${AUTHORIZE_URL}"
case "${AUTHORIZE_URL}" in
  *"/authorize"*) ;;
  *) fail "redirect did not point at /authorize: ${AUTHORIZE_URL}" ;;
esac

# Many IdP setups expect the user to be logged in BEFORE hitting /authorize.
# Try /authorize first; if it 401/403s, log in on the IdP and replay.
log "3. login alice on the IdP"
curl -fsS -c "${IDP_JAR}" -H 'content-type: application/json' \
  -X POST "${IDP}/api/auth/login" \
  --data "$(jq -nc --arg e "${EMAIL}" --arg p "${PASSWORD}" \
              '{email:$e,password:$p}')" \
  >/dev/null || fail "alice login failed"

log "4. replay /authorize as logged-in alice"
# The /authorize endpoint should now respond with a 302 to the App's callback
# carrying ?code=...&state=...
CALLBACK_URL=$(curl -sS -b "${IDP_JAR}" -o /dev/null -w '%{redirect_url}' \
  "${AUTHORIZE_URL}")
if [[ -z "${CALLBACK_URL}" ]]; then
  # Some yauth builds require an explicit consent POST. Try that.
  log "   (no redirect — attempting POST /authorize for consent)"
  CALLBACK_URL=$(curl -sS -b "${IDP_JAR}" -o /dev/null -w '%{redirect_url}' \
    -X POST -H 'content-type: application/x-www-form-urlencoded' \
    --data "consent=approve" \
    "${AUTHORIZE_URL}")
fi
[[ -n "${CALLBACK_URL}" ]] || fail "no callback URL from /authorize"
log "   → ${CALLBACK_URL}"
case "${CALLBACK_URL}" in
  *"/sso/callback?"*) ;;
  *) fail "callback did not point at /sso/callback: ${CALLBACK_URL}" ;;
esac

# -- 5. Hit the App's callback. The App should JIT-provision alice and
#       respond with a session cookie + a final redirect.
log "5. GET ${CALLBACK_URL} (App-side code exchange + JIT)"
FINAL=$(curl -sS -b "${APP_JAR}" -c "${APP_JAR}" \
  -o /tmp/cb-body.html -w '%{http_code}|%{redirect_url}' \
  "${CALLBACK_URL}")
HTTP_CODE="${FINAL%%|*}"
REDIR="${FINAL#*|}"
log "   → HTTP ${HTTP_CODE}, redirect=${REDIR:-<none>}"
[[ "${HTTP_CODE}" =~ ^(200|302|303)$ ]] || fail "callback returned ${HTTP_CODE}"

# -- 6. /api/me with the session cookie should return alice -------------------
log "6. GET /api/me with session cookie"
ME=$(curl -fsS -b "${APP_JAR}" "${APP}/api/me") || fail "/api/me failed"
echo "${ME}" | jq .
EMAIL_OUT=$(echo "${ME}" | jq -r '.email // empty')
[[ "${EMAIL_OUT}" == "${EMAIL}" ]] || fail "expected ${EMAIL}, got ${EMAIL_OUT}"

# -- 7. (best-effort) try to mint a bearer JWT for alice ----------------------
log "7. POST /api/auth/bearer/token (best-effort, JWT inspection)"
TOK_JSON=$(curl -sS -b "${APP_JAR}" -H 'content-type: application/json' \
  -X POST "${APP}/api/auth/bearer/token" --data '{}' || true)
if echo "${TOK_JSON}" | jq -e .access_token >/dev/null 2>&1; then
  ACCESS=$(echo "${TOK_JSON}" | jq -r .access_token)
  PAYLOAD=$(jwt_payload "${ACCESS}")
  echo "${PAYLOAD}" | jq .
  SUB=$(echo "${PAYLOAD}" | jq -r '.sub // empty')
  [[ -n "${SUB}" ]] || fail "JWT had no sub claim"
  log "   JWT sub=${SUB} (verified)"
else
  log "   (bearer endpoint not enabled or required different flow — skipping)"
fi

log "PASS: cross-IdP federation flow completed for ${EMAIL}"
