#!/usr/bin/env bash
# Seed the cross-IdP federation example.
#
# Idempotent enough for the demo: registration calls 409 once users exist,
# which we treat as success.
#
# Stages:
#   1. IdP: register alice + bob, register Server B as OAuth client.
#   2. App: register admin, log in (capture session cookie),
#           create org "acme", create the SSO connection pointing at the IdP.
#
# Outputs:
#   .seed/idp-client.json        — { client_id, client_secret }
#   .seed/app-connection.json    — { org_id, connection_id }

set -euo pipefail

IDP="${IDP:-http://localhost:8080}"
APP="${APP:-http://localhost:8081}"
# Server B's backend reaches the IdP over the docker network (idp:8080) when
# run inside compose; from a host shell we fall back to localhost.
IDP_INTERNAL="${IDP_INTERNAL:-http://idp:8080}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEED_DIR="${ROOT}/.seed"
mkdir -p "${SEED_DIR}"

log() { printf '\033[1;36m[seed]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[seed]\033[0m %s\n' "$*" >&2; }

wait_for() {
  local url="$1" name="$2" tries=60
  log "waiting for ${name} at ${url} ..."
  until curl -fsS "${url}" >/dev/null 2>&1; do
    tries=$((tries - 1))
    if [[ ${tries} -le 0 ]]; then
      echo "ERROR: ${name} never became healthy" >&2
      exit 1
    fi
    sleep 1
  done
  log "${name} is up"
}

# -- 0. Health -----------------------------------------------------------------
wait_for "${IDP}/api/health" "idp"
wait_for "${APP}/api/health" "app"

# -- 1. IdP: users -------------------------------------------------------------
register_user() {
  local base="$1" email="$2" password="$3" name="$4"
  local resp
  resp=$(curl -sS -o /tmp/resp.json -w '%{http_code}' \
    -H 'content-type: application/json' \
    -X POST "${base}/api/auth/register" \
    --data "$(jq -nc --arg e "${email}" --arg p "${password}" --arg n "${name}" \
                 '{email:$e,password:$p,display_name:$n}')")
  case "${resp}" in
    200|201) log "  + registered ${email}" ;;
    409)     log "  = ${email} already exists (idempotent)" ;;
    *)       echo "ERROR: registering ${email} failed: HTTP ${resp}" >&2
             cat /tmp/resp.json >&2; exit 1 ;;
  esac
}

log "IdP: registering users"
register_user "${IDP}" "alice@example.com" "alicepasswd1" "Alice"
register_user "${IDP}" "bob@example.com"   "bobpasswd123" "Bob"

# -- 2. IdP: dynamic client registration for Server B -------------------------
if [[ -s "${SEED_DIR}/idp-client.json" ]]; then
  log "IdP: client already registered (re-using ${SEED_DIR}/idp-client.json)"
else
  log "IdP: registering Server B as an OAuth client"
  curl -sS -H 'content-type: application/json' \
    -X POST "${IDP}/api/auth/oauth/register" \
    --data "$(jq -nc '{
      client_name: "Server B (cross-idp example)",
      redirect_uris: ["http://localhost:8081/api/auth/sso/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post",
      scope: "openid email profile"
    }')" \
    | jq '{client_id, client_secret}' \
    > "${SEED_DIR}/idp-client.json"
  log "  + wrote ${SEED_DIR}/idp-client.json"
fi

CLIENT_ID=$(jq -r .client_id "${SEED_DIR}/idp-client.json")
CLIENT_SECRET=$(jq -r .client_secret "${SEED_DIR}/idp-client.json")
log "  client_id=${CLIENT_ID}"

# -- 3. App: admin user + login session ---------------------------------------
log "App: registering admin"
register_user "${APP}" "admin@example.com" "adminpasswd1" "Admin"

COOKIE_JAR="$(mktemp)"
log "App: logging in admin"
curl -sS -c "${COOKIE_JAR}" -H 'content-type: application/json' \
  -X POST "${APP}/api/auth/login" \
  --data '{"email":"admin@example.com","password":"adminpasswd1"}' \
  -o /tmp/resp.json
grep -q "^.*\s\(session\|yauth_session\)\s" "${COOKIE_JAR}" \
  || warn "  expected session cookie in jar; continuing anyway"

# -- 4. App: create org -------------------------------------------------------
log "App: creating org acme"
ORG_RESP=$(curl -sS -b "${COOKIE_JAR}" -H 'content-type: application/json' \
  -X POST "${APP}/api/auth/organizations" \
  --data '{"name":"Acme App","slug":"acme","display_name":"Acme App"}')
ORG_ID=$(echo "${ORG_RESP}" | jq -r '.id // .data.id // empty')
if [[ -z "${ORG_ID}" ]]; then
  # If org already exists the create call may 409. Try to list.
  ORG_ID=$(curl -sS -b "${COOKIE_JAR}" "${APP}/api/auth/organizations" \
    | jq -r '[.[] // (.data[]?)] | map(select(.slug=="acme")) | .[0].id // empty')
fi
if [[ -z "${ORG_ID}" ]]; then
  echo "ERROR: could not determine org id" >&2
  echo "  create response was:" >&2; echo "${ORG_RESP}" >&2; exit 1
fi
log "  org_id=${ORG_ID}"

# -- 5. App: create SSO connection -------------------------------------------
log "App: creating SSO connection on org ${ORG_ID}"
CONN_RESP=$(curl -sS -b "${COOKIE_JAR}" -H 'content-type: application/json' \
  -X POST "${APP}/api/auth/organizations/${ORG_ID}/sso/connections" \
  --data "$(jq -nc \
      --arg du "${IDP_INTERNAL}/.well-known/openid-configuration" \
      --arg ci "${CLIENT_ID}" --arg cs "${CLIENT_SECRET}" \
      '{
        name: "Server A IdP",
        kind: "oidc_client",
        oidc: {
          discovery_url: $du,
          client_id: $ci,
          client_secret: $cs,
          scopes: ["openid","email","profile"],
          claim_mappings: {
            email: "email",
            display_name: "name",
            external_id: "sub"
          }
        },
        jit_provisioning_enabled: true,
        default_role_on_jit: "member"
      }')")
CONN_ID=$(echo "${CONN_RESP}" | jq -r '.id // .data.id // empty')

if [[ -z "${CONN_ID}" ]]; then
  warn "  no connection id returned; assuming already exists. response:"
  warn "    ${CONN_RESP}"
  CONN_ID=$(curl -sS -b "${COOKIE_JAR}" \
    "${APP}/api/auth/organizations/${ORG_ID}/sso/connections" \
    | jq -r '[.[] // (.data[]?)] | .[0].id // empty')
fi
log "  connection_id=${CONN_ID}"

jq -n --arg oid "${ORG_ID}" --arg cid "${CONN_ID}" \
   '{org_id:$oid, connection_id:$cid}' \
   > "${SEED_DIR}/app-connection.json"
log "  + wrote ${SEED_DIR}/app-connection.json"

log "seed complete."
log "  open  http://localhost:5174  and click \"Sign in via Server A IdP\""
