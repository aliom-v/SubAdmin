#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

API_BASE="http://127.0.0.1:18080"
TMP_DIR="$(mktemp -d /tmp/subadmin-phase4-XXXXXX)"
COMPOSE_OVERRIDE_FILE="${TMP_DIR}/docker-compose.acceptance.yml"
ENV_CREATED_FOR_ACCEPTANCE="false"

cat >"${COMPOSE_OVERRIDE_FILE}" <<YAML
services:
  api:
    volumes:
      - phase4_data:/data
volumes:
  phase4_data:
YAML

COMPOSE_ARGS=(-f docker-compose.yml -f "${COMPOSE_OVERRIDE_FILE}")

cleanup() {
  docker compose "${COMPOSE_ARGS[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  if [[ "${ENV_CREATED_FOR_ACCEPTANCE}" == "true" ]]; then
    rm -f .env
  fi
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

if [[ ! -f .env ]]; then
  cp .env.example .env
  ENV_CREATED_FOR_ACCEPTANCE="true"
fi

docker compose "${COMPOSE_ARGS[@]}" down -v --remove-orphans >/dev/null 2>&1 || true

echo "[phase4] start stack"
docker compose "${COMPOSE_ARGS[@]}" up -d --build api web sublink >/dev/null

echo "[phase4] wait /healthz"
for _ in {1..60}; do
  if curl -fsS "${API_BASE}/healthz" >"${TMP_DIR}/healthz.json"; then
    break
  fi
  sleep 2
done
grep -q '"status":"ok"' "${TMP_DIR}/healthz.json"

echo "[phase4] check /metrics"
curl -fsS "${API_BASE}/metrics" >"${TMP_DIR}/metrics.txt"
grep -q '^subadmin_http_requests_total' "${TMP_DIR}/metrics.txt"

echo "[phase4] login with default admin"
LOGIN_PAYLOAD='{"username":"admin","password":"admin123"}'
LOGIN_RESP="$(curl -fsS -X POST "${API_BASE}/api/login" -H 'Content-Type: application/json' -d "${LOGIN_PAYLOAD}")"
TOKEN="$(printf '%s' "${LOGIN_RESP}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
[[ -n "${TOKEN}" ]]
AUTH_HEADER="Authorization: Bearer ${TOKEN}"

curl -fsS "${API_BASE}/api/me" -H "${AUTH_HEADER}" >"${TMP_DIR}/me.json"
grep -q '"username":"admin"' "${TMP_DIR}/me.json"

echo "[phase4] create manual node for output regression"
NODE_PAYLOAD='{"name":"phase4-node","raw_uri":"ss://YWVzLTI1Ni1nY206cGFzc0BleGFtcGxlLmNvbTo0NDM=#phase4","enabled":true,"group_name":"phase4"}'
NODE_CODE="$(curl -sS -o "${TMP_DIR}/node.json" -w '%{http_code}' -X POST "${API_BASE}/api/nodes" -H "${AUTH_HEADER}" -H 'Content-Type: application/json' -d "${NODE_PAYLOAD}")"
[[ "${NODE_CODE}" == "201" ]]

echo "[phase4] strategy api regression"
curl -fsS "${API_BASE}/api/strategy" -H "${AUTH_HEADER}" >"${TMP_DIR}/strategy-get.json"
grep -q '"strategy_mode":"merge_dedupe"' "${TMP_DIR}/strategy-get.json"

STRATEGY_UPSTREAM_PAYLOAD='{"name":"phase4-strategy-upstream","url":"http://example.com/sub","enabled":true,"refresh_interval":60}'
STRATEGY_UPSTREAM_CODE="$(curl -sS -o "${TMP_DIR}/strategy-upstream.json" -w '%{http_code}' -X POST "${API_BASE}/api/upstreams" -H "${AUTH_HEADER}" -H 'Content-Type: application/json' -d "${STRATEGY_UPSTREAM_PAYLOAD}")"
[[ "${STRATEGY_UPSTREAM_CODE}" == "201" ]]
STRATEGY_UPSTREAM_ID="$(sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' "${TMP_DIR}/strategy-upstream.json")"
[[ -n "${STRATEGY_UPSTREAM_ID}" ]]

STRATEGY_RAW_PAYLOAD='{"content":"trojan://password@example.net:443#phase4"}'
STRATEGY_RAW_CODE="$(curl -sS -o "${TMP_DIR}/strategy-raw.json" -w '%{http_code}' -X PUT "${API_BASE}/api/upstreams/${STRATEGY_UPSTREAM_ID}/raw" -H "${AUTH_HEADER}" -H 'Content-Type: application/json' -d "${STRATEGY_RAW_PAYLOAD}")"
[[ "${STRATEGY_RAW_CODE}" == "200" ]]

printf -v STRATEGY_PAYLOAD '{"strategy_mode":"priority_override","manual_nodes_priority":0,"rename_suffix_format":"[{source}]","upstreams":[{"id":%s,"priority":10}]}' "${STRATEGY_UPSTREAM_ID}"

STRATEGY_PREVIEW_CODE="$(curl -sS -o "${TMP_DIR}/strategy-preview.json" -w '%{http_code}' -X POST "${API_BASE}/api/strategy/preview" -H "${AUTH_HEADER}" -H 'Content-Type: application/json' -d "${STRATEGY_PAYLOAD}")"
[[ "${STRATEGY_PREVIEW_CODE}" == "200" ]]
grep -q '"strategy_mode":"priority_override"' "${TMP_DIR}/strategy-preview.json"
grep -q '"output_nodes":1' "${TMP_DIR}/strategy-preview.json"
grep -q '"dropped_nodes":1' "${TMP_DIR}/strategy-preview.json"
grep -q '"winner_source":"manual"' "${TMP_DIR}/strategy-preview.json"

STRATEGY_PUT_CODE="$(curl -sS -o "${TMP_DIR}/strategy-put.json" -w '%{http_code}' -X PUT "${API_BASE}/api/strategy" -H "${AUTH_HEADER}" -H 'Content-Type: application/json' -d "${STRATEGY_PAYLOAD}")"
[[ "${STRATEGY_PUT_CODE}" == "200" ]]
grep -q '"strategy_mode":"priority_override"' "${TMP_DIR}/strategy-put.json"

curl -fsS "${API_BASE}/api/strategy" -H "${AUTH_HEADER}" >"${TMP_DIR}/strategy-after-put.json"
grep -q '"strategy_mode":"priority_override"' "${TMP_DIR}/strategy-after-put.json"

echo "[phase4] output endpoint + etag drill"
CLASH_HEADERS="${TMP_DIR}/clash.headers"
CLASH_CODE="$(curl -sS -D "${CLASH_HEADERS}" -o "${TMP_DIR}/clash.body" -w '%{http_code}' "${API_BASE}/clash")"
if [[ "${CLASH_CODE}" == "200" ]]; then
  ETAG="$(awk 'tolower($1)=="etag:" {print $2}' "${CLASH_HEADERS}" | tr -d '\r' | tail -n1)"
  [[ -n "${ETAG}" ]]
  CLASH_304="$(curl -sS -o /dev/null -w '%{http_code}' "${API_BASE}/clash" -H "If-None-Match: ${ETAG}")"
  [[ "${CLASH_304}" == "304" ]]
else
  [[ "${CLASH_CODE}" == "502" ]]
fi

SINGBOX_CODE="$(curl -sS -o "${TMP_DIR}/singbox.body" -w '%{http_code}' "${API_BASE}/singbox")"
[[ "${SINGBOX_CODE}" == "200" || "${SINGBOX_CODE}" == "502" ]]

echo "[phase4] backup export regression"
curl -fsS "${API_BASE}/api/backup/export" -H "${AUTH_HEADER}" >"${TMP_DIR}/backup.json"
grep -q '"upstreams"' "${TMP_DIR}/backup.json"
grep -q '"manual_nodes"' "${TMP_DIR}/backup.json"

echo "[phase4] login lock drill"
BAD_CODE=""
for _ in {1..10}; do
  BAD_CODE="$(curl -sS -o "${TMP_DIR}/bad-login.json" -w '%{http_code}' -X POST "${API_BASE}/api/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"wrong-pass"}')"
  if [[ "${BAD_CODE}" == "429" ]]; then
    break
  fi
done
[[ "${BAD_CODE}" == "429" ]]

echo "[phase4] upstream retry drill"
UPSTREAM_PAYLOAD='{"name":"phase4-bad-upstream","url":"http://10.255.255.1:81/sub","enabled":true,"refresh_interval":60}'
UPSTREAM_CODE="$(curl -sS -o "${TMP_DIR}/upstream.json" -w '%{http_code}' -X POST "${API_BASE}/api/upstreams" -H "${AUTH_HEADER}" -H 'Content-Type: application/json' -d "${UPSTREAM_PAYLOAD}")"
[[ "${UPSTREAM_CODE}" == "201" ]]

SYNC_CODE="$(curl -sS -o "${TMP_DIR}/sync.json" -w '%{http_code}' -X POST "${API_BASE}/api/sync" -H "${AUTH_HEADER}" || true)"
[[ "${SYNC_CODE}" == "200" || "${SYNC_CODE}" == "502" ]]

curl -fsS "${API_BASE}/api/logs/system?limit=200" -H "${AUTH_HEADER}" >"${TMP_DIR}/system-logs.json"
grep -q 'request_id' "${TMP_DIR}/system-logs.json"
grep -q 'sync_upstream_retry' "${TMP_DIR}/system-logs.json"
grep -q 'update_strategy' "${TMP_DIR}/system-logs.json"
grep -q 'preview_strategy' "${TMP_DIR}/system-logs.json"

curl -fsS "${API_BASE}/api/logs/sync?limit=200" -H "${AUTH_HEADER}" >"${TMP_DIR}/sync-logs.json"
grep -q '"status":"fail"' "${TMP_DIR}/sync-logs.json"

echo "[phase4] all checks passed"
