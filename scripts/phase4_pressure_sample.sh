#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

API_BASE="${API_BASE:-http://127.0.0.1:18080}"
TOTAL_REQUESTS="${TOTAL_REQUESTS:-200}"
CONCURRENCY="${CONCURRENCY:-20}"
START_STACK="${START_STACK:-true}"
HTTP_TIMEOUT_SECONDS="${HTTP_TIMEOUT_SECONDS:-20}"
ENDPOINTS="${ENDPOINTS:-/healthz /metrics /clash /singbox}"
REPORT_DIR="${REPORT_DIR:-data/reports/phase4-pressure-$(date -u +%Y%m%d-%H%M%S)}"

if ! [[ "${TOTAL_REQUESTS}" =~ ^[0-9]+$ ]] || [[ "${TOTAL_REQUESTS}" -le 0 ]]; then
  echo "TOTAL_REQUESTS must be a positive integer"
  exit 1
fi
if ! [[ "${CONCURRENCY}" =~ ^[0-9]+$ ]] || [[ "${CONCURRENCY}" -le 0 ]]; then
  echo "CONCURRENCY must be a positive integer"
  exit 1
fi

mkdir -p "${REPORT_DIR}"

cleanup() {
  if [[ "${START_STACK}" == "true" ]]; then
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_healthz() {
  for _ in {1..60}; do
    if curl -fsS "${API_BASE}/healthz" >/dev/null; then
      return 0
    fi
    sleep 2
  done
  echo "health check timeout: ${API_BASE}/healthz"
  return 1
}

if [[ "${START_STACK}" == "true" ]]; then
  if [[ ! -f .env ]]; then
    cp .env.example .env
  fi
  echo "[phase4-pressure] start stack"
  docker compose up -d --build api web sublink >/dev/null
  wait_healthz
else
  echo "[phase4-pressure] use existing stack at ${API_BASE}"
  wait_healthz
fi

percentile() {
  local sorted_file="$1"
  local p="$2"
  awk -v p="${p}" '
    { values[NR] = $1 }
    END {
      if (NR == 0) {
        printf "0.0000"
        exit
      }
      idx = int((NR - 1) * p) + 1
      if (idx < 1) {
        idx = 1
      }
      if (idx > NR) {
        idx = NR
      }
      printf "%.4f", values[idx]
    }
  ' "${sorted_file}"
}

request_once() {
  local endpoint="$1"
  local status_and_time
  if ! status_and_time="$(
    curl -m "${HTTP_TIMEOUT_SECONDS}" -sS -o /dev/null \
      -w '%{http_code} %{time_total}' "${API_BASE}${endpoint}"
  )"; then
    status_and_time="000 ${HTTP_TIMEOUT_SECONDS}"
  fi
  printf '%s\n' "${status_and_time}"
}

endpoint_accept_regex() {
  local endpoint="$1"
  case "${endpoint}" in
    "/clash"|"/singbox")
      printf '^(200|304|502)$'
      ;;
    *)
      printf '^200$'
      ;;
  esac
}

summary_file="${REPORT_DIR}/summary.md"
generated_at="$(date -u +'%Y-%m-%d %H:%M:%S UTC')"
cat >"${summary_file}" <<EOF
# Phase 4 压测抽检报告（自动生成）

- 生成时间：${generated_at}
- API_BASE：\`${API_BASE}\`
- TOTAL_REQUESTS：\`${TOTAL_REQUESTS}\`
- CONCURRENCY：\`${CONCURRENCY}\`
- START_STACK：\`${START_STACK}\`
- HTTP_TIMEOUT_SECONDS：\`${HTTP_TIMEOUT_SECONDS}\`

| endpoint | total | ok | fail | success_rate | avg_s | p50_s | p95_s | p99_s | max_s |
|---|---|---|---|---|---|---|---|---|---|
EOF

for endpoint in ${ENDPOINTS}; do
  safe_name="$(printf '%s' "${endpoint}" | tr '/:' '__')"
  raw_file="${REPORT_DIR}/${safe_name}.raw.txt"
  latency_file="${REPORT_DIR}/${safe_name}.latency.txt"
  : >"${raw_file}"

  echo "[phase4-pressure] endpoint ${endpoint}"
  for ((i = 1; i <= TOTAL_REQUESTS; i++)); do
    request_once "${endpoint}" >>"${raw_file}" &
    if (( i % CONCURRENCY == 0 )); then
      wait
    fi
  done
  wait

  awk '{ print $2 }' "${raw_file}" | sort -n >"${latency_file}"
  total="$(wc -l <"${raw_file}" | tr -d ' ')"
  ok="$(awk -v re="$(endpoint_accept_regex "${endpoint}")" '$1 ~ re { c++ } END { print c + 0 }' "${raw_file}")"
  fail=$((total - ok))
  success_rate="$(awk -v ok="${ok}" -v total="${total}" 'BEGIN { if (total == 0) { printf "0.00" } else { printf "%.2f", (ok * 100) / total } }')"
  avg="$(awk '{ sum += $1 } END { if (NR == 0) { printf "0.0000" } else { printf "%.4f", sum / NR } }' "${latency_file}")"
  p50="$(percentile "${latency_file}" 0.50)"
  p95="$(percentile "${latency_file}" 0.95)"
  p99="$(percentile "${latency_file}" 0.99)"
  max="$(awk 'END { if (NR == 0) { printf "0.0000" } else { printf "%.4f", $1 } }' "${latency_file}")"

  printf '| `%s` | %s | %s | %s | %s%% | %s | %s | %s | %s | %s |\n' \
    "${endpoint}" "${total}" "${ok}" "${fail}" "${success_rate}" "${avg}" "${p50}" "${p95}" "${p99}" "${max}" \
    >>"${summary_file}"
done

echo "[phase4-pressure] done"
echo "[phase4-pressure] report: ${summary_file}"
echo "[phase4-pressure] raw data: ${REPORT_DIR}"
