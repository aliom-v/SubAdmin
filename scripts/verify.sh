#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

require_command() {
  local cmd="$1"
  local install_hint="$2"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "[verify] missing command: ${cmd}"
    echo "[verify] hint: ${install_hint}"
    exit 1
  fi
}

echo "[verify] check shell scripts"
bash -n scripts/phase4_acceptance.sh
bash -n scripts/phase4_pressure_sample.sh
bash -n scripts/verify.sh

require_command go "install Go 1.22+ and ensure 'go' is in PATH"
require_command npm "install Node.js 20+ and ensure 'npm' is in PATH"

echo "[verify] backend tests"
(
  cd backend
  go test ./...
)

echo "[verify] frontend dependencies"
(
  cd web
  npm ci
  npm run build
)

echo "[verify] done"
