#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
GRPC_WORKERS="${1:-${PII_GRPC_MAX_WORKERS:-6}}"

if ! [[ "${GRPC_WORKERS}" =~ ^[0-9]+$ ]] || [[ "${GRPC_WORKERS}" -lt 1 ]]; then
  echo "grpc_workers must be a positive integer" >&2
  exit 1
fi

cd "${PROJECT_ROOT}"
export PII_GRPC_MAX_WORKERS="${GRPC_WORKERS}"
export PII_HS_COMBINED_ENABLED="${PII_HS_COMBINED_ENABLED:-true}"
export PII_CONTEXT_EMBED_MAX_CHARS="${PII_CONTEXT_EMBED_MAX_CHARS:-256}"

echo "Starting gRPC direct mode with 1 replica, ${GRPC_WORKERS} worker(s)"
docker compose -f docker-compose.yml -f docker-compose.direct.yml --profile grpc up -d --build api-grpc
