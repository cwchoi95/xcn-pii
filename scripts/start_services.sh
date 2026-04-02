#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-grpc}"
GRPC_SCALE="${2:-1}"
GRPC_WORKERS="${3:-${PII_GRPC_MAX_WORKERS:-6}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ "${TARGET}" != "http" && "${TARGET}" != "grpc" && "${TARGET}" != "all" ]]; then
  echo "target must be http, grpc, or all" >&2
  exit 1
fi

if ! [[ "${GRPC_SCALE}" =~ ^[0-9]+$ ]] || [[ "${GRPC_SCALE}" -lt 1 ]]; then
  echo "grpc_scale must be a positive integer" >&2
  exit 1
fi

if ! [[ "${GRPC_WORKERS}" =~ ^[0-9]+$ ]] || [[ "${GRPC_WORKERS}" -lt 1 ]]; then
  echo "grpc_workers must be a positive integer" >&2
  exit 1
fi

cd "${PROJECT_ROOT}"
export PII_GRPC_MAX_WORKERS="${GRPC_WORKERS}"
export PII_HS_COMBINED_ENABLED="${PII_HS_COMBINED_ENABLED:-true}"
export PII_CONTEXT_EMBED_MAX_CHARS="${PII_CONTEXT_EMBED_MAX_CHARS:-256}"

if [[ "${TARGET}" == "http" ]]; then
  echo "Starting HTTP services"
  docker compose --profile http up -d --build api
  exit 0
fi

if [[ "${TARGET}" == "grpc" ]]; then
  echo "Starting gRPC services with ${GRPC_SCALE} replica(s), ${GRPC_WORKERS} worker(s) per replica"
  docker compose --profile grpc up -d --build api-grpc api-grpc-lb
  docker compose --profile grpc up -d --scale "api-grpc=${GRPC_SCALE}" api-grpc
  exit 0
fi

echo "Starting HTTP and gRPC services with ${GRPC_SCALE} gRPC replica(s), ${GRPC_WORKERS} worker(s) per replica"
docker compose --profile http --profile grpc up -d --build api api-grpc api-grpc-lb
docker compose --profile grpc up -d --scale "api-grpc=${GRPC_SCALE}" api-grpc
