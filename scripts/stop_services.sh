#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-grpc}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ "${TARGET}" != "http" && "${TARGET}" != "grpc" && "${TARGET}" != "all" ]]; then
  echo "target must be http, grpc, or all" >&2
  exit 1
fi

cd "${PROJECT_ROOT}"

if [[ "${TARGET}" == "http" ]]; then
  echo "Stopping HTTP services"
  docker compose --profile http stop api >/dev/null 2>&1 || true
  docker compose --profile http rm -f api >/dev/null 2>&1 || true
  exit 0
fi

if [[ "${TARGET}" == "grpc" ]]; then
  echo "Stopping gRPC services"
  docker compose --profile grpc stop api-grpc-lb api-grpc >/dev/null 2>&1 || true
  docker compose --profile grpc rm -f api-grpc-lb api-grpc >/dev/null 2>&1 || true
  exit 0
fi

echo "Stopping all services"
docker compose --profile http --profile grpc down
