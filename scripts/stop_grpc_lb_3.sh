#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

echo "Stopping gRPC LB mode"
docker compose --profile grpc stop api-grpc-lb api-grpc >/dev/null 2>&1 || true
docker compose --profile grpc rm -f api-grpc-lb api-grpc >/dev/null 2>&1 || true
