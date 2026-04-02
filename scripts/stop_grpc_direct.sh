#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

echo "Stopping gRPC direct mode"
docker compose -f docker-compose.yml -f docker-compose.direct.yml --profile grpc stop api-grpc >/dev/null 2>&1 || true
docker compose -f docker-compose.yml -f docker-compose.direct.yml --profile grpc rm -f api-grpc >/dev/null 2>&1 || true
