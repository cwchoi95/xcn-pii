# gRPC Interface

## Proto

- [`app/proto/pii.proto`](app/proto/pii.proto)

Service:

- `xcn.pii.v1.PiiDetector/Health`
- `xcn.pii.v1.PiiDetector/Detect`

## Run (local Python)

```bash
cd backend
pip install -r requirements.txt
python -m app.grpc_server
```

Default bind:

- host: `0.0.0.0`
- port: `50051`

Environment:

- `PII_GRPC_HOST` (default `0.0.0.0`)
- `PII_GRPC_PORT` (default `50051`)
- `PII_GRPC_MAX_WORKERS` (default `6`)
- `PII_GRPC_MAX_CONCURRENT_STREAMS` (default `1024`)
- `PII_GRPC_KEEPALIVE_TIME_MS` (default `30000`)
- `PII_GRPC_KEEPALIVE_TIMEOUT_MS` (default `10000`)
- `PII_GRPC_MAX_CONCURRENT_RPCS` (default `0`, unlimited)
- `PII_GRPC_SO_REUSEPORT` (default `true`)
- `GRPC_INSTALL_SEMANTIC` (default `true`)
- `PII_HS_COMBINED_ENABLED` (default `true`)
- `PII_CONTEXT_EMBED_MAX_CHARS` (default `256`)

## Run (Docker Compose)

Direct single-instance mode:

```bash
docker compose -f docker-compose.yml -f docker-compose.direct.yml --profile grpc up -d --build api-grpc
```

Host endpoint:

- `localhost:50051`

Recommended use:

- single instance
- no load balancer
- simplest production or local deployment

Scale-out LB mode:

```bash
docker compose --profile grpc up -d --build api-grpc api-grpc-lb
```

Host endpoint:

- `localhost:50055`

Scale-out example:

```bash
docker compose --profile grpc up -d --build api-grpc api-grpc-lb
docker compose --profile grpc up -d --scale api-grpc=3 api-grpc
```

Recommended starting point:

- `PII_GRPC_MAX_WORKERS=6`
- `PII_HS_COMBINED_ENABLED=true`
- `PII_CONTEXT_EMBED_MAX_CHARS=256`
- semantic context target keys: `SN, SSN, DN, PN, BN`
- direct mode: `api-grpc=1`
- LB mode: `api-grpc=3`

Notes:

- Direct mode endpoint: `localhost:50051`
- LB mode endpoint: `localhost:50055`
- External clients should connect to `localhost:50055` only when LB mode is enabled.
- Internal compose-network clients should use `api-grpc-lb:50051` only in LB mode.
- HTTP API is separated under the `http` profile, so it will not start unless explicitly requested.
- gRPC runtime no longer compiles proto at startup; generated stubs are checked into `app/proto/`.
- Semantic embedding packages are included in the default gRPC build.
- For current tuning, use direct mode for `1` replica and LB mode for `3` replicas.

## Current Baseline

Current production-oriented baseline:

- semantic model: `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`
- semantic context target keys: `SN, SSN, DN, PN, BN`
- excluded from semantic context: `MN, EML, IP, AN, SN_INVALID`
- `SN_INVALID` is not returned by default and is not generated unless `PII_INCLUDE_SN_INVALID=true`
- direct mode recommendation: `api-grpc=1`, `PII_GRPC_MAX_WORKERS=6`
- LB mode recommendation: `api-grpc=3`

Recent benchmark reference:

- environment: direct mode, `localhost:50051`
- payload: synthetic `2991` chars, `AN` included
- run: `100 requests / warmup 10 / concurrency 10 / channels 10`
- result after `SN_INVALID` cost reduction:
  - `42.38 rps`
  - `p50 232.86ms`
  - `p95 270.13ms`
  - `p99 280.15ms`

## Mode Scripts

Direct mode:

```bash
./scripts/start_grpc_direct.sh
./scripts/stop_grpc_direct.sh
```

LB mode:

```bash
./scripts/start_grpc_lb_3.sh
./scripts/stop_grpc_lb_3.sh
```

PowerShell:

```powershell
.\scripts\start_grpc_direct.ps1
.\scripts\stop_grpc_direct.ps1
.\scripts\start_grpc_lb_3.ps1
.\scripts\stop_grpc_lb_3.ps1
```

## Benchmark Client

From repository root:

```bash
py -3 ./scripts/grpc_benchmark.py --target 127.0.0.1:50055 --requests 500 --concurrency 20 --channels 8
```

Duration-based run:

```bash
py -3 ./scripts/grpc_benchmark.py --target 127.0.0.1:50055 --duration-sec 30 --requests -1 --concurrency 40 --channels 16
```

Custom payload file:

```bash
py -3 ./scripts/grpc_benchmark.py --target 127.0.0.1:50055 --payload-file ./sample.txt --requests 200
```

## Request/Response overview

`DetectRequest`:

- `text`: 검사할 원문
- `max_results_per_type`: 타입별 최대 결과 수
- `ruleset`: `default` 또는 `strict` 등

`DetectResponse`:

- `success`, `status`, `message`
- `data`:
  - `SN`, `SSN`, `DN`, `PN`, `MN`, `BN`, `AN`, `EML`, `IP`
  - 각 타입별 `*_cnt`
- `meta`:
  - `ruleset_name`, `ruleset_version`, `ruleset_updated_at`

Notes:

- empty result keys are omitted
- `SN_INVALID` and `*_CTX_REJECTED` are hidden from normal external responses
