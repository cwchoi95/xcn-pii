from __future__ import annotations

import argparse
import os
import statistics
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import grpc


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.proto import pii_pb2, pii_pb2_grpc  # noqa: E402


DEFAULT_TEXT = """
홍길동 연락처는 010.1234.1258 이고 이메일은 test.user@example.com 입니다.
주민등록번호 예시는 900101-1234567 이고 사업자등록번호는 123-45-67890 입니다.
주소는 서울특별시 강남구 테헤란로 123-4 이며 IP 는 192.168.0.10 입니다.
""".strip()


@dataclass
class Result:
    ok: bool
    latency_ms: float
    status_code: str


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    rank = (len(values) - 1) * p
    lo = int(rank)
    hi = min(lo + 1, len(values) - 1)
    frac = rank - lo
    return values[lo] * (1.0 - frac) + values[hi] * frac


def build_channels(target: str, count: int, insecure: bool, timeout_sec: float) -> list[grpc.Channel]:
    options = [
        ("grpc.keepalive_time_ms", 30000),
        ("grpc.keepalive_timeout_ms", 10000),
        ("grpc.keepalive_permit_without_calls", 1),
        ("grpc.http2.max_pings_without_data", 0),
        ("grpc.max_receive_message_length", 64 * 1024 * 1024),
        ("grpc.max_send_message_length", 64 * 1024 * 1024),
        ("grpc.service_config", '{"loadBalancingConfig":[{"round_robin":{}}]}'),
    ]
    channels: list[grpc.Channel] = []
    for _ in range(max(1, count)):
        if insecure:
            channel = grpc.insecure_channel(target, options=options)
        else:
            channel = grpc.secure_channel(target, grpc.ssl_channel_credentials(), options=options)
        grpc.channel_ready_future(channel).result(timeout=timeout_sec)
        channels.append(channel)
    return channels


def load_text(args: argparse.Namespace) -> str:
    if args.payload_file:
        return Path(args.payload_file).read_text(encoding="utf-8")
    if args.payload_text:
        return args.payload_text
    return DEFAULT_TEXT


def run_once(
    stub: pii_pb2_grpc.PiiDetectorStub,
    text: str,
    max_results_per_type: int,
    ruleset: str,
    timeout_sec: float,
) -> Result:
    request = pii_pb2.DetectRequest(
        text=text,
        max_results_per_type=max_results_per_type,
        ruleset=ruleset,
    )
    t0 = time.perf_counter()
    try:
        response = stub.Detect(request, timeout=timeout_sec)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        if response.success and response.status == 200:
            return Result(ok=True, latency_ms=latency_ms, status_code="OK")
        return Result(ok=False, latency_ms=latency_ms, status_code=f"APP_{response.status}")
    except grpc.RpcError as exc:
        latency_ms = (time.perf_counter() - t0) * 1000.0
        return Result(ok=False, latency_ms=latency_ms, status_code=str(exc.code()))


def iter_round_robin(items: Iterable[pii_pb2_grpc.PiiDetectorStub]) -> Iterable[pii_pb2_grpc.PiiDetectorStub]:
    while True:
        for item in items:
            yield item


def benchmark(args: argparse.Namespace) -> int:
    text = load_text(args)
    channels = build_channels(
        target=args.target,
        count=args.channels,
        insecure=not args.tls,
        timeout_sec=args.connect_timeout_sec,
    )
    stubs = [pii_pb2_grpc.PiiDetectorStub(channel) for channel in channels]
    stub_iter = iter_round_robin(stubs)
    stub_lock = threading.Lock()

    def next_stub() -> pii_pb2_grpc.PiiDetectorStub:
        with stub_lock:
            return next(stub_iter)

    print(f"target={args.target}")
    print(f"channels={len(channels)} concurrency={args.concurrency} requests={args.requests} duration_sec={args.duration_sec}")
    print(f"ruleset={args.ruleset} max_results_per_type={args.max_results_per_type} payload_chars={len(text)}")

    if args.warmup_requests > 0:
        print(f"warmup_requests={args.warmup_requests}")
        for _ in range(args.warmup_requests):
            _ = run_once(next_stub(), text, args.max_results_per_type, args.ruleset, args.rpc_timeout_sec)

    latencies: list[float] = []
    failures = 0
    status_counts: dict[str, int] = {}
    submitted = 0
    completed = 0
    t0_all = time.perf_counter()
    deadline = (t0_all + args.duration_sec) if args.duration_sec > 0 else None

    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        inflight = set()

        def submit_one() -> None:
            nonlocal submitted
            future = executor.submit(
                run_once,
                next_stub(),
                text,
                args.max_results_per_type,
                args.ruleset,
                args.rpc_timeout_sec,
            )
            inflight.add(future)
            submitted += 1

        while len(inflight) < args.concurrency and (args.requests <= 0 or submitted < args.requests):
            if deadline is not None and time.perf_counter() >= deadline:
                break
            submit_one()

        while inflight:
            done, _ = wait(inflight, return_when=FIRST_COMPLETED)
            for future in done:
                inflight.remove(future)
                result = future.result()
                completed += 1
                latencies.append(result.latency_ms)
                status_counts[result.status_code] = status_counts.get(result.status_code, 0) + 1
                if not result.ok:
                    failures += 1

                should_submit = args.requests <= 0 or submitted < args.requests
                if deadline is not None and time.perf_counter() >= deadline:
                    should_submit = False
                if should_submit:
                    submit_one()

    total_sec = max(0.001, time.perf_counter() - t0_all)
    latencies.sort()
    success = completed - failures
    throughput = success / total_sec

    print("")
    print("summary")
    print(f"  total_sec={total_sec:.2f}")
    print(f"  submitted={submitted} completed={completed} success={success} failures={failures}")
    print(f"  throughput_rps={throughput:.2f}")
    if latencies:
        print(f"  latency_avg_ms={statistics.mean(latencies):.2f}")
        print(f"  latency_min_ms={latencies[0]:.2f}")
        print(f"  latency_p50_ms={percentile(latencies, 0.50):.2f}")
        print(f"  latency_p95_ms={percentile(latencies, 0.95):.2f}")
        print(f"  latency_p99_ms={percentile(latencies, 0.99):.2f}")
        print(f"  latency_max_ms={latencies[-1]:.2f}")

    print("")
    print("status_counts")
    for key in sorted(status_counts):
        print(f"  {key}={status_counts[key]}")

    for channel in channels:
        channel.close()

    return 0 if failures == 0 else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="gRPC benchmark client for xcn-pii-new")
    parser.add_argument("--target", default=os.getenv("PII_GRPC_TARGET", "127.0.0.1:50055"))
    parser.add_argument("--requests", type=int, default=100, help="Total request count. <=0 means unlimited until duration.")
    parser.add_argument("--duration-sec", type=float, default=0.0, help="Run duration limit. 0 means disabled.")
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--channels", type=int, default=4, help="Number of gRPC channels to open.")
    parser.add_argument("--warmup-requests", type=int, default=10)
    parser.add_argument("--connect-timeout-sec", type=float, default=10.0)
    parser.add_argument("--rpc-timeout-sec", type=float, default=30.0)
    parser.add_argument("--ruleset", default="default")
    parser.add_argument("--max-results-per-type", type=int, default=200)
    parser.add_argument("--payload-file")
    parser.add_argument("--payload-text")
    parser.add_argument("--tls", action="store_true")
    args = parser.parse_args()

    if args.concurrency < 1:
        parser.error("--concurrency must be >= 1")
    if args.channels < 1:
        parser.error("--channels must be >= 1")
    if args.requests == 0 and args.duration_sec <= 0:
        parser.error("Set --requests > 0 or --duration-sec > 0")
    return args


if __name__ == "__main__":
    raise SystemExit(benchmark(parse_args()))
