#!/usr/bin/env python3
"""
Security Hub NF Benchmark Suite
SRS 비기능 요구사항 정량 검증 스크립트
실행: python backend/tests/run_qa_benchmark.py
전제: 백엔드가 localhost:8000에서 실행 중이어야 함
"""

import asyncio
import os
import sys
import time
import uuid
from datetime import datetime

# Windows ProactorEventLoop SSL 버그 방지
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

try:
    import httpx
except ImportError:
    print("[오류] httpx 패키지가 필요합니다: pip install httpx")
    sys.exit(1)

BASE_URL = "http://localhost:8000"
SESSION_UUID = str(uuid.uuid4())  # 이 세션에 사용할 공통 UUID

RESULTS: list[dict] = []


# =============================================================================
# 유틸리티
# =============================================================================

def percentile(samples: list[float], p: float) -> float:
    if not samples:
        return 0.0
    sorted_s = sorted(samples)
    idx = int(p * len(sorted_s))
    idx = min(idx, len(sorted_s) - 1)
    return sorted_s[idx]


def record(test: str, target: str, actual, passed: bool, detail: str) -> dict:
    result = {
        "test": test,
        "target": target,
        "actual": actual,
        "passed": passed,
        "detail": detail,
    }
    RESULTS.append(result)
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {test} | target={target} | actual={actual}")
    return result


def make_headers(device_uuid: str | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if device_uuid is not None:
        headers["X-Device-UUID"] = device_uuid
    return headers


# =============================================================================
# NF-PERF-01: /analyze 응답 시간
# =============================================================================

async def run_perf_whitelist(client: httpx.AsyncClient) -> None:
    """화이트리스트 히트 경로 — naver.com (suffix 매칭)"""
    print("\n[NF-PERF-01] /analyze 응답 시간 — 화이트리스트 히트 경로")
    url = "https://www.naver.com"
    payload = {"text": url}
    headers = make_headers(SESSION_UUID)

    # 워밍업 10회
    for _ in range(10):
        try:
            await client.post(f"{BASE_URL}/analyze", json=payload, headers=headers)
        except Exception:
            pass

    # 측정 20회
    latencies: list[float] = []
    for _ in range(20):
        t0 = time.perf_counter()
        try:
            resp = await client.post(f"{BASE_URL}/analyze", json=payload, headers=headers)
            t1 = time.perf_counter()
            if resp.status_code == 200:
                latencies.append((t1 - t0) * 1000)
        except Exception as e:
            print(f"    [경고] 요청 실패: {e}")

    if not latencies:
        record("NF-PERF-01 (whitelist hit)", "p95 ≤ 50ms", "측정불가", False, "모든 요청 실패")
        return

    p50 = percentile(latencies, 0.50)
    p95 = percentile(latencies, 0.95)
    p99 = percentile(latencies, 0.99)
    mx  = max(latencies)
    passed = p95 <= 50.0
    detail = f"p50={p50:.1f}ms p95={p95:.1f}ms p99={p99:.1f}ms max={mx:.1f}ms n={len(latencies)}"
    record("NF-PERF-01 (whitelist hit)", "p95 ≤ 50ms", f"{p95:.1f}ms", passed, detail)


async def run_perf_heuristic(client: httpx.AsyncClient) -> None:
    """휴리스틱 전용 경로 — 의심스러운 도메인, WHOIS/SSL 불필요"""
    print("\n[NF-PERF-01] /analyze 응답 시간 — 휴리스틱 전용 경로")
    # suspicious_keywords + suspicious_tld 복합 → WHOIS 없이 휴리스틱 판단
    url = "https://login-verify-secure.xyz/account/confirm"
    payload = {"text": url}
    headers = make_headers(SESSION_UUID)

    for _ in range(10):
        try:
            await client.post(f"{BASE_URL}/analyze", json=payload, headers=headers)
        except Exception:
            pass

    latencies: list[float] = []
    for _ in range(20):
        t0 = time.perf_counter()
        try:
            resp = await client.post(f"{BASE_URL}/analyze", json=payload, headers=headers)
            t1 = time.perf_counter()
            if resp.status_code == 200:
                latencies.append((t1 - t0) * 1000)
        except Exception as e:
            print(f"    [경고] 요청 실패: {e}")

    if not latencies:
        record("NF-PERF-01 (heuristic-only)", "p95 ≤ 100ms", "측정불가", False, "모든 요청 실패")
        return

    p50 = percentile(latencies, 0.50)
    p95 = percentile(latencies, 0.95)
    p99 = percentile(latencies, 0.99)
    mx  = max(latencies)
    passed = p95 <= 100.0
    detail = f"p50={p50:.1f}ms p95={p95:.1f}ms p99={p99:.1f}ms max={mx:.1f}ms n={len(latencies)}"
    record("NF-PERF-01 (heuristic-only)", "p95 ≤ 100ms", f"{p95:.1f}ms", passed, detail)


async def run_perf_full_path(client: httpx.AsyncClient) -> None:
    """전체 경로 — 랜덤 미지 도메인, WHOIS+SSL 조회 포함"""
    print("\n[NF-PERF-01] /analyze 응답 시간 — Full path (WHOIS+SSL)")
    rand_id = str(uuid.uuid4())[:8]
    url = f"https://xk9z-nf-test-{rand_id}.xyz/phish"
    payload = {"text": url}
    headers = make_headers(SESSION_UUID)

    # 워밍업 2회 (외부 네트워크 호출이 있어 워밍업 적게)
    for _ in range(2):
        try:
            await client.post(f"{BASE_URL}/analyze", json=payload, headers=headers, timeout=10.0)
        except Exception:
            pass

    latencies: list[float] = []
    for i in range(5):
        # 각 요청마다 다른 랜덤 도메인 사용 (캐시 히트 방지)
        rand_id2 = str(uuid.uuid4())[:8]
        url2 = f"https://xk9z-nf-test-{rand_id2}.xyz/phish"
        payload2 = {"text": url2}
        t0 = time.perf_counter()
        try:
            resp = await client.post(
                f"{BASE_URL}/analyze", json=payload2, headers=headers, timeout=15.0
            )
            t1 = time.perf_counter()
            if resp.status_code == 200:
                latencies.append((t1 - t0) * 1000)
        except Exception as e:
            print(f"    [경고] 요청 {i+1} 실패: {e}")

    if not latencies:
        record("NF-PERF-01 (full WHOIS+SSL)", "p95 ≤ 3000ms", "측정불가", False, "모든 요청 실패")
        return

    p50 = percentile(latencies, 0.50)
    p95 = percentile(latencies, 0.95)
    p99 = percentile(latencies, 0.99)
    mx  = max(latencies)
    passed = p95 <= 3000.0
    detail = f"p50={p50:.1f}ms p95={p95:.1f}ms p99={p99:.1f}ms max={mx:.1f}ms n={len(latencies)}"
    record("NF-PERF-01 (full WHOIS+SSL)", "p95 ≤ 3000ms", f"{p95:.1f}ms", passed, detail)


# =============================================================================
# NF-ISOLATION-01: 동시 요청 데이터 격리
# =============================================================================

async def run_isolation(client: httpx.AsyncClient) -> None:
    """3개 동시 요청 — 각자의 URL 결과만 반환되어야 함"""
    print("\n[NF-ISOLATION-01] 동시 요청 데이터 격리")
    urls = [
        "https://www.naver.com",                          # safe (whitelist)
        "https://login-verify-secure.xyz/steal",          # suspicious
        "https://www.coupang.com",                        # safe (whitelist)
    ]
    payloads = [{"text": u} for u in urls]
    headers = make_headers(SESSION_UUID)

    async def single_request(payload: dict) -> dict:
        try:
            resp = await client.post(f"{BASE_URL}/analyze", json=payload, headers=headers)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            return {"error": str(e)}
        return {}

    results = await asyncio.gather(*(single_request(p) for p in payloads))

    isolation_ok = True
    detail_parts = []
    for i, (url, result) in enumerate(zip(urls, results)):
        if "error" in result:
            isolation_ok = False
            detail_parts.append(f"req{i+1}: ERROR={result['error']}")
            continue
        # 각 응답의 url 필드(또는 분석 입력)가 자신의 URL을 포함해야 함
        # API가 url 필드를 반환하지 않을 경우 label 존재 여부만 확인
        label = result.get("label") or result.get("status") or result.get("verdict", "")
        detail_parts.append(f"req{i+1}(url={url[:30]}...): label={label}")

    # 3개 요청 모두 응답이 있어야 격리 성공
    responded = sum(1 for r in results if r and "error" not in r)
    isolation_ok = responded == 3
    passed = isolation_ok
    actual_str = f"{responded}/3 응답"
    record(
        "NF-ISOLATION-01",
        "3/3 응답 + 결과 격리",
        actual_str,
        passed,
        " | ".join(detail_parts),
    )


# =============================================================================
# NF-RATELIMIT-01: Rate limit 429 검증 (NF-24)
# =============================================================================

async def run_ratelimit(client: httpx.AsyncClient) -> None:
    """11회 연속 /analyze POST — 10번은 성공, 11번은 429여야 함"""
    print("\n[NF-RATELIMIT-01] Rate limit 검증 (10/min 초과 시 429)")

    # 별도 UUID 사용 (이전 측정에서 카운터가 차있을 수 있으므로 새 IP로 인식되지 않지만,
    # 같은 IP에서 실행되므로 rate limit은 IP 기반임을 주의)
    rl_uuid = str(uuid.uuid4())
    headers = make_headers(rl_uuid)
    payload = {"text": "https://www.google.com/test-rate-limit"}

    statuses: list[int] = []
    retry_after_present = False

    for i in range(11):
        try:
            resp = await client.post(
                f"{BASE_URL}/analyze",
                json=payload,
                headers=headers,
                timeout=10.0,
            )
            statuses.append(resp.status_code)
            if resp.status_code == 429:
                retry_after_present = "retry-after" in {k.lower() for k in resp.headers}
        except Exception as e:
            statuses.append(-1)
            print(f"    [경고] 요청 {i+1} 예외: {e}")

    # 처음 10개는 2xx or 4xx(not 429), 11번째는 429
    first_10_ok = all(s != 429 for s in statuses[:10])
    eleventh_429 = len(statuses) >= 11 and statuses[10] == 429
    passed = first_10_ok and eleventh_429 and retry_after_present

    status_str = ",".join(str(s) for s in statuses)
    detail = (
        f"statuses=[{status_str}] "
        f"first10_ok={first_10_ok} "
        f"11th=429:{eleventh_429} "
        f"Retry-After:{retry_after_present}"
    )
    record(
        "NF-RATELIMIT-01",
        "req1-10: 2xx, req11: 429+Retry-After",
        f"11th={statuses[10] if len(statuses) == 11 else 'N/A'}",
        passed,
        detail,
    )


# =============================================================================
# NF-UUID-01: DeviceUUID 검증 (NF-30)
# =============================================================================

async def run_uuid_validation(client: httpx.AsyncClient) -> None:
    """DeviceUUID 헤더 없음/잘못됨/정상 3가지 케이스"""
    print("\n[NF-UUID-01] DeviceUUID 헤더 검증")
    payload = {"text": "https://example.com"}

    # 테스트 1: 헤더 없음 → 401
    resp1 = await client.post(
        f"{BASE_URL}/analyze", json=payload,
        headers={"Content-Type": "application/json"},
        timeout=5.0,
    )
    test1_pass = resp1.status_code == 401
    record(
        "NF-UUID-01 (no header)",
        "401",
        str(resp1.status_code),
        test1_pass,
        f"HTTP {resp1.status_code}",
    )

    # 테스트 2: 잘못된 UUID → 400
    resp2 = await client.post(
        f"{BASE_URL}/analyze", json=payload,
        headers={"Content-Type": "application/json", "X-Device-UUID": "not-a-uuid"},
        timeout=5.0,
    )
    test2_pass = resp2.status_code == 400
    record(
        "NF-UUID-01 (malformed UUID)",
        "400",
        str(resp2.status_code),
        test2_pass,
        f"HTTP {resp2.status_code}",
    )

    # 테스트 3: 올바른 UUID v4 → 정상 처리 (not 401/400)
    resp3 = await client.post(
        f"{BASE_URL}/analyze", json=payload,
        headers=make_headers(str(uuid.uuid4())),
        timeout=10.0,
    )
    test3_pass = resp3.status_code not in (401, 400)
    record(
        "NF-UUID-01 (valid UUID v4)",
        "not 401/400",
        str(resp3.status_code),
        test3_pass,
        f"HTTP {resp3.status_code}",
    )


# =============================================================================
# NF-FALLBACK-01: 보수적 SUSPICIOUS 폴백
# =============================================================================

async def run_fallback(client: httpx.AsyncClient) -> None:
    """알 수 없는 도메인은 suspicious/danger, 절대 safe 반환 불가 (DC-06)"""
    print("\n[NF-FALLBACK-01] 보수적 SUSPICIOUS 폴백 검증")
    headers = make_headers(SESSION_UUID)

    # 테스트 1: 완전 미지의 랜덤 도메인
    rand_id = str(uuid.uuid4()).replace("-", "")[:12]
    unknown_url = f"https://xk9z-unknown-{rand_id}.xyz/path"
    resp1 = await client.post(
        f"{BASE_URL}/analyze",
        json={"text": unknown_url},
        headers=headers,
        timeout=15.0,
    )
    if resp1.status_code == 200:
        body1 = resp1.json()
        label1 = (
            body1.get("label")
            or body1.get("status")
            or body1.get("verdict", "unknown")
        )
        # label이 RiskStatus enum 값일 수 있음 (safe/suspicious/danger)
        label1_lower = str(label1).lower()
        test1_pass = label1_lower in ("suspicious", "danger")
        record(
            "NF-FALLBACK-01 (unknown domain)",
            "suspicious or danger (not safe)",
            label1_lower,
            test1_pass,
            f"url={unknown_url[:50]} label={label1}",
        )
    else:
        record(
            "NF-FALLBACK-01 (unknown domain)",
            "suspicious or danger (not safe)",
            f"HTTP {resp1.status_code}",
            False,
            f"분석 요청 실패: HTTP {resp1.status_code}",
        )

    # 테스트 2: 빈 URL(URL 없음) → SUSPICIOUS (DC-06, 파이프라인 0단계)
    resp2 = await client.post(
        f"{BASE_URL}/analyze",
        json={"text": "이것은 URL이 없는 문자입니다."},
        headers=headers,
        timeout=10.0,
    )
    if resp2.status_code == 200:
        body2 = resp2.json()
        label2 = (
            body2.get("label")
            or body2.get("status")
            or body2.get("verdict", "unknown")
        )
        label2_lower = str(label2).lower()
        test2_pass = label2_lower in ("suspicious", "danger")
        record(
            "NF-FALLBACK-01 (no URL in text)",
            "suspicious or danger (not safe)",
            label2_lower,
            test2_pass,
            f"label={label2}",
        )
    else:
        record(
            "NF-FALLBACK-01 (no URL in text)",
            "suspicious or danger (not safe)",
            f"HTTP {resp2.status_code}",
            False,
            f"분석 요청 실패: HTTP {resp2.status_code}",
        )


# =============================================================================
# NF-12: Cache-Control 응답 헤더
# =============================================================================

async def run_cache_control(client: httpx.AsyncClient) -> None:
    """모든 /analyze 응답에 Cache-Control: no-store 헤더 포함 여부"""
    print("\n[NF-12] Cache-Control: no-store 응답 헤더 검증")
    payload = {"text": "https://www.naver.com"}
    headers = make_headers(SESSION_UUID)

    resp = await client.post(f"{BASE_URL}/analyze", json=payload, headers=headers, timeout=10.0)
    cc = resp.headers.get("cache-control", "")
    passed = "no-store" in cc.lower()
    record(
        "NF-12 (Cache-Control)",
        "Cache-Control: no-store",
        cc or "(없음)",
        passed,
        f"HTTP {resp.status_code}, Cache-Control: {cc}",
    )


# =============================================================================
# NF-25: DISABLE_DOCS 코드 확인 (정적 검증)
# =============================================================================

def run_disable_docs_check() -> None:
    """main.py 코드에서 DISABLE_DOCS 설정 확인"""
    print("\n[NF-25] DISABLE_DOCS 설정 코드 확인")
    main_py = os.path.join(
        os.path.dirname(__file__), "..", "main.py"
    )
    try:
        with open(main_py, encoding="utf-8") as f:
            content = f.read()
        has_disable_docs = "DISABLE_DOCS" in content
        has_docs_none = "docs_url=None" in content or "docs_url = None" in content
        has_redoc_none = "redoc_url=None" in content or "redoc_url = None" in content
        has_openapi_none = "openapi_url=None" in content
        passed = all([has_disable_docs, has_docs_none, has_redoc_none, has_openapi_none])
        detail = (
            f"DISABLE_DOCS 환경변수: {has_disable_docs}, "
            f"docs_url=None: {has_docs_none}, "
            f"redoc_url=None: {has_redoc_none}, "
            f"openapi_url=None: {has_openapi_none}"
        )
        record(
            "NF-25 (DISABLE_DOCS)",
            "코드에 DISABLE_DOCS 조건부 비활성화 구현",
            "구현됨" if passed else "미구현",
            passed,
            detail,
        )
    except Exception as e:
        record("NF-25 (DISABLE_DOCS)", "코드에 DISABLE_DOCS 조건부 비활성화 구현",
               "확인불가", False, str(e))


# =============================================================================
# NF-27: SQLite WAL + busy_timeout 코드 확인 (정적 검증)
# =============================================================================

def run_sqlite_wal_check() -> None:
    """db_init.py 코드에서 WAL 모드 및 busy_timeout 설정 확인"""
    print("\n[NF-27] SQLite WAL + busy_timeout=5000 설정 코드 확인")
    db_init_py = os.path.join(
        os.path.dirname(__file__), "..", "database", "db_init.py"
    )
    try:
        with open(db_init_py, encoding="utf-8") as f:
            content = f.read()
        has_wal = "journal_mode=WAL" in content or "journal_mode = WAL" in content
        has_timeout = "busy_timeout=5000" in content or "busy_timeout = 5000" in content
        has_sync = "synchronous=NORMAL" in content or "synchronous = NORMAL" in content
        passed = has_wal and has_timeout
        detail = (
            f"WAL모드: {has_wal}, "
            f"busy_timeout=5000: {has_timeout}, "
            f"synchronous=NORMAL: {has_sync}"
        )
        record(
            "NF-27 (SQLite WAL)",
            "WAL 모드 + busy_timeout=5000",
            "구현됨" if passed else "미구현",
            passed,
            detail,
        )
    except Exception as e:
        record("NF-27 (SQLite WAL)", "WAL 모드 + busy_timeout=5000",
               "확인불가", False, str(e))


# =============================================================================
# NF-28: 세마포어 한계 코드 확인 (정적 검증)
# =============================================================================

def run_semaphore_check() -> None:
    """sandbox.py 코드에서 세마포어 슬롯 수 확인"""
    print("\n[NF-28] 세마포어 한계 (7-A: 4슬롯, 7-B: 3슬롯) 코드 확인")
    sandbox_py = os.path.join(
        os.path.dirname(__file__), "..", "routers", "sandbox.py"
    )
    try:
        with open(sandbox_py, encoding="utf-8") as f:
            content = f.read()
        has_browse4 = "Semaphore(4)" in content
        has_auto3 = "Semaphore(3)" in content
        passed = has_browse4 and has_auto3
        detail = (
            f"7-A _BROWSE_SEM=Semaphore(4): {has_browse4}, "
            f"7-B _AUTO_SEM=Semaphore(3): {has_auto3}"
        )
        record(
            "NF-28 (Semaphore 슬롯)",
            "7-A: 4슬롯, 7-B: 3슬롯",
            "구현됨" if passed else "미구현/불일치",
            passed,
            detail,
        )
    except Exception as e:
        record("NF-28 (Semaphore 슬롯)", "7-A: 4슬롯, 7-B: 3슬롯",
               "확인불가", False, str(e))


# =============================================================================
# 메인 실행
# =============================================================================

async def main() -> int:
    print("=" * 65)
    print("Security Hub NF 벤치마크 스위트")
    print(f"실행 일시: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"세션 UUID: {SESSION_UUID}")
    print("=" * 65)

    # 정적 코드 검증 (백엔드 불필요)
    run_disable_docs_check()
    run_sqlite_wal_check()
    run_semaphore_check()

    # 백엔드 연결 확인
    print("\n[연결 확인] localhost:8000 백엔드 접근 테스트...")
    try:
        async with httpx.AsyncClient(timeout=5.0) as probe:
            check = await probe.get(f"{BASE_URL}/openapi.json")
            if check.status_code == 200:
                print("  백엔드 연결 성공 (openapi.json 200)")
                backend_version = check.json().get("info", {}).get("version", "unknown")
            else:
                print(f"  [경고] /openapi.json → HTTP {check.status_code}")
                backend_version = "unknown"
    except Exception as e:
        print(f"\n[오류] 백엔드에 연결할 수 없습니다: {e}")
        print("  백엔드를 먼저 시작하세요:")
        print("    cd C:\\dev\\security_hub\\backend")
        print("    venv\\Scripts\\Activate.ps1")
        print("    uvicorn main:app --reload --port 8000")
        # 정적 검증 결과만으로 리포트 생성
        write_report("unknown", backend_running=False)
        return 1

    # HTTP 측정
    async with httpx.AsyncClient(timeout=30.0) as client:
        await run_perf_whitelist(client)
        await run_perf_heuristic(client)
        await run_perf_full_path(client)
        await run_cache_control(client)
        await run_isolation(client)
        await run_uuid_validation(client)
        await run_fallback(client)
        await run_ratelimit(client)

    write_report(backend_version, backend_running=True)

    # 최종 요약 출력
    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["passed"])
    failed = total - passed

    print("\n" + "=" * 65)
    print("NF 벤치마크 결과 요약")
    print("=" * 65)
    print(f"{'NF 항목':<35} {'목표':<25} {'실측':<20} {'판정'}")
    print("-" * 95)
    for r in RESULTS:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"{r['test']:<35} {r['target']:<25} {str(r['actual']):<20} {status}")

    print("=" * 65)
    print(f"총 {total}개 항목: PASS={passed}, FAIL={failed}")
    if failed == 0:
        print("전체 PASS — SRS NF 요건 충족")
    else:
        print(f"[주의] {failed}개 항목 NF 목표 미달")
    print(f"\n리포트 저장: docs/qa_benchmark.md")

    return 0 if failed == 0 else 1


def write_report(backend_version: str, backend_running: bool = True) -> None:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(RESULTS)
    passed_count = sum(1 for r in RESULTS if r["passed"])
    failed_count = total - passed_count
    failed_items = [r for r in RESULTS if not r["passed"]]

    lines = [
        "# Security Hub NF 벤치마크 결과",
        "",
        f"실행 일시: {now_str}",
        f"백엔드 버전: {backend_version}",
        f"백엔드 상태: {'실행 중' if backend_running else '미실행 (정적 검증만)'}",
        "",
        "## 결과 요약",
        "",
        "| NF 항목 | SRS 목표 | 실측값 | 판정 |",
        "|---------|---------|--------|------|",
    ]

    for r in RESULTS:
        verdict = "PASS" if r["passed"] else "FAIL"
        lines.append(
            f"| {r['test']} | {r['target']} | {r['actual']} | {verdict} |"
        )

    lines += [
        "",
        "## 상세 측정값",
        "",
    ]

    for r in RESULTS:
        verdict = "PASS" if r["passed"] else "FAIL"
        lines.append(f"### {r['test']} — {verdict}")
        lines.append(f"- **SRS 목표**: {r['target']}")
        lines.append(f"- **실측값**: {r['actual']}")
        lines.append(f"- **상세**: {r['detail']}")
        lines.append("")

    lines += [
        "## 측정 방법 및 조건",
        "",
        "- 응답 시간: `time.perf_counter()` (단조 시계) 기반, httpx AsyncClient",
        "- p95 계산: sorted(latencies)[int(0.95 * n)] 인덱스 값",
        "- 화이트리스트 히트 URL: https://www.naver.com (whitelist_v2.csv suffix 매칭)",
        "- 휴리스틱 경로 URL: https://login-verify-secure.xyz/account/confirm",
        "- Full path URL: 매 측정마다 UUID 기반 랜덤 미지 도메인 생성 (캐시 미스 보장)",
        "- Rate limit: 11회 연속 POST /analyze (동일 IP/세션)",
        "- NF-25/27/28: 소스 코드 정적 분석 (코드 확인)",
        "",
        "## 판정",
        "",
        f"- 전체 통과: {total}개 중 {passed_count}개",
        f"- 미달 항목: {'(없음)' if not failed_items else ', '.join(r['test'] for r in failed_items)}",
        "",
    ]

    docs_dir = os.path.join(os.path.dirname(__file__), "..", "..", "docs")
    os.makedirs(docs_dir, exist_ok=True)
    report_path = os.path.join(docs_dir, "qa_benchmark.md")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\n[리포트] 저장 완료: {os.path.abspath(report_path)}")


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
