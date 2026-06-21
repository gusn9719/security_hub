#!/usr/bin/env python3
# =============================================================================
# backend/tests/run_sandbox_escape_test.py
# 강화된 7-A/7-B 컨테이너에서 실제 탈출 시도 6종을 실행해 전부 막히는지 증명
#
# "가상 서버가 뚫리면 실제 서버나 사용자 기기가 위험해지는 거 아니냐"는
# 질문에 "Docker라서 안전하다"는 말로만 답하지 않기 위한 스크립트. 강화된
# 파라미터(mem_limit/nano_cpus/pids_limit/cap_drop=ALL/security_opt=
# no-new-privileges, DC-51)로 실제 컨테이너를 띄운 뒤 container.exec_run()
# 으로 호스트 침투를 시도하고, 전부 실패(=차단)해야 정상이다.
#
# 실행: cd C:\dev\security_hub && python backend/tests/run_sandbox_escape_test.py
# 주의: 실제 Docker 컨테이너를 여러 개 띄운다. Docker Desktop이 실행 중이어야 함.
# =============================================================================

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import docker  # noqa: E402

import services.browse_service as browse_service  # noqa: E402
from services.browse_service import (   # noqa: E402
    create_browse_session,
    terminate_browse_session,
    shutdown_all_sessions,
    _create_browse_network,
    _active_sessions,
)
from services.sandbox_service import (  # noqa: E402
    BROWSERLESS_IMAGE,
    _create_sandbox_network,
)

RESULTS: list[dict] = []
EXEC_TIMEOUT = 40


def record(category: str, attempt: str, expected: str, actual: str, blocked: bool) -> None:
    RESULTS.append({"category": category, "attempt": attempt, "expected": expected,
                     "actual": actual, "blocked": blocked})
    tag = "PASS(차단됨)" if blocked else "FAIL(차단 안 됨)"
    print(f"  [{tag}] {category}: {actual[:120]}")


async def _exec(container, cmd: str) -> tuple[int, str]:
    exit_code, output = await asyncio.wait_for(
        asyncio.to_thread(container.exec_run, ["sh", "-c", cmd]),
        timeout=EXEC_TIMEOUT,
    )
    text = output.decode("utf-8", errors="replace").strip() if isinstance(output, bytes) else str(output)
    return exit_code, text


async def probe_filesystem_and_socket(container, label: str) -> None:
    print(f"\n[{label}] 1. 호스트 파일시스템 마운트 시도")
    code, out = await _exec(container, "ls -la /host 2>&1; mount 2>&1 | grep -i host || echo NO_HOST_MOUNT")
    blocked = "No such file" in out or "NO_HOST_MOUNT" in out
    record(f"{label}-호스트FS", "ls /host, mount | grep host", "마운트 없음", out, blocked)

    print(f"\n[{label}] 2. 호스트 Docker 소켓 접근 시도")
    code, out = await _exec(container, "ls -la /var/run/docker.sock 2>&1")
    blocked = "No such file" in out or "cannot access" in out
    record(f"{label}-DockerSocket", "ls /var/run/docker.sock", "소켓 부재", out, blocked)


async def probe_host_backend_ssrf(container, label: str) -> None:
    print(f"\n[{label}] 3. host.docker.internal 통한 호스트 백엔드 SSRF 시도")
    code, out = await _exec(
        container,
        "curl -s -o /dev/null -w 'HTTP=%{http_code}' --max-time 3 "
        "http://host.docker.internal:8000/ 2>&1 || echo CURL_FAILED",
    )
    blocked = "CURL_FAILED" in out or "HTTP=000" in out or out.strip() == ""
    record(f"{label}-SSRF(host.docker.internal)", "curl host.docker.internal:8000",
           "연결 실패 (0.0.0.0 매핑)", out, blocked)


async def probe_fork_bomb(container, label: str, pids_limit: int) -> None:
    """프로세스 수를 세는 명령을 폭탄 시도와 같은 exec_run 한 줄에 넣으면
    fork 실패 에러 메시지가 출력에 섞여 마지막 줄 파싱이 깨진다 — 폭탄 시도와
    카운트를 별도 exec_run 호출로 분리한다. 스폰된 프로세스는 짧게(2초) 살아
    있다가 끝나도록 해서 다음 검증 항목에 pids_limit 잔여 영향을 주지 않는다."""
    print(f"\n[{label}] 4. 프로세스 폭탄 시도 (pids_limit={pids_limit})")
    target = pids_limit * 3
    await _exec(container, f"for i in $(seq 1 {target}); do sleep 2 & done; echo QUEUED")
    await asyncio.sleep(1.5)
    _, out = await _exec(container, "ls /proc | grep -E '^[0-9]+$' | wc -l")
    try:
        actual_count = int(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        actual_count = -1
    blocked = 0 <= actual_count <= pids_limit + 20  # 여유 마진(baseline 프로세스 수 고려)
    record(f"{label}-ForkBomb", f"sleep 2 & x{target}",
           f"프로세스 수 <= ~{pids_limit}", f"실제 프로세스 수={actual_count} (요청={target})", blocked)
    await asyncio.sleep(3)  # 스폰된 프로세스 종료 대기 — 컨테이너 정리 전 정상 상태 복귀


async def probe_cap_eff(container, label: str) -> None:
    print(f"\n[{label}] 5. CapEff(유효 권한) 확인")
    code, out = await _exec(container, "cat /proc/self/status | grep CapEff || echo NO_PROC_STATUS")
    blocked = "0000000000000000" in out
    record(f"{label}-CapEff", "cat /proc/self/status | grep CapEff", "CapEff=0 (cap_drop=ALL)", out, blocked)


def probe_icc(client) -> None:
    """enable_icc=false 네트워크 옵션이 실제로 같은 네트워크 내 컨테이너 간
    통신을 막는지 — 운영 코드는 세션마다 전용 네트워크를 새로 만들어서
    실제로는 이 상황(같은 네트워크에 컨테이너 2개)이 절대 발생하지 않지만,
    그 방어선 자체가 살아있는지 별도로 검증한다."""
    print("\n[ICC] 6. 같은 격리 네트워크 내 컨테이너 간 통신(ping) 시도")
    network = _create_browse_network(client)
    c1 = c2 = None
    try:
        c1 = client.containers.run("alpine:latest", ["sleep", "60"], detach=True, remove=True,
                                    network=network.name)
        c2 = client.containers.run("alpine:latest", ["sleep", "60"], detach=True, remove=True,
                                    network=network.name)
        c1.reload()
        c2.reload()
        ip2 = c2.attrs["NetworkSettings"]["Networks"][network.name]["IPAddress"]
        exit_code, out = c1.exec_run(["sh", "-c", f"ping -c1 -W2 {ip2} 2>&1 || echo PING_FAILED"])
        text = out.decode("utf-8", errors="replace").strip() if isinstance(out, bytes) else str(out)
        blocked = "PING_FAILED" in text or "100% packet loss" in text or exit_code != 0
        record("ICC-차단", f"ping {ip2}", "ICC 차단으로 실패", text, blocked)
    finally:
        for c in (c1, c2):
            if c is not None:
                try:
                    c.stop(timeout=3)
                except Exception:
                    pass
        try:
            network.remove()
        except Exception as e:
            print(f"  [경고] 테스트 네트워크 삭제 실패(무해): {e}")


async def run_7a() -> None:
    print("=" * 78)
    print("[7-A] kasmweb/chromium 컨테이너 탈출시도 검증")
    print("=" * 78)
    result = await create_browse_session("https://example.com")
    if result.get("error"):
        print(f"[오류] 7-A 세션 생성 실패: {result['error']}")
        return
    container_id = result["container_id"]
    network_name = result["network_name"]
    session = _active_sessions.get(container_id)
    container = session["container"] if session else None
    if container is None:
        print("[오류] 활성 세션에서 컨테이너 핸들을 찾지 못함")
        return
    try:
        await probe_filesystem_and_socket(container, "7-A")
        await probe_host_backend_ssrf(container, "7-A")
        await probe_cap_eff(container, "7-A")
        await probe_fork_bomb(container, "7-A", pids_limit=256)
    finally:
        await terminate_browse_session(container_id, network_name)
        # create_browse_session() 의 온디맨드 성공 직후(L1314)와
        # terminate_browse_session() 종료 시(L1555) 모두 _replenish_pool() 을
        # 백그라운드로 띄운다 — 이번 한 번의 세션 생성+종료만으로 POOL_SIZE(2)개
        # idle 컨테이너가 다 채워질 때까지 기다린 뒤 shutdown 해야 고아가 안 남는다.
        # 둘 다 끝났다는 신뢰할 수 있는 종료 조건은 "더 이상 보충 중인 게 없고
        # idle 큐가 꽉 찼다"이다(스크립트형 1회성 실행에서만 필요한 정리 로직).
        pool_size = browse_service.POOL_SIZE
        for _ in range(75):  # 최대 ~150초 대기
            warming = browse_service._pool_warming
            idle = browse_service._pool_idle.qsize()
            if warming == 0 and idle >= pool_size:
                break
            await asyncio.sleep(2)
        await shutdown_all_sessions()  # 활성 세션 + idle 컨테이너 전부 정리


async def run_7b(client) -> None:
    print("\n" + "=" * 78)
    print("[7-B] Browserless 컨테이너 탈출시도 검증")
    print("=" * 78)
    network = await asyncio.to_thread(_create_sandbox_network, client)
    container = None
    try:
        container = await asyncio.to_thread(
            client.containers.run,
            BROWSERLESS_IMAGE,
            detach=True,
            remove=True,
            ports={"3000/tcp": ("127.0.0.1", None)},
            environment={"TOKEN": "sandbox_token"},
            network=network.name,
            extra_hosts={"host.docker.internal": "0.0.0.0"},
            mem_limit="512m",
            nano_cpus=int(0.5 * 1e9),
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            pids_limit=128,
        )
        await asyncio.sleep(3)  # 컨테이너 부팅 대기
        await probe_filesystem_and_socket(container, "7-B")
        await probe_host_backend_ssrf(container, "7-B")
        await probe_cap_eff(container, "7-B")
        await probe_fork_bomb(container, "7-B", pids_limit=128)
    finally:
        if container is not None:
            try:
                await asyncio.to_thread(container.stop, timeout=5)
            except Exception as e:
                print(f"  [경고] 7-B 컨테이너 정리 실패: {e}")
        try:
            await asyncio.to_thread(network.remove)
        except Exception as e:
            print(f"  [경고] 7-B 네트워크 삭제 실패: {e}")


def _table() -> str:
    lines = ["| 영역 | 시도 | 기대 결과 | 실제 결과 | 판정 |", "|---|---|---|---|---|"]
    for r in RESULTS:
        verdict = "PASS (차단됨)" if r["blocked"] else "**FAIL (차단 안 됨)**"
        actual = r["actual"].replace("\n", " ").replace("|", "/")[:100]
        lines.append(f"| {r['category']} | {r['attempt']} | {r['expected']} | {actual} | {verdict} |")
    return "\n".join(lines) + "\n"


def write_report() -> None:
    report_path = os.path.join(os.path.dirname(__file__), "..", "..", "docs", "sandbox_hardening.md")
    n_total = len(RESULTS)
    n_blocked = sum(1 for r in RESULTS if r["blocked"])
    content = f"""# 샌드박스 격리 강화 + 탈출시도 검증 결과 (DC-51)

`backend/tests/run_sandbox_escape_test.py` 실행 결과. 강화된 파라미터로
실제 7-A(kasmweb/chromium)/7-B(Browserless) 컨테이너를 띄운 뒤
`container.exec_run()`으로 호스트 침투를 시도했다.

## 적용된 강화 파라미터

| | 7-A (`browse_service.py`) | 7-B (`sandbox_service.py`) |
|---|---|---|
| mem_limit | 512m | 512m |
| nano_cpus | 0.5 코어 | 0.5 코어 |
| pids_limit | 256 | 128 |
| 포트 바인딩 | 127.0.0.1 (변경 전: 전체 노출) | 127.0.0.1 (기존 유지) |
| cap_drop | ALL | ALL |
| security_opt | no-new-privileges | no-new-privileges |

Kasm Chromium 1.14.0 / Browserless 둘 다 `cap_drop=["ALL"]` +
`security_opt=["no-new-privileges"]` 적용 후에도 noVNC 렌더링, CDP
원격 디버깅, Playwright 자동분석 전부 정상 동작 확인(별도 스모크 테스트,
`cap_add` 예외 불필요).

## 탈출시도 검증 결과 ({n_blocked}/{n_total} 차단)

{_table()}

## 한계

- ICC(컨테이너 간 통신) 테스트는 운영 코드가 세션마다 전용 네트워크를
  새로 생성하므로 실제로는 발생하지 않는 상황을 인위적으로 재현한 것이다
  — `enable_icc=false` 라는 방어선 자체가 살아있는지만 별도로 확인했다.
- 프로세스 폭탄 테스트는 컨테이너 baseline 프로세스 수(Xvnc·창관리자·
  Chromium 등)를 포함한 합계로 판정하므로 약간의 여유 마진을 둠
  (`pids_limit + 20`).
- Docker 컨테이너 경계 자체(커널 네임스페이스·cgroup) 너머의 커널
  0-day 취약점까지는 이 테스트로 증명할 수 없다 — 이건 모든 컨테이너
  기반 격리의 공통적 한계이며, 졸업작품 범위에서 추가로 줄일 수 있는
  부분은 아니다.
"""
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(content)


async def main() -> None:
    try:
        client = await asyncio.to_thread(docker.from_env)
    except Exception as e:
        print(f"[오류] Docker 연결 실패: {e}")
        return

    await run_7a()
    await run_7b(client)
    probe_icc(client)

    n_total = len(RESULTS)
    n_blocked = sum(1 for r in RESULTS if r["blocked"])
    print("\n" + "=" * 78)
    print(f"[결론] {n_blocked}/{n_total} 탈출 시도 차단됨")
    if n_blocked < n_total:
        print("[경고] 차단되지 않은 시도가 있음 — 위 표에서 FAIL 항목 확인 필요")

    write_report()
    print("[리포트] docs/sandbox_hardening.md 작성 완료")


if __name__ == "__main__":
    asyncio.run(main())
