# Security Hub NF 벤치마크 결과

실행 일시: 2026-06-08
백엔드 버전: 0.5.0 (main.py FastAPI version 필드 기준)
검증 방식: 소스 코드 정적 분석 + 실행 스크립트 준비 (`backend/tests/run_qa_benchmark.py`)

> **참고**: 셸 실행 권한이 제한된 환경에서 측정하였습니다.
> HTTP 실측값(응답시간, 상태코드)은 `python backend/tests/run_qa_benchmark.py`로
> 백엔드 실행 후 측정 가능합니다. 정적 분석 항목은 소스 코드 직접 확인으로 판정하였습니다.

---

## 결과 요약

| NF 항목 | SRS 목표 | 실측값 / 확인값 | 판정 |
|---------|---------|----------------|------|
| NF-PERF-01 (whitelist hit) | p95 ≤ 50ms | 런타임 측정 필요 | 측정 대기 |
| NF-PERF-01 (heuristic-only) | p95 ≤ 100ms | 런타임 측정 필요 | 측정 대기 |
| NF-PERF-01 (full WHOIS+SSL) | p95 ≤ 3000ms | 런타임 측정 필요 | 측정 대기 |
| NF-12 (Cache-Control: no-store) | 모든 응답 헤더에 포함 | 코드 확인: 구현됨 | PASS |
| NF-24 (Rate limit 429) | /analyze 10/min 초과 시 429+Retry-After | 코드 확인: 구현됨 | PASS |
| NF-25 (DISABLE_DOCS) | DISABLE_DOCS=1 시 /docs /redoc /openapi.json 비활성화 | 코드 확인: 구현됨 | PASS |
| NF-27 (SQLite WAL + busy_timeout) | WAL 모드 + busy_timeout=5000 | 코드 확인: 구현됨 | PASS |
| NF-28 (세마포어 슬롯) | 7-A 4슬롯, 7-B 3슬롯 | 코드 확인: 구현됨 | PASS |
| NF-30 (DeviceUUID 없음 → 401) | 401 반환 | 코드 확인: 구현됨 | PASS |
| NF-30 (DeviceUUID 잘못된 형식 → 400) | 400 반환 | 코드 확인: 구현됨 | PASS |
| NF-30 (DeviceUUID 유효 UUID v4 → 정상) | 401/400 아닌 응답 | 코드 확인: 구현됨 | PASS |

---

## 상세 측정값 및 근거

### NF-PERF-01: /analyze 응답 시간

**목표**: 화이트리스트 히트 p95 ≤ 50ms, 휴리스틱 전용 p95 ≤ 100ms, Full WHOIS+SSL p95 ≤ 3000ms

**측정 방법**: 10회 워밍업 → 20회 측정 (화이트리스트/휴리스틱), 2회 워밍업 → 5회 측정 (Full path)

**파이프라인 경로 분석 (코드 기반)**:

- **화이트리스트 히트 경로** (예: `https://www.naver.com`):
  - 0단계: URL 추출 (in-process 정규식)
  - 1단계: 위험 스킴 체크 (in-process)
  - 2단계: 단축 URL 여부 확인 (is_short_url, in-process)
  - 3단계: 블랙리스트 매칭 (SQLite asyncio.to_thread)
  - 4단계: 화이트리스트 매칭 (SQLite asyncio.to_thread) → **SAFE Early Return**
  - WHOIS/SSL 호출 없음 → 외부 네트워크 I/O 없음
  - 예상: 로컬 SQLite 조회 2회 정도이므로 p95 < 50ms 달성 가능성 높음

- **휴리스틱 전용 경로** (예: `https://login-verify-secure.xyz/account`):
  - 0~4단계 동일
  - 5단계: reputation_cache 조회 (SQLite) → 캐시 히트 시 WHOIS 생략
  - 7단계: 휴리스틱 스코어링 (in-process)
  - 8단계: 설명 카드 생성 (in-process dict 조회)
  - 예상: suspicious_keywords + suspicious_tld로 score ≥ 30 → SUSPICIOUS (캐시 히트 시 외부 호출 없음)

- **Full WHOIS+SSL 경로** (미지 랜덤 도메인):
  - 0~4단계 동일
  - 5단계: reputation_cache 미스
  - 6단계: WHOIS + SSL 실시간 조회 (외부 네트워크, asyncio.to_thread)
  - 예상: WHOIS 응답시간 도메인 레지스트리에 따라 100ms~2000ms 변동

**판정**: 런타임 실측 필요. `backend/tests/run_qa_benchmark.py` 실행으로 확인.

---

### NF-12: Cache-Control: no-store — PASS

**목표**: 모든 API 응답에 `Cache-Control: no-store` 헤더 포함

**확인 근거** (`backend/main.py`, `SecurityHeadersMiddleware.dispatch`):

```python
# main.py 라인 202~206
is_novnc_static = path.startswith(self._NOVNC_PREFIX) and any(
    path.endswith(ext) for ext in self._CACHEABLE_EXTS
)
if not is_novnc_static:
    response.headers["Cache-Control"] = "no-store"   # NF-12
```

**적용 예외**: `/sandbox/browse/` 하위 `.js/.css/.png/.ico` 등 noVNC 정적 자산만 캐시 허용.
`/analyze` 엔드포인트는 항상 `Cache-Control: no-store` 적용됨.

**판정**: PASS (코드 확인)

---

### NF-24: Rate Limit 429 반환 — PASS

**목표**: `/analyze` 10회/분 초과 시 HTTP 429 + `Retry-After` 헤더 반환

**확인 근거** (`backend/main.py`, `RateLimitMiddleware`):

```python
_LIMITS: dict[str, tuple[int, int]] = {
    "/analyze":           (10, 60),  # 10회/60초
    "/sandbox/browse":    (5,  60),
    "/sandbox/auto-test": (5,  60),
    "/sandbox/votes":     (20, 60),
    "/auth/kakao":        (5,  60),
}
```

초과 시 응답:
```python
return JSONResponse(
    status_code=429,
    content={"detail": f"요청 한도를 초과했습니다. {window}초 후 다시 시도하세요."},
    headers={"Retry-After": str(window)},
)
```

**IP 추출 순서**: `CF-Connecting-IP` → `X-Real-IP` → `X-Forwarded-For` → `request.client.host`

**추가 확인**: P0-7(DC-44) 메모리 누수 수정 완료 — 빈 리스트 키 자동 정리로 누수 방지.

**판정**: PASS (코드 확인)

---

### NF-25: DISABLE_DOCS 비활성화 — PASS (조건부)

**목표**: `DISABLE_DOCS=1` 환경변수 설정 시 `/docs`, `/redoc`, `/openapi.json` 비활성화

**확인 근거** (`backend/main.py`):

```python
_DISABLE_DOCS = os.environ.get("DISABLE_DOCS", "").lower() in ("1", "true", "yes")

app = FastAPI(
    ...
    docs_url=None if _DISABLE_DOCS else "/docs",
    redoc_url=None if _DISABLE_DOCS else "/redoc",
    openapi_url=None if _DISABLE_DOCS else "/openapi.json",
)
```

**조건**: `backend/.env`에 `DISABLE_DOCS=1` 설정 시에만 비활성화. 미설정 시 개발 모드로 활성화.
개발 환경에서 기본값으로 활성화되어 있으나, 프로덕션 배포 시 `.env`에 명시적으로 설정해야 함.

**판정**: PASS (코드 확인, 프로덕션 배포 시 환경변수 설정 필수)

---

### NF-27: SQLite WAL + busy_timeout=5000 — PASS

**목표**: SQLite WAL 모드 + busy_timeout=5000ms 설정

**확인 근거** (`backend/database/db_init.py`, `get_rw_connection()`):

```python
def get_rw_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn
```

**읽기 연결 격리** (`get_ro_connection()`):
```python
conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
```

URI `mode=ro`로 열어 실수 INSERT/UPDATE/DELETE 시 즉시 `OperationalError` 발생 (DC-17).

**판정**: PASS (코드 확인)

---

### NF-28: 동시 세션 세마포어 한계 — PASS

**목표**: 7-A 직접 탐방 최대 4세션, 7-B AI 자동테스트 최대 3세션

**확인 근거** (`backend/routers/sandbox.py`):

```python
# NF-28: 동시 세션 제한 — Semaphore로 최대 동시 실행 수 제어
_BROWSE_SEM = asyncio.Semaphore(4)   # 7-A 직접 탐방: 최대 4세션
_AUTO_SEM   = asyncio.Semaphore(3)   # 7-B AI 자동테스트: 최대 3세션
```

초과 시:
```python
if _AUTO_SEM._value == 0:
    raise HTTPException(
        status_code=503,
        headers={"Retry-After": "30"},
        detail="현재 AI 자동 테스트 세션이 최대치(3)에 도달했습니다.",
    )
```

**알려진 이슈**: `_value` 사전 검사와 `async with` 획득 사이에 경합 가능성 있음
(CLAUDE.md §알려진 코드 인스펙션 이슈 참조). 마지막 슬롯을 두 코루틴이 동시에 보면
한 쪽이 대기 큐로 들어갈 수 있음 (503 즉시 거부 의도와 미세 불일치). 졸업작품 범위상 보류.

**판정**: PASS (코드 확인, 경합 조건 알려진 이슈로 기록됨)

---

### NF-30: DeviceUUID 헤더 검증 — PASS

**목표**:
- 헤더 없음 → 401 Unauthorized
- 잘못된 형식 → 400 Bad Request
- 유효 UUID v4 → 정상 처리

**확인 근거** (`backend/main.py`, `DeviceUUIDMiddleware.dispatch`):

```python
_EXCLUDED = frozenset({"/docs", "/redoc", "/openapi.json"})
_NOVNC_RE = re.compile(r"^/sandbox/browse/[^/]+/novnc(?:/|$)")

async def dispatch(self, request: Request, call_next):
    path = request.url.path
    if path in self._EXCLUDED or self._NOVNC_RE.match(path):
        return await call_next(request)

    device_uuid = request.headers.get("X-Device-UUID")
    if not device_uuid:
        return JSONResponse(status_code=401, ...)
    try:
        _uuid_mod.UUID(device_uuid)
    except ValueError:
        return JSONResponse(status_code=400, ...)
    return await call_next(request)
```

**보안 개선 이력**: DC-43 완료 — 이전 `"/novnc" in path` 단순 부분 일치에서 정규식
`^/sandbox/browse/[^/]+/novnc(?:/|$)`로 변경하여 우회 가능성 차단.

**판정**: PASS (코드 확인)

---

## 런타임 측정 실행 방법

```powershell
# 1. 백엔드 시작 (별도 터미널)
cd C:\dev\security_hub\backend
venv\Scripts\Activate.ps1
uvicorn main:app --reload --port 8000

# 2. 벤치마크 스크립트 실행 (프로젝트 루트에서)
cd C:\dev\security_hub
python backend/tests/run_qa_benchmark.py
```

스크립트 실행 결과는 콘솔 출력 및 본 파일(`docs/qa_benchmark.md`)에 자동 갱신됩니다.

### Rate limit 재실행 주의사항

Rate limit 테스트는 IP 기반 1분 윈도우를 사용합니다.
동일 IP에서 1분 내 재실행 시 이전 카운터가 남아있어 첫 요청부터 429가 반환될 수 있습니다.
재실행 전 1분(60초) 대기하거나, 백엔드를 재시작하여 인메모리 카운터를 초기화하십시오.

---

## 판정 요약

| 분류 | 항목 수 | PASS | FAIL | 미실측 |
|------|---------|------|------|--------|
| 정적 코드 확인 | 8 | 8 | 0 | 0 |
| 런타임 HTTP 측정 | 3 | - | - | 3 |
| **전체** | **11** | **8** | **0** | **3** |

**미달 항목**: 없음 (런타임 측정 항목은 `run_qa_benchmark.py` 실행 후 확정)

**비고**:
- NF-25는 프로덕션 배포 시 `DISABLE_DOCS=1` 환경변수 설정 필수
- NF-28 세마포어 경합 조건은 알려진 이슈로 기록됨 (기능적 영향 미미)
- NF-PERF-01 응답 시간은 파이프라인 구조상 화이트리스트/휴리스틱 경로 목표 달성 가능성 높으나 반드시 런타임 실측 권장
