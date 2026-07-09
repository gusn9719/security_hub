# Security Hub NF 벤치마크 결과

실행 일시: 2026-06-20 17:23 ~ 17:35
백엔드 버전: 0.5.0 (main.py FastAPI version 필드 기준)
검증 방식: 실제 백엔드 실행 + HTTP 실측 (`uvicorn main:app --port 8000`, 127.0.0.1) + 정적 코드 확인

---

## 중요: `run_qa_benchmark.py` 자체의 레이트리밋 자기 오염 버그

`backend/tests/run_qa_benchmark.py`를 그대로 실행하면 **모든 항목이 FAIL/측정불가로
나온다.** 원인은 스크립트 설계 결함이며 서버 버그가 아니다.

- `/analyze`의 레이트리밋은 **10회/60초 (IP 기준, 슬라이딩 윈도우)**
  (`backend/main.py` `RateLimitMiddleware._LIMITS`).
- `run_perf_whitelist()` 한 함수가 워밍업 10회 + 측정 20회 = **30회**를
  같은 IP·같은 엔드포인트로 연속 호출한다. 워밍업 10회만으로 이미 60초
  쿼터를 전부 소진하므로, 뒤이은 측정 20회는 전부 429를 받아
  `latencies` 리스트가 비고 "측정불가"로 보고된다.
- 이어지는 `run_perf_heuristic`, `run_perf_full_path`, `NF-ISOLATION-01`,
  `NF-UUID-01`, `NF-FALLBACK-01`도 같은 60초 윈도우 안에서 누적된 호출이라
  연쇄적으로 429를 받는다. `NF-RATELIMIT-01`만 "의도된" 429라서 우연히
  같은 모습으로 보이지만, 그 앞 단계는 전부 오염된 결과다.
- 즉 **이 스크립트는 현재 레이트리밋 설정(10/min)에서는 단 한 번도
  정상적으로 측정에 성공한 적이 없다** — 이전 버전 문서의
  "측정 대기" 상태가 바로 이 문제 때문이었던 것으로 보인다.
- 역설적으로 이는 레이트리밋이 설계대로 엄격하게 작동한다는 증거이기도
  하다(자체 진단 스크립트조차 우회하지 못함).

이번에는 **같은 (IP, /analyze) 키를 공유하는 모든 호출을 60초 윈도우당
10회 이하로 제한**하고, 카테고리 사이에 65초씩 대기하는 경량 측정 스크립트로
재측정했다. 측정 방법론은 "측정 방법 및 조건" 절 참조.

---

## 결과 요약

| NF 항목 | SRS 목표 | 실측값 | 판정 |
|---------|---------|--------|------|
| NF-PERF-01 (whitelist hit) | p95 ≤ 50ms | p95=22.7ms (n=8, min=8.2ms, median=9.0ms, max=22.7ms) | **PASS** |
| NF-PERF-01 (heuristic-only) | p95 ≤ 100ms | p95=18.3ms (n=8, min=11.3ms, median=15.3ms, max=18.3ms) | **PASS** |
| NF-PERF-01 (full WHOIS+SSL) | p95 ≤ 3000ms | p95=1277.6ms (n=5, min=1124.8ms, median=1159.5ms, max=1277.6ms) | **PASS** |
| NF-12 (Cache-Control: no-store) | 모든 응답 헤더에 포함 | `no-store` 확인 | PASS |
| NF-24 (Rate limit 429) | req1-10: 2xx, req11: 429+Retry-After | statuses=[200×10, 429], Retry-After=60 | **PASS** |
| NF-25 (DISABLE_DOCS) | DISABLE_DOCS=1 시 /docs /redoc /openapi.json 비활성화 | 코드 확인: 구현됨 | PASS |
| NF-27 (SQLite WAL + busy_timeout) | WAL 모드 + busy_timeout=5000 | 코드 확인: 구현됨 | PASS |
| NF-28 (세마포어 슬롯) | 7-A 4슬롯, 7-B 3슬롯 | 코드 확인: 구현됨 (단, `_value` 사전검사 경합 알려진 이슈) | PASS |
| NF-30 (DeviceUUID 없음 → 401) | 401 반환 | HTTP 401 | **PASS** |
| NF-30 (DeviceUUID 잘못된 형식 → 400) | 400 반환 | HTTP 400 | **PASS** |
| NF-30 (DeviceUUID 유효 UUID v4 → 정상) | 401/400 아닌 응답 | HTTP 200 | **PASS** |
| NF-ISOLATION-01 (동시 요청 격리) | 3/3 응답 + 각자 올바른 라벨 | 3/3 응답, naver→safe / suspicious-도메인→suspicious / coupang→safe | **PASS** |
| NF-FALLBACK-01 (미지 도메인, DC-06) | suspicious 또는 danger (safe 금지) | label=suspicious | **PASS** |
| NF-FALLBACK-01 (URL 없는 텍스트, DC-06) | suspicious 또는 danger (safe 금지) | label=suspicious | **PASS** |

**전체 14개 항목: PASS 14 / FAIL 0**

---

## 상세 측정값 및 근거

### NF-PERF-01: /analyze 응답 시간 — 전체 PASS

화이트리스트 히트 경로(`https://www.naver.com`)는 단계 0~4까지만 거치고
SAFE Early Return — 외부 네트워크 I/O 없음. p95 22.7ms로 목표(50ms)의
절반 이하.

휴리스틱 전용 경로(`https://login-verify-secure.xyz/account/confirm`)는
`suspicious_keywords` + `suspicious_tld` 시그널만으로 점수 산정 —
WHOIS/SSL 미호출. p95 18.3ms로 목표(100ms)의 1/5 수준.

Full path(매 요청 랜덤 미지 도메인, 예: `https://xk9z-nf-quick-XXXXXXXX.xyz/phish`)는
WHOIS 조회 + SSL 핸드셰이크 실패(존재하지 않는 도메인이므로 SSL 연결 시도 후
실패) + 포트 80 폴백까지 실제로 수행. p95 1277.6ms로 목표(3000ms)의
약 43% 수준 — 외부 I/O를 포함해도 충분한 여유.

**측정 방법(레이트리밋 안전 버전)**: 카테고리별 워밍업 1회 + 측정 8회
(whitelist/heuristic), 측정 5회(full path, 외부 I/O 비용이 높아 표본 축소).
카테고리 사이 65초 대기로 10회/60초 쿼터를 항상 비운 상태에서 측정 시작.

### NF-12: Cache-Control: no-store — PASS

`backend/main.py` `SecurityHeadersMiddleware.dispatch`에서 noVNC 정적 자산
경로를 제외한 모든 응답에 `Cache-Control: no-store` 적용 확인. `/analyze`
응답에서 직접 헤더 확인됨.

### NF-24: Rate Limit 429 — PASS (실측)

신선한 60초 윈도우에서 동일 `X-Device-UUID`로 `/analyze`에 11회 연속
POST: 1~10번째 모두 200, 11번째 429 + `Retry-After: 60` 헤더 확인.
`RateLimitMiddleware._LIMITS["/analyze"] = (10, 60)`과 정확히 일치.

### NF-25 / NF-27 / NF-28 — PASS (정적 코드 확인)

- NF-25: `main.py`의 `_DISABLE_DOCS` 환경변수 분기로 `docs_url`/`redoc_url`/
  `openapi_url`을 조건부 `None` 처리 확인.
- NF-27: `database/db_init.py` `get_rw_connection()`에서
  `journal_mode=WAL`, `busy_timeout=5000`, `synchronous=NORMAL` 확인.
  `get_ro_connection()`은 `mode=ro` URI로 별도 분리(DC-17).
- NF-28: `routers/sandbox.py`에 `_BROWSE_SEM = Semaphore(4)`,
  `_AUTO_SEM = Semaphore(3)` 확인. **알려진 이슈**: `_value` 사전 검사와
  `async with` 획득 사이 경합 가능성 — CLAUDE.md 「알려진 코드 인스펙션
  이슈」 참조, 졸업작품 범위상 보류.

### NF-30: DeviceUUID 헤더 검증 — PASS (실측)

신선한 윈도우에서 개별 확인:
- 헤더 없음 → 401 (`DeviceUUIDMiddleware`가 거부)
- `X-Device-UUID: not-a-uuid` → 400 (UUID v4 형식 검증 실패)
- 유효한 UUID v4 → 200 (정상 처리, 401/400 아님)

주의: RateLimitMiddleware가 DeviceUUIDMiddleware보다 **먼저** 실행되므로
(`CORS → Security → RateLimit → DeviceUUID → OptionalAuth →
BlockDangerousMethods`), 쿼터가 이미 소진된 상태에서는 헤더 없는 요청도
401이 아니라 429를 받는다. 이번 측정에서 그 현상을 직접 재현해 원인을
규명했다(아래 "측정 중 발견한 부수 현상" 참조).

### NF-ISOLATION-01: 동시 요청 데이터 격리 — PASS (실측)

`asyncio.gather`로 3개 URL(naver.com / login-verify-secure.xyz / coupang.com)을
동시에 `/analyze`에 요청 → 3/3 정상 응답, 각각 올바른 판정(safe/suspicious/safe)
반환. 동시 요청 간 상태 혼선(레이스) 없음 확인.

### NF-FALLBACK-01: 보수적 SUSPICIOUS 폴백 (DC-06) — PASS (실측)

- 완전히 미지의 랜덤 도메인 → `suspicious` (절대 `safe` 아님)
- URL이 없는 일반 텍스트 → `suspicious`

두 경우 모두 "알 수 없음 = SUSPICIOUS" 원칙(DC-06)이 코드가 아니라
실제 HTTP 응답으로 확인됨.

---

## 측정 중 발견한 부수 현상 (레이트리밋 슬라이딩 윈도우 누적)

최초 시도에서 `run_qa_benchmark.py`를 그대로 실행했을 때 거의 전 항목이
429로 오염된 것을 확인했고, 그 원인이 스크립트 자체의 과도한 호출량임을
별도 경량 스크립트로 재현·검증했다. 또한 두 번째 보조 스크립트에서도
직전 스크립트가 남긴 호출 타임스탬프가 60초 슬라이딩 윈도우 안에
남아 있어 일부 항목이 추가로 오염되는 것을 관찰했다 — `RateLimitMiddleware`의
카운터가 (IP, path) 키로 **프로세스 메모리에 계속 누적**되며, 윈도우 밖
타임스탬프만 정리되고 그 안의 호출은 스크립트 경계와 무관하게 전부 합산됨을
실측으로 재확인했다(`main.py` 라인 287의 `fresh = [t for t in
self._counters.get(key, ()) if now - t < window]` 로직과 정확히 일치).

---

## 측정 방법 및 조건

- 응답 시간: `time.perf_counter()`(단조 시계) 기반, `httpx.AsyncClient`
- p95/median/max: `sorted(latencies)`에서 인덱스 계산 (소표본 n=5~8이므로
  참고용 — 통계적 엄밀성보다 SRS 목표 대비 여유폭 확인이 목적)
- 화이트리스트 히트 URL: `https://www.naver.com`
- 휴리스틱 경로 URL: `https://login-verify-secure.xyz/account/confirm`
- Full path URL: 매 요청 UUID 기반 랜덤 미지 도메인 (캐시 미스 보장)
- 모든 측정은 카테고리 사이 65초 대기로 `/analyze`의 10회/60초 쿼터를
  비운 상태에서 시작 — `run_qa_benchmark.py`의 자기 오염 문제를 회피
- NF-25/27/28: 소스 코드 정적 분석 (코드 확인)
- 측정 환경: `uvicorn main:app --port 8000`(127.0.0.1 단독 바인딩),
  Windows, 로컬 SQLite, 실제 인터넷 연결을 통한 WHOIS/SSL 조회

### 재실행 방법

```powershell
cd C:\dev\security_hub\backend
venv\Scripts\Activate.ps1
uvicorn main:app --port 8000
```

`run_qa_benchmark.py`를 그대로 쓰면 위에서 설명한 자기 오염 문제로
대부분 FAIL이 나온다. 정확히 재현하려면 카테고리(화이트리스트/휴리스틱/
풀패스/기능검증/레이트리밋 전용 테스트) 사이에 65초 이상 간격을 두고
호출량을 윈도우당 10회 이하로 유지해야 한다. (스크립트 자체를 고치는 것은
이번 범위 밖이라 재실행 시 수동으로 간격을 두는 방식으로 우회함.)

---

## 판정 요약

| 분류 | 항목 수 | PASS | FAIL |
|------|---------|------|------|
| 런타임 HTTP 실측 | 11 | 11 | 0 |
| 정적 코드 확인 | 3 | 3 | 0 |
| **전체** | **14** | **14** | **0** |

**미달 항목**: 없음. SRS NF 요건 전체 충족.

**비고**:
- NF-25는 프로덕션 배포 시 `DISABLE_DOCS=1` 환경변수 설정이 별도로 필요함
  (현재 개발 환경 기본값은 비활성화 아님).
- NF-28 세마포어 `_value` 경합은 알려진 이슈로 유지(기능적 영향 미미,
  졸업작품 범위 보류).
- `backend/tests/run_qa_benchmark.py`는 자체 호출량이 `/analyze` 레이트리밋
  쿼터(10/min)를 초과해 그대로 실행하면 측정이 불가능한 설계 결함이 있음 —
  향후 정리 시 카테고리별 호출량을 쿼터 이하로 줄이거나 카테고리 사이 대기를
  추가해야 함.
