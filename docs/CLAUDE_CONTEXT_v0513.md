# Security Hub — CLAUDE_CONTEXT v0513

> 새 대화 시작 시 본 파일을 첨부하여 프로젝트 전체 맥락을 전달한다.
> v0507 이후 변경 사항을 모두 반영했으며, SRS v10 / CLAUDE.md와 일관성 유지.

---

## 0. 문서 정보

| 항목 | 내용 |
|------|------|
| 문서명 | CLAUDE_CONTEXT |
| 버전 | v0513 (2026-05-13) |
| 이전 버전 | v0507 (2026-05-07) |
| 대상 SRS | v10 (`security_hub_srs_v10.xlsx`) |
| 대상 CLAUDE.md | 2026-05-13 갱신본 |
| 다음 갱신 시점 | W8 (5/24 전후) 또는 큰 결정 발생 시 |

---

## 1. 프로젝트 정체성

**이 프로젝트는 단순 피싱 차단 도구가 아니다.**

> **사용자 즉각 피드백 기반 학습형 위협 인텔리전스 시스템**
>
> KISA C-TAS가 못 잡은 신규 위협을 사용자 집단지성(7-A 직접 탐방 + 투표)으로 발견하고, 그 결과가 다음 분석에 즉시 반영되는 피드백 순환 구조를 가진다.

이 정체성이 모든 정책 결정의 출발점이다.

| 기존 사고 | 우리 사고 |
|----------|----------|
| 위험은 무조건 차단 | 명백한 위험만 차단, 애매하면 격리 체험 권유 |
| 사용자 투표는 부가 기능 | 투표가 시스템 학습 메커니즘 그 자체 |
| 단일 호스트 처리 막연히 | 분석 vs 샌드박스 병목 명확히 분리 |

### 1-1. 차별화 시연 시나리오

1. evil-bank.kr 분석 → SUSPICIOUS (휴리스틱 점수 35)
2. 7-A 진입 → 5초 둘러보고 "danger 투표"
3. 같은 URL 재분석 → DANGER (점수 70, prior_danger_vote 시그널 발동)

**30초 데모로 "시간이 지날수록 시스템이 학습한다" 증명**. 단순 블랙리스트 매칭 앱과 결정적으로 다른 지점.

---

## 2. 기술 스택

| 레이어 | 기술 |
|--------|------|
| 프론트엔드 | Flutter (Android only, APK 직배포, minSdkVersion=21) |
| 백엔드 | Python FastAPI + Uvicorn |
| AI | Google Gemini 2.5 Flash (7-B findings 요약 전용) |
| DB | SQLite (`backend/security_hub.db`, WAL 모드) |
| 7-A 샌드박스 | kasmweb/chromium:1.14.0 (사용자 직접 탐방, noVNC) |
| 7-B 샌드박스 | Browserless + Playwright (AI 자동 테스트) |
| 개발 환경 | Windows PowerShell, Python 3.14, `backend/venv/` |

---

## 3. 아키텍처 불변 원칙

**절대 바꾸지 않는다.**

1. **Gemini는 7-B 요약자다.** `/analyze` 파이프라인에서 완전 제거됨 (DC-25). `gemini_service.py`는 7-B sandbox findings 자연어 요약에만 사용.
2. **SAFE는 화이트리스트 히트 단 하나의 경로뿐.** 휴리스틱 점수가 낮아도 SAFE 반환 불가 — 알 수 없음 = SUSPICIOUS (DC-06).
3. **판정 설명 카드는 EXPLANATION_DICT에서만.** LLM 즉석 생성 금지 (DC-25, 할루시네이션 방지).
4. **블랙리스트 히트 URL은 KISA 재신고하지 않는다.** 이미 신고된 URL — 논리적 모순.
5. **Gemini 모델은 `gemini-2.5-flash`만.** 2.0 시리즈는 deprecated.
6. **'공식 사이트로 이동' 버튼 없다.** 화이트리스트 오매핑 시 앱이 피해 공모 방지 (DC-01).

---

## 4. 분석 파이프라인 (0~8단계)

Early Return 구조. 각 단계에서 확정 판정 시 즉시 반환.

| 단계 | 담당 | 동작 |
|------|------|------|
| 0 | `url_validator.check_dangerous_scheme()` | 위험 스킴 (javascript:/file://`/data:/vbscript:/blob:`) → DANGER |
| 1 | `url_validator.normalize_url()` | URL 추출 + 더블 디코딩 + IDN → ASCII + 쿼리 제거 |
| 2 | `url_expander.expand_url()` | 단축 URL 해제 (최대 3-hop, SSRF 방어) |
| 3 | `blacklist_service.check_blacklist()` | url_hash → domain → registered_domain 3단계 매칭 → DANGER |
| 4 | `whitelist_service.is_whitelisted()` | 히트 + 스푸핑 없음 → SAFE / 위험 쿼리 → SUSPICIOUS |
| 5 | `domain_similarity.py` (연결 필요) | Levenshtein 유사도 검사 |
| 6 | `domain_reputation_service` | WHOIS/SSL 조회 (캐시 TTL 7일) |
| 7 | `heuristic_scorer.score_url()` | 다신호 가중합. **score ≥ 70 → DANGER (v0513 임계값 상향)** |
| 8 | `explanation_service.build_explanation_cards()` | 카드 리스트 생성 |

**판정 레이블**: 코드 `danger/suspicious/safe` → UI `위험/의심/안전`

### 4-1. 휴리스틱 시그널 가중치 (`heuristic_scorer.py`)

| 시그널 | 가중치 |
|--------|--------|
| ip_in_url | +35 |
| dangerous_extension | +35 |
| subdomain_spoofing | +30 |
| homograph_idn | +25 |
| brand_keyword_mismatch | +20 |
| new_domain (≤30일) | +20 |
| whois_no_record | +20 |
| double_encoding | +15 |
| excessive_subdomains | +15 |
| fresh_infrastructure | +15 |
| suspicious_tld | +10 |
| port_in_url | +10 |
| url_too_long | +5 |
| **typosquat (Levenshtein, ANL-06)** | **+35** ← 파이프라인 연결 필요 |
| **prior_danger_vote_low (3-9건)** | **+20** ← v0513 신규 |
| **prior_danger_vote_high (10건+)** | **+35** ← v0513 신규 |
| **sandbox_score_high (≥70)** | **+30** ← v0513 신규 |

### 4-2. 임계값 (v0513 변경)

```
score ≥ 70 → DANGER  (v0507까지 60 → v0513 상향)
score ≥ 30 → SUSPICIOUS
score < 30 → "SAFE" 반환되지만 DC-06에 의해 analysis_service가 SUSPICIOUS 강제
```

**임계값 상향 사유**: 휴리스틱 단독 차단의 정확도 부담 완화. 우리 강점인 격리 샌드박스 체험을 통한 사용자 학습 권유 폭 확대. 시그널 단독으로는 DANGER 도달 불가, 2~3개 조합 필요.

---

## 5. DB 스키마

### 5-1. 현재 운영 중 (그대로 유지)

| 테이블 | 역할 | 주요 키 |
|--------|------|---------|
| `blacklist` | C-TAS 피싱 URL | url_hash, domain, registered_domain |
| `whitelist` | 안전 도메인 | domain (match_mode: exact/suffix) |
| `domain_reputation_cache` | WHOIS/SSL 캐시 (TTL 7일) | registered_domain |

### 5-2. 재설계 / 신규 (v0513 결정)

#### `sandbox_results` — 재설계 (DAT-04, DC-33)

```sql
session_id          TEXT PRIMARY KEY              -- v0507: url_hash UNIQUE → 변경
url                 TEXT NOT NULL
domain              TEXT NOT NULL
registered_domain   TEXT
url_hash            TEXT NOT NULL                 -- UNIQUE 제거
mode                TEXT NOT NULL CHECK(mode IN ('7a','7b'))  -- 신규
final_url           TEXT
redirect_count      INTEGER DEFAULT 0
error               TEXT
screenshot_paths    TEXT                          -- JSON 배열
visited_urls        TEXT                          -- 7-A CDP navigation JSON, 신규
sandbox_score       INTEGER                       -- 7-A는 NULL
findings_json       TEXT NOT NULL DEFAULT '[]'
summary             TEXT
created_at          TEXT NOT NULL
expired_at          TEXT NOT NULL                 -- TTL: 24시간
```

핵심 변경: url_hash UNIQUE 제거 (같은 URL 동시 세션 허용), session_id PK, mode 컬럼.

#### `url_votes` — 재설계 (DAT-05, DC-30)

```sql
id                  INTEGER PRIMARY KEY AUTOINCREMENT
session_id          TEXT NOT NULL UNIQUE          -- FK 제거, NOT NULL만 유지
device_uuid         TEXT NOT NULL                 -- 신규 (NF-30 식별 시스템)
url                 TEXT NOT NULL
domain              TEXT NOT NULL
registered_domain   TEXT
vote                TEXT NOT NULL CHECK(vote IN ('danger','safe'))
voted_at            TEXT NOT NULL
UNIQUE(device_uuid, registered_domain)            -- 신규: 1기기 1표 (어그로 방어 Layer 1)
```

핵심 변경: device_uuid 도입, 복합 UNIQUE 제약. session_id FK 제거 사유 — sandbox_results 24h 만료와 url_votes 영구 보존의 충돌 회피.

#### `analysis_history` — 신규 (DAT-06, DC-31)

```sql
id                INTEGER PK AUTOINCREMENT
url_hash          TEXT NOT NULL
url               TEXT NOT NULL
registered_domain TEXT
verdict           TEXT NOT NULL CHECK(verdict IN ('danger','suspicious','safe'))
triggered_signals TEXT                  -- JSON 배열
heuristic_score   INTEGER
prior_vote_danger INTEGER DEFAULT 0
prior_vote_safe   INTEGER DEFAULT 0
response_time_ms  INTEGER
device_uuid       TEXT
analyzed_at       TEXT NOT NULL
```

목적: 정량 지표 측정(탐지율·오탐률·p95) + 시그널 정확도 평가 + 신규 위협 후보 발굴. FastAPI BackgroundTasks로 비동기 INSERT.

### 5-3. 동시성 (v0513 신규, NF-27)

```python
# db_init.py 초기화 시
PRAGMA journal_mode = WAL
PRAGMA busy_timeout = 5000
PRAGMA synchronous = NORMAL

# 모든 INSERT/UPDATE에 적용
@with_retry(max_attempts=3, delay_ms=100, backoff=2)
```

---

## 6. 가상 샌드박스

| | 7-A 직접 탐방 | 7-B AI 자동 테스트 |
|--|--|--|
| 이미지 | kasmweb/chromium:1.14.0 | ghcr.io/browserless/chromium |
| 포트 | HTTP 6902 (noVNC) | WebSocket CDP |
| Flutter | WebView로 noVNC URL 로드 | 결과 화면만 표시 |
| Gemini | 미사용 | findings 요약만 |
| 투표 | 세션 종료 후 양방향 수집 | 미수집 |
| **동시 한계 (신규)** | **4세션** | **3세션** |
| 한계 초과 | 503 + Retry-After: 30 | 동일 |

### 6-1. 7-A 서버사이드 강화 (DC-34, W7 본격 착수)

**Tier 1 (CDP 활용 가능 시)**:
- CDP `Page.frameNavigated` 구독 → visited_urls 전수 기록
- `Page.downloadWillBegin` 감지 → 컨테이너 즉시 종료
- 60초 체류 OR 3페이지 이상 방문 → 의견 묻기 모달
- navigation URL 매번 blacklist 재매칭

**Tier 0 (CDP 불가 시)**:
- 시작 URL만 기록
- 다운로드 디렉토리 read-only 마운트
- 절대 5분 타임아웃 + 정적 경고 배너

**5/14 오전 30분 CDP 검증으로 Tier 1/0 분기 결정.**

---

## 7. 핵심 정책 결정 (v0513)

### 7-1. 1종/2종 오류 정책

| | 우선순위 | 위치 |
|--|---------|------|
| 1종 오류 (위험→SAFE) | 최우선 회피 | SAFE는 화이트리스트 단독 경로만 |
| 2종 오류 (안전→DANGER) | 차순위 | DANGER 임계값 70으로 상향, 샌드박스 체험 권유 |

→ **결과**: SAFE 경로가 좁아서 1종 오류 가능성 구조적으로 최소화.

### 7-2. 어그로 방어 4중 (NF-29, DC-35)

```
Layer 1 (DB)    : (device_uuid, registered_domain) UNIQUE
Layer 2 (Logic) : safe_count > danger_count 시 시그널 미발동
Layer 3 (UX)    : 7-A 세션 30초 체류 + (CDP 시) navigation 1회 이상
Layer 4 (Score) : prior_danger_vote_high +35로 제한 (단독 DANGER 불가)
```

우회 비용: 100표 만들려면 100대 기기 + 100개 7-A 세션 → 1시간 15분 이상 소요.

### 7-3. UUID vs 회원가입 (NF-30)

**UUID 단독 채택**. 회원가입 미도입.

- 식별 단위: device_uuid (Flutter SharedPreferences 영구 저장)
- 헤더 `X-Device-UUID` 강제 (누락 시 401)
- Rate limiting: device_uuid 기반 (CGNAT 환경에서 IP는 무의미)
- UUID 재설치 우회는 의도된 한계 — 식별 목적이지 신뢰 목적이 아님
- 진짜 신뢰는 7-A 컨테이너 자원 한계(NF-28)와 session_id UNIQUE 제약이 만들어냄

### 7-4. 동시 처리 한계

| 엔드포인트 | RPS / 동시 한계 | 병목 |
|-----------|----------------|------|
| /analyze | RPS 150 / 동시 100명 | DB 조회 (캐시 히트 80% 가정) |
| /sandbox/browse (7-A) | 동시 4세션 | RAM (512MB × 4 = 2GB) |
| /sandbox/run (7-B) | 동시 3세션 | RAM (300MB × 3 = 0.9GB) |
| /votes | device_uuid당 분당 20건 | 메모리 rate limiter |

본격 운영 시 마이그레이션 경로: SQLite → PostgreSQL, 컨테이너 → Kubernetes, rate limiter → Redis.

---

## 8. 일정·진행 상태

### 8-1. 현재 시점 (2026-05-13)

- **현재 주차**: W7
- **Sprint 5E**: 완료 (파이프라인 0~8단계, 보안 미들웨어, 클립보드 배너, Kasm 세션 만료)
- **Sprint 6**: 진행 중 (DANGER 액션 url_launcher, 결과 공유)
- **Sprint 7**: 핵심 진행 중 (7-A/7-B 기본 완료, 투표 + /votes + E2E 미완)
- **Sprint 8**: 보안 강화 (NF-12 Cache-Control / NF-24 Rate Limiting / NF-25 API docs 비활성화)

### 8-2. 0518까지 5일 계획 (5/13~5/17)

| 일자 | 작업 |
|------|------|
| 5/13 (오늘) | DB 스키마 확정, /votes API 스펙 확정, SRS v10 작성 완료 |
| **5/14 오전** | **CDP 검증 (30분) → Tier 1/0 분기 확정** |
| 5/14 오후 | `migrate_db.py` 작성 + url_votes/sandbox_results/analysis_history DROP & RECREATE. UUID 미들웨어 + 메모리 rate limiter |
| 5/14 야간 | SQLite WAL + busy_timeout + write retry 데코레이터 (NF-27) |
| 5/15 | `/votes` 엔드포인트 + Flutter 투표 모달 + `domain_similarity` 파이프라인 연결 + `typosquat` 카드 + prior_danger_vote 시그널 연결 |
| 5/15 야간 | analysis_history 비동기 INSERT (BackgroundTasks) |
| 5/16 | `blob:` 스킴 + Cache-Control: no-store + API docs 비활성화 (NF-12, NF-25, ANL-00 마무리) |
| 5/17 | ERD + 시스템 구성도 + SRS v11 (필요 시) + CLAUDE.md 동기화 |

### 8-3. 0518 이후 큰 그림

| 주차 | 핵심 작업 |
|------|----------|
| W7 (5/18~5/24) | 7-A CDP navigation 추적, 다운로드 차단, 위험 navigation 차단 (Tier 1) |
| W8 (5/25~5/31) | 7-B 결과 화면 마무리, sandbox_score 룰 확정, E2E #3 |
| W9 (6/1~6/7) | 전체 E2E, 버그 수정, 시연 시나리오 준비 |
| W10~W11 (6월) | 신규 개발 없음, 심사 준비만 |

---

## 9. 미구현 SRS 항목

### 9-1. P0 (0518까지 마무리 필요)

| ID | 내용 | 일정 |
|----|------|------|
| ANL-00 | `blob:` 스킴 DANGER 처리 | 5/16 |
| ANL-06 | Levenshtein 유사도 파이프라인 연결 | 5/15 |
| ANL-10 | prior_danger_vote 시그널 연결 | 5/15 |
| DAT-04 | sandbox_results 재설계 마이그레이션 | 5/14 |
| DAT-05 | url_votes 재설계 마이그레이션 | 5/14 |
| DAT-06 | analysis_history 신설 + BackgroundTasks | 5/15 |
| SBX-03 | /votes 엔드포인트 + Flutter 모달 | 5/15 |
| SBX-04 | 샌드박스 동시 한계 (asyncio.Semaphore) | 5/14 |
| NF-12 | `Cache-Control: no-store` 추가 | 5/16 |
| NF-24 | API Rate Limiting (device_uuid 기반) | 5/14 |
| NF-25 | API docs 비활성화 + Server 헤더 제거 | 5/16 |
| NF-27 | SQLite WAL + busy_timeout + retry | 5/14 |
| NF-28 | 샌드박스 동시 한계 구현 | 5/14 |
| NF-29 | 어그로 방어 4중 구현 | 5/15 |
| NF-30 | device_uuid 미들웨어 + Flutter 발급 | 5/14 |

### 9-2. P1 (W7~W8)

| ID | 내용 |
|----|------|
| SBX-01 | 7-A CDP navigation 추적 (Tier 1) |
| ANL-11 | sandbox_score 피드백 시그널 |
| ACT-01 | 발신번호 차단 (url_launcher) |

### 9-3. P2 (졸업 작품 범위 외)

| ID | 내용 |
|----|------|
| INP-04 | 문자 직접 읽어오기 (READ_SMS 권한) |
| INP-05 | 문자 수신 알림 감지 (RECEIVE_SMS 권한) |

---

## 10. v0507 이후 DC 로그 신규 (DC-30~35)

| DC | 결정 | 영향 |
|----|------|------|
| **DC-30** | ANL-10 신설 — url_votes를 휴리스틱 시그널로 연결 | 우리 앱의 핵심 차별화 메커니즘 (피드백 순환) |
| **DC-31** | ANL-11 (sandbox_score 시그널) + DAT-06 (analysis_history) 신설 | 샌드박스 피드백 순환 완성 + 정량 지표 인프라 |
| **DC-32** | 동시 처리 구조 도입 (WAL + Semaphore + device_uuid rate limit) | CGNAT 환경 대응, 호스트 자원 보호 |
| **DC-33** | sandbox_results 재설계 (session_id PK, mode 컬럼, url_hash UNIQUE 제거) | 동시 세션 충돌 해소 |
| **DC-34** | 7-A 서버사이드 강화 (CDP Tier 1/0 분기) | navigation 추적 + 다운로드 차단 + 의견 묻기 모달 |
| **DC-35** | 어그로 방어 4중 (UNIQUE + safe 가드 + 30초 체류 + 가중치 상한) | 투표 신뢰성 확보 |

전체 DC 로그(DC-001 ~ DC-35)는 `security_hub_srs_v10.xlsx` 「설계변경이력」 시트 참조.

---

## 11. Open Questions

### 11-1. v0507에서 해소된 것

- ~~Q-12: UUID vs 회원가입~~ → UUID 단독 채택 (NF-30, DC-32)
- ~~Q-13: 동시 사용자 처리 정책~~ → asyncio.Semaphore + SQLite WAL (NF-27, NF-28)
- ~~Q-14: 투표 신뢰성 구조~~ → 4중 방어 (NF-29, DC-35)

### 11-2. v0513 신규 / 미해소

| ID | 질문 | 상태 |
|----|------|------|
| Q-15 | kasmweb 1.14.0이 외부에서 `--remote-debugging-port` 인자 받을 수 있나? | 5/14 오전 검증 |
| Q-16 | CDP가 동작해도 호스트 → 컨테이너 CDP 접근 시 보안 격리 어떻게? | W7 검토 |
| Q-17 | Levenshtein 시그널 가중치 +35 → 단독으로 DANGER 못 만들지만, 다른 시그널 1개와 조합 시 너무 쉽게 70 도달? | 5/17 회귀 테스트로 검증 |
| Q-18 | analysis_history 데이터 양 — 1년 1GB 가정, 실제 시연 환경에서 증가 속도는? | W8 실측 |

---

## 12. 코딩 규칙

- **Dart**: camelCase / **Python**: snake_case
- 모든 외부 통신(Gemini, DB, URL 해제, WHOIS)에 try-catch + 폴백
- DB 조회 실패 → SUSPICIOUS 폴백 (보수적, SAFE 절대 금지)
- 비동기 완료 후 `mounted` 체크 (Flutter)
- 설계 변경 시 DC 로그 기록 필수 (SRS 「설계변경이력」 시트)
- 새 기능은 TC 먼저 작성 (TC-First, SRS 「테스트케이스」 시트)
- PowerShell 환경: 터미널 명령어는 PowerShell 문법 사용
- 부분 수정이 아닌, 복사해서 덮어쓸 수 있는 완전한 코드 블록 제공
- 패키지 추가 시 설치 명령어(`flutter pub add` / `pip install`) 함께 제공

---

## 13. 산출물 위치

| 파일 | 역할 |
|------|------|
| `security_hub_srs_v10.xlsx` | 요구사항 명세 + DC 로그 + TC (진실의 출처) |
| `CLAUDE_CONTEXT_v0513.md` | 본 문서 — 새 대화 시작 시 첨부 |
| `CLAUDE.md` (코드 작업용) | 코드 작업 즉시 참조용 빠른 가이드 |
| `backend/security_hub.db` | SQLite (Git 제외) |
| `data/scripts/migrate_db.py` | DB 마이그레이션 (5/14 작성 예정) |

---

## 14. 다음 단계

**즉시 (다음 응답)**:
- CLAUDE.md 갱신 — 신규 시그널 가중치, DB 스키마 재설계 반영, 미구현 SRS 항목 갱신

**5/14 클로드 코드 작업 지시서**:
1. CDP 검증 (30분, Tier 1/0 분기 결정)
2. `migrate_db.py` 작성 (url_votes/sandbox_results/analysis_history)
3. UUID 미들웨어 + 메모리 rate limiter
4. SQLite WAL + busy_timeout + with_retry 데코레이터

**김검수 시각 자동 적용 항목** (모든 응답에서):
- 예외 처리, 경계값, 폴백, 보안, 자원 관리, TC 완결성, 설계 근거 7개 체크리스트
- 어그로 방어 / SAFE 경로 좁힘 / 임계값 70 적용 일관성 확인

---

**문서 끝.** 본 컨텍스트로 새 대화 시 SRS v10 + CLAUDE.md와 함께 첨부 권장.
