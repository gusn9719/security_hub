# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## 프로젝트 개요

**AI기반 피싱 탐지 및 가상 환경 테스트 앱** — 한이음 ICT 드림업 2026 졸업 작품.
의심 문자/URL을 다신호 스코어링 파이프라인으로 분석해 `safe / suspicious / danger` 판정을 내리고, 가상 샌드박스(직접 탐방·AI 자동 테스트)를 제공하는 Flutter + FastAPI 앱.

- 레포 루트: `C:/dev/security_hub/`
- Flutter 루트: `frontend/`
- FastAPI 루트: `backend/`
- DB: `backend/security_hub.db` (SQLite, Git 제외)

---

## 실행 명령어

```powershell
# 백엔드 (venv 활성화 필요)
cd C:\dev\security_hub\backend
venv\Scripts\Activate.ps1
uvicorn main:app --reload --port 8000

# DB 마이그레이션 (스키마 변경 시)
cd C:\dev\security_hub
python data/scripts/migrate_db.py

# C-TAS 블랙리스트 CSV 적재 (최초 1회)
$env:PYTHONPATH = "C:\dev\security_hub\backend"
python data/scripts/load_ctas_csv.py --dir data/raw/

# Flutter
cd C:\dev\security_hub\frontend
flutter run
```

> Android 에뮬레이터에서 백엔드 주소: `http://10.0.2.2:8000`
> kasmweb HTTP 포트 6902 사용 시 `android:usesCleartextTraffic="true"` 필요.

## 테스트 실행

```powershell
# 단일 테스트 파일 실행
cd C:\dev\security_hub\backend
python -m pytest tests/test_domain_reputation.py -v

# 전체 테스트
python -m pytest tests/ -v
```

테스트 파일은 `backend/tests/`에 위치. `sys.path`에 `backend/`를 직접 추가하는 방식으로 모듈 임포트 (uvicorn 실행 환경과 동일).

---

## 아키텍처 불변 원칙

> 이 원칙들은 절대 바꾸지 않는다.

1. **Gemini는 7-B 요약자다.** `/analyze` 파이프라인에서 완전 제거 (DC-25). `gemini_service.py`는 7-B sandbox findings 자연어 요약에만 사용.
2. **SAFE는 화이트리스트 히트 단 하나의 경로뿐.** 휴리스틱 점수가 낮아도 SAFE 반환 불가 — 알 수 없음 = SUSPICIOUS (DC-06).
3. **설명 카드는 `EXPLANATION_DICT`에서만.** `explanation_service.py`의 딕셔너리 기반. LLM 즉석 생성 금지 (DC-25, 할루시네이션 방지).
4. **블랙리스트 히트 URL을 KISA 재신고하지 않는다.** 이미 신고된 URL — 논리적 모순.
5. **Gemini 모델은 `gemini-2.5-flash`만.** `gemini-2.0-flash`, `gemini-2.0-flash-lite`는 deprecated (2026-06-01 종료) — 사용 금지.

---

## 분석 파이프라인 (0~8단계, `analysis_service.py`)

Early Return 구조. 각 단계에서 확정 판정 시 즉시 반환.

| 단계 | 담당 모듈 | 동작 |
|------|-----------|------|
| 0 | `blacklist_service.extract_urls()` | URL 없음 → SUSPICIOUS |
| 1 | `url_validator.check_dangerous_scheme()` | `javascript:/data:/vbscript:/file:` → DANGER. ⚠️ SRS ANL-00에 `blob:` 추가 요구됨(미구현) |
| 2 | `url_expander.expand_url()` | 단축 URL 해제 (최대 3-hop, SSRF 방어) |
| 3 | `blacklist_service.check_blacklist()` | url_hash → domain → registered_domain 3단계 매칭 → DANGER |
| 4 | `whitelist_service.is_whitelisted()` | 히트 + 스푸핑 없음 → SAFE / 히트 + Open Redirect → SUSPICIOUS |
| 5~6 | `reputation_cache_service` / `domain_reputation_service` | WHOIS/SSL 조회 (캐시 TTL: 코드=**7일**, SRS DAT-03=24h — DC-15 반영 SRS 미업데이트) |
| 7 | `heuristic_scorer.score_url()` | 아래 시그널 가중합, score ≥ 60 → DANGER, ≥ 30 → SUSPICIOUS, < 30 → heuristic은 "SAFE"이나 DC-06에 의해 analysis_service가 SUSPICIOUS로 강제 |
| 8 | `explanation_service.build_explanation_cards()` | `ExplanationCard` 리스트 생성 |

**판정 레이블**: 코드 `danger/suspicious/safe` → UI `위험/의심/안전`

### 7단계 휴리스틱 시그널 (`heuristic_scorer.py` 실제 구현)

| 시그널 키 | 가중치 | 설명 |
|-----------|--------|------|
| `ip_in_url` | 35 | IP 주소 직접 접속 |
| `subdomain_spoofing` | 30 | naver.com.evil.kr 형태 서브도메인 위장 |
| `brand_keyword_mismatch` | 20 | 브랜드 키워드 있으나 공식 도메인 아님 |
| `homograph_idn` | 25 | 비ASCII 문자 혼용 (키릴/그리스 등) |
| `double_encoding` | 15 | %252F 등 이중 인코딩 우회 |
| `dangerous_extension` | 35 | .apk/.exe/.bat 등 악성 파일 직링크 |
| `suspicious_tld` | 10 | .xyz/.top/.club 등 피싱 다빈도 TLD |
| `excessive_subdomains` | 15 | 서브도메인 3레벨 이상 |
| `port_in_url` | 10 | 비표준 포트 명시 (80/443 제외) |
| `url_too_long` | 5 | URL 100자 초과 |
| `new_domain` *(domain_evidence)* | 20 | 도메인 등록 30일 이내 |
| `fresh_infrastructure` *(domain_evidence)* | 15 | 도메인 + SSL 모두 최신 |
| `whois_no_record` *(domain_evidence)* | 20 | WHOIS 레코드 없음 |

> **주의**: SRS ANL-07/컨텍스트 파일에 기술된 Levenshtein 기반 타이포스쿼팅 탐지는 현재 코드에 없음. 대신 `brand_keyword_mismatch`(브랜드 키워드 + 공식 도메인 비교)로 구현됨. `domain_similarity.py` 파일은 존재하나 파이프라인에 미연결.

---

## 디렉토리 구조

```
security_hub/
├── backend/
│   ├── main.py                  # FastAPI 진입점, 미들웨어, lifespan
│   ├── config.py                # 전역 상수 (SKIP_WHOIS_TLDS 등)
│   ├── routers/
│   │   ├── analyze.py           # POST /analyze
│   │   └── sandbox.py           # POST /sandbox/browse, DELETE ../{id}, POST /sandbox/auto-test
│   ├── schemas/
│   │   └── analysis.py          # AnalyzeRequest, AnalyzeResponse, ExplanationCard
│   ├── services/
│   │   ├── analysis_service.py  # 파이프라인 오케스트레이터 (핵심)
│   │   ├── url_validator.py     # 위험 스킴·IP URL·서브도메인 스푸핑·동형문자
│   │   ├── url_expander.py      # 단축 URL 해제
│   │   ├── heuristic_scorer.py  # 다신호 위험도 점수 계산
│   │   ├── explanation_service.py  # EXPLANATION_DICT 기반 카드 생성
│   │   ├── gemini_service.py    # 7-B findings 자연어 요약 전용
│   │   ├── domain_reputation_service.py  # WHOIS/SSL 실시간 조회
│   │   ├── reputation_cache_service.py   # domain_reputation_cache 읽기/쓰기
│   │   ├── browse_service.py    # 7-A: kasmweb/chromium 컨테이너 관리
│   │   └── sandbox_service.py   # 7-B: Browserless + Playwright 자동 분석
│   ├── database/
│   │   ├── db_init.py           # SQLite 연결 + 테이블 초기화
│   │   ├── blacklist_service.py # 블랙리스트 3단계 조회 + URL 추출
│   │   ├── whitelist_service.py # 화이트리스트 exact/suffix/pattern 매칭
│   │   ├── reputation_cache_service.py
│   │   └── vote_service.py      # url_votes 저장/집계
│   └── tests/
│       └── test_domain_reputation.py  # TC-ANL-01~10
├── frontend/
│   └── lib/
│       ├── models/analysis_result.dart
│       ├── services/api_service.dart
│       └── screens/
│           ├── home_screen.dart             # 클립보드 배너 포함
│           ├── sandbox_browse_screen.dart   # 7-A KasmVNC WebView + 세션 만료 처리
│           └── virtual_sandbox_screen.dart  # 7-B AI 자동 테스트 결과
└── data/
    └── scripts/
        ├── load_ctas_csv.py   # C-TAS CSV → blacklist DB 적재
        └── migrate_db.py      # DB 마이그레이션
```

---

## DB 스키마 요약

SQLite `backend/security_hub.db`. 커넥션은 읽기/쓰기 분리 (DC-17):
```python
read_conn.execute("PRAGMA query_only = ON")
write_conn.execute("PRAGMA journal_mode = WAL")
```

| 테이블 | 역할 | 주요 조회키 |
|--------|------|------------|
| `blacklist` | C-TAS 피싱 URL | `url_hash`, `domain`, `registered_domain` |
| `whitelist` | 안전 도메인 | `domain` (match_mode: exact/suffix/pattern) |
| `domain_reputation_cache` | WHOIS/SSL 캐시 (TTL 7일) | `registered_domain` |
| `url_votes` | 7-A 직접 탐방 후 투표 | `session_id` UNIQUE (중복 방지) |
| `sandbox_results` | 7-A/7-B 세션 결과 (TTL 24h) | `url_hash`, `session_id` |

`url_hash`는 더블 디코딩 + IDN→ASCII + 쿼리스트링 제거 후 SHA256. `load_ctas_csv.py`와 `blacklist_service.py`가 동일 정규화 로직을 반드시 공유해야 함.

---

## 가상 샌드박스

| | 7-A 직접 탐방 | 7-B AI 자동 테스트 |
|--|--|--|
| Docker 이미지 | `kasmweb/chromium:1.14.0` | `ghcr.io/browserless/chromium` |
| 포트 | HTTP 6902 (noVNC) | WebSocket CDP |
| Flutter | WebView로 noVNC URL 로드 | 결과 화면만 표시 |
| Gemini | 미사용 | findings 요약만 |
| 투표 | 세션 종료 후 danger/safe 수집 | 미수집 |

컨테이너 생성 시 UUID 랜덤 VNC_PW + `127.0.0.1` 바인딩 필수 (DC-27).

---

## 코딩 규칙

- **Dart**: `camelCase` (변수/함수), `PascalCase` (클래스/Widget/Enum)
- **Python**: `snake_case` (변수/함수), `PascalCase` (클래스/Pydantic 모델)
- 모든 외부 통신(Gemini, DB, URL 해제, WHOIS)은 `try-catch` + 폴백 처리
- DB 조회 실패 → SUSPICIOUS 반환 (보수적 폴백)
- Gemini 실패 → findings 목록 그대로 노출 (서비스 중단 없음)
- `mounted` 체크: 비동기 완료 후 위젯 소멸 시 `setState` 방지
- 설계 변경 시 DC 로그(docs/CLAUDE_CONTEXT_v0507.md §16) 기록 필수
- 새 기능은 TC 먼저 작성 (TC-First)
- PowerShell 환경: 터미널 명령어는 PowerShell 문법 사용

---

## 보안 미들웨어 (`main.py`)

1. `BlockDangerousMethodsMiddleware` — TRACE/CONNECT/TRACK 405 차단
2. `SecurityHeadersMiddleware` — `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Content-Security-Policy` 주입 (noVNC 경로 `/sandbox/browse/`는 CSP·X-Frame-Options 제외)
3. 전역 예외 핸들러 — 스택 트레이스 클라이언트 미노출

**SRS 대비 미구현 보안 요구사항 (Sprint 8 전 완료 필요):**

| 요구사항 ID | 내용 | 비고 |
|-------------|------|------|
| NF-12 | `Cache-Control: no-store` 응답 헤더 추가 | `SecurityHeadersMiddleware`에 누락 |
| NF-24 | API Rate Limiting — `/analyze` IP당 10회/분, `/sandbox/browse` 5회/분, 초과 시 HTTP 429 | 미구현 |
| NF-25 | `/docs`, `/redoc`, `/openapi.json` 프로덕션에서 404 반환 (Server 헤더 제거 포함) | FastAPI 기본 노출 중 |
| ANL-00 | `blob:` 스킴 → DANGER 처리 | `url_validator.py` DANGEROUS_SCHEMES에 미추가 |

---

## 환경 변수

`backend/.env` (Git 제외):
```
GEMINI_API_KEY=...
```

---

## 현재 스프린트 상태 (2026-05-07 기준)

- **Sprint 5E 완료**: 파이프라인 0~8단계 확정, 보안 미들웨어, 클립보드 배너, Kasm 세션 만료 처리
- **Sprint 6 진행 중**: DANGER 액션 버튼(url_launcher), 발신번호 차단(ACT-01 미구현), 결과 공유 미완
- **Sprint 7 진행 중**: 7-A/7-B 샌드박스 기본 구현 완료, 투표 모달 + /votes 엔드포인트 + E2E 검증 미완
- **미구현 SRS 항목**: NF-24(Rate Limiting), NF-12(Cache-Control), NF-25(API docs 비활성화), ANL-00(`blob:` 스킴), ACT-01(발신번호 차단), INP-04(SMS 직접 읽기), INP-05(수신 알림)
- **W10~W11 (6월)**: 신규 개발 없음, 심사 준비만

전체 맥락은 `docs/CLAUDE_CONTEXT_v0507.md` 참조.
