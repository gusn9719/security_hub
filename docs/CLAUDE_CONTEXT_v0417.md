# CLAUDE_CONTEXT.md — Security Hub
# AI기반 피싱 탐지 및 가상 환경 테스트 앱 | 한이음 ICT 드림업 2026
# 마지막 업데이트: 2026-04-17 (v7 — DB 스키마 최적화, 판정 레이블 한글화, 쿼리패턴 통합, DC-13~15 추가)
# 새 대화 시작 시 이 파일을 첨부하여 컨텍스트를 유지한다.

---

## 1. 프로젝트 개요

| 항목 | 내용 |
|------|------|
| **프로젝트명** | AI기반 피싱 탐지 및 가상 환경 테스트 앱 |
| **성격** | 한이음 ICT 드림업 2026 졸업 작품 (실제 심사 대상) |
| **핵심 목표** | 의심 문자/URL → DB 기반 필터링 → 안전/의심/위험 판정 → 가상환경 테스트 제공 |
| **앱명** | `security_hub` (pubspec.yaml 기준) |
| **프로젝트 루트** | `C:/dev/security_hub/` |
| **현재 주차** | W3 (Sprint 5C 착수) — 2026-04-13~19 |

---

## 2. 기술 스택

| 레이어 | 기술 | 역할 |
|--------|------|------|
| 프론트엔드 | Flutter (Dart) | 모바일 UX, 신호등 UI, 결과 화면 |
| 백엔드 | Python 3.14 + FastAPI + Uvicorn | API 서버, 분석 파이프라인 |
| AI | Gemini 2.5 Flash (`google-genai` SDK) | evidence → 사용자 언어 번역만 (판정 불가) |
| 격리 환경 | Playwright (Chromium headless) | 가상 샌드박스 |
| DB | SQLite (`backend/security_hub.db`) | 블랙리스트 / 화이트리스트 / 캐시 |

### 패키지 현황

**Flutter (pubspec.yaml)**
- `cupertino_icons ^1.0.8`
- `http 1.6.0`
- `url_launcher 6.3.2`

**Python (requirements.txt)**
- `fastapi==0.135.2`, `uvicorn[standard]==0.42.0`, `pydantic==2.7.4`
- `python-dotenv==1.0.1`
- `google-genai` (신규 SDK — `google-generativeai`는 deprecated)
- `requests` (단축 URL 해제)
- `python-Levenshtein` (도메인 유사도 — Sprint 5C 추가 예정)

### Gemini 모델

- 사용 모델: `gemini-2.5-flash` — 유료 계정, 성능·비용 균형 최적
- ⚠️ `gemini-2.0-flash`, `gemini-2.0-flash-lite` — deprecated, 2026-06-01 완전 종료. **사용 금지.**

---

## 3. 아키텍처 불변 원칙

> 이 원칙들은 어떤 상황에서도 바꾸지 않는다. 설계 변경 요청이 와도 이 원칙에 위배되면 거부한다.

1. **Gemini는 번역자다.** 판정 권한 없음. 파이프라인이 생성한 `evidence` dict를 사용자 언어로 다듬는 역할만.
2. **모르면 무조건 의심.** 블랙/화이트 모두 미스인 URL은 판정 없이 의심 반환.
3. **블랙리스트 히트 URL을 KISA에 재신고하지 않는다.** 이미 신고된 URL — 논리적 모순.
4. **안전 화면에서 "공식 사이트로 이동" 버튼을 만들지 않는다.** 오매핑 시 앱이 피해에 공모.
5. **Gemini 호출 최소화.** 안전 = 미호출, 위험 = evidence 번역, 의심 = 캐시 미스 시만 호출.

### 판정 레이블 정책

| 코드 내부 (Enum/API) | UI 표시 / 문서 | 신호등 |
|---------------------|--------------|--------|
| `danger` | 위험 | 빨강 |
| `suspicious` | 의심 | 노랑 |
| `safe` | 안전 | 초록 |

> 코드 내부 enum 값과 API 필드는 영어 소문자 유지 (Dart/Python 관례). UI 문자열과 문서 레이블만 한글 사용.

---

## 4. 코딩 규칙

### 4-1. 디렉토리 구조

**Flutter**
```
lib/
├── main.dart                        # 앱 진입점, HomeScreen
├── models/
│   └── analysis_result.dart         # AnalysisResult, RiskStatus
├── services/
│   └── api_service.dart             # 백엔드 HTTP 통신
├── screens/
│   └── virtual_sandbox_screen.dart  # 가상환경 화면 (Sprint 7)
└── widgets/
    └── traffic_light.dart           # 신호등 위젯
```

**Python 백엔드**
```
backend/
├── main.py                      # FastAPI 진입점, CORS, lifespan DB init
├── routers/
│   └── analyze.py               # POST /analyze
├── schemas/
│   └── analysis.py              # Pydantic 요청/응답 스키마
├── services/
│   ├── analysis_service.py      # 파이프라인 오케스트레이터 (Early Return)
│   ├── url_expander.py          # 단축 URL 해제
│   ├── gemini_service.py        # evidence → 사용자 언어 번역
│   └── domain_similarity.py     # Levenshtein 유사도 (Sprint 5C)
├── database/
│   ├── db_init.py               # SQLite 연결 + 테이블 초기화
│   ├── blacklist_service.py     # 블랙리스트 조회
│   ├── whitelist_service.py     # 화이트리스트 조회 + 쿼리스트링 패턴
│   └── cache_service.py         # suspicious_cache (Sprint 5C)
├── scripts/
│   ├── load_ctas_csv.py
│   └── load_whitelist_csv.py
├── data/                        # C-TAS CSV (Git 제외)
├── security_hub.db              # SQLite DB (Git 제외)
├── .env                         # GEMINI_API_KEY (Git 제외)
└── requirements.txt
```

### 4-2. 명명 규칙
- Dart: `camelCase` (변수/함수), `PascalCase` (클래스/Widget/Enum)
- Python: `snake_case` (변수/함수), `PascalCase` (클래스/Pydantic 모델)
- 이름만 보고 역할을 알 수 있어야 한다: `_buildTrafficLight()` ✅ / `_build1()` ❌

### 4-3. 방어적 프로그래밍 (필수)
- 모든 외부 통신(Gemini, DB, URL 해제)은 `try-catch` + 폴백 처리.
- 빈 입력값은 서버 전송 전에 프론트에서 먼저 차단.
- `mounted` 체크: 비동기 완료 후 위젯 소멸 시 setState 방지.
- DB 조회 실패 → SUSPICIOUS 반환 (안전 쪽으로 폴백).
- Gemini 실패 → evidence 기반 템플릿 폴백 (서비스 중단 없음).
- DB 커넥션: 읽기전용(분석용) / 쓰기(캐시·신고 적재) 분리.

### 4-4. 문서화
- 핵심 클래스·함수 상단에 Docstring 필수.
- TODO 형식: `// TODO: [스프린트명] 설명`
- 코드 섹션 구분: `// ===` 구분선 사용

### 4-5. 개발 프로세스
- **TC-First**: 새 기능 코드 전에 TC를 먼저 작성한다.
- **DC 로그 원칙**: 설계가 바뀌면 반드시 이유를 DC 로그로 기록한다. 이유 없는 변경은 없다.
- **코드 제공**: 부분 수정이 아닌, 복사해서 덮어쓸 수 있는 완전한 코드 블록으로 제공.
- **패키지 추가 시**: `flutter pub add` / `pip install` 명령어 함께 제공.
- **PowerShell 환경**: 모든 터미널 명령어는 PowerShell 문법으로 제공.

---

## 5. 서버 실행 명령어

```powershell
# 백엔드 (venv 활성화 상태)
cd C:\dev\security_hub\backend
venv\Scripts\Activate.ps1
uvicorn main:app --reload --port 8000

# CSV 적재 (최초 1회)
$env:PYTHONPATH = "C:\dev\security_hub\backend"
python scripts/load_ctas_csv.py --dir data/

# Flutter
cd C:\dev\security_hub
flutter run
```

> ⚠️ 에뮬레이터 → 백엔드 주소: `http://10.0.2.2:8000`
> ⚠️ PowerShell 한글 인코딩 이슈: 터미널에서 깨져 보여도 실제 데이터는 정상.

---

## 6. 색상 팔레트

| 상태 | Primary | Background | Border |
|------|---------|-----------|--------|
| 안전 (Safe) | `#0F9B58` | `#ECFDF5` | `#6EE7B7` |
| 의심 (Suspicious) | `#D97706` | `#FFFBEB` | `#FCD34D` |
| 위험 (Danger) | `#DC2626` | `#FEF2F2` | `#FCA5A5` |
| 앱 Primary | `#1A56DB` | `#F8F9FC` | `#E5E7EB` |

---

## 7. 분석 파이프라인 (Early Return)

### 핵심 흐름

```
[1단계] 단축 URL 해제  ✅ Sprint 5A
    requests.head(), User-Agent 설정, timeout 5초, 1회만
    실패 시 → 원본 URL 그대로 2단계로

[2단계] 블랙리스트 매칭  ✅ Sprint 4
    1차: url_hash SHA256 정확 일치 (O(1))
    2차: domain 일치
    히트 → 위험 + evidence 생성 + Gemini 번역. 종료.

[3단계] 화이트리스트 매칭  ✅ Sprint 5A / 5C 확장
    exact / suffix / pattern 3모드
    히트 + SUSPICIOUS_QUERY_PATTERNS 없음 → 안전. Gemini 미호출. 종료.
    히트 + SUSPICIOUS_QUERY_PATTERNS 감지 → 의심으로 강등 (예외)
    미스 → 4단계로 진행

    SUSPICIOUS_QUERY_PATTERNS (Open Redirect + 위험 쿼리스트링 통합):
    - 리다이렉트: redirect, goto, url=, next=, return=, continue=
    - 자격증명 탈취: token, auth, access_token, refresh_token, passwd, password
    - 파일 다운로드: download, file, attachment, apk
    - 로그인 우회: login_redirect, autologin, session

[4단계] 의심 캐시(suspicious_cache) 조회  🔲 Sprint 5C
    캐시 히트 → 캐시된 설명 반환. Gemini 미호출. 종료.
    hit_count += 1 (3회 이상이면 블랙리스트 후보 — 별도 컬럼 없이 쿼리로 조회)

[5단계] 도메인 유사도 검사  🔲 Sprint 5C
    화이트리스트 전체와 Levenshtein Distance 비교
    ※ 도메인 ≤5자는 스킵 (op.gg / dak.gg 같은 짧은 도메인 오탐 방지)
    임계값: 6~15자 → distance ≤2, 16자 이상 → distance ≤3
    유사 도메인 발견 시 → evidence에 similar_domain, edit_distance 추가
    ※ 판정 변경 불가 — evidence 보강 용도만. 단독으로 위험 판정 안 함.

[6단계] ANL-05 도메인 평판  🔲 Sprint 미정
    SSL 인증서, 도메인 등록일 조회
    30일 이내 신규 도메인 → evidence에 domain_age_days 추가
    단독 판정 불가 — evidence 보강 용도만

[7단계] 의심 확정 + Gemini 번역
    파이프라인이 evidence dict 완성 → Gemini 번역 → 의심 캐시 저장 (TTL: 7일)
    Gemini 실패 시 → 템플릿 폴백

[8단계] 가상 샌드박스 (사용자 선택)  🔲 Sprint 7
    7-A: 직접 탐방 / 7-B: AI 자동 테스트
```

### evidence 구조

```python
evidence = {
    "blacklist_hit": False,
    "whitelist_hit": False,
    "suspicious_query_params": [],    # 감지된 위험 파라미터 목록 (리다이렉트 포함)
    "similar_whitelist_domain": None, # 예: "kakao.com"
    "edit_distance": None,            # 예: 2
    "domain_age_days": None,
    "ssl_valid": None,
    "category": None,                 # 블랙리스트 히트 시 smType (공공기관/택배/금융/기타)
}
# ※ raw_message 제거 — category만으로 Gemini 번역 및 폴백 템플릿 선택 충분
```

### Gemini 프롬프트 구조 (확정)

```python
prompt = f"""
아래는 이 URL에 대한 분석 근거입니다. 이 근거만을 바탕으로,
일반 사용자가 이해할 수 있도록 쉽게 설명해주세요.
근거에 없는 내용은 절대 추가하지 마세요.

[분석 근거]
{json.dumps(evidence, ensure_ascii=False, indent=2)}
"""
```

### 상태별 동작 요약

| 상태 | 조건 | Gemini | 응답 시간 | 버튼 |
|------|------|--------|----------|------|
| 위험 | 블랙리스트 히트 | ✅ evidence 번역 | ~5초 이하 | 발신번호 차단 |
| 안전 | 화이트리스트 히트 (위험 패턴 없음) | ❌ | ~100ms | 5초 카운트다운 후 URL 열기 |
| 의심 (캐시 히트) | 동일 URL 재분석 | ❌ | ~150ms | 가상환경 테스트 / 신고 |
| 의심 (캐시 미스) | 블랙·화이트 모두 미스 | ✅ evidence 번역 | ~5초 이하 | 가상환경 테스트 / 신고 |

### 위험 판정 폴백 템플릿

```python
# 위험 판정 시 Gemini 실패 → category 기준 템플릿 반환
DANGER_TEMPLATES = {
    "공공기관": "이 URL은 공공기관을 사칭한 스미싱으로, KISA C-TAS에 신고된 전적이 있습니다.",
    "택배":     "이 URL은 택배사를 사칭한 스미싱으로, KISA C-TAS에 신고된 전적이 있습니다.",
    "금융":     "이 URL은 금융기관을 사칭한 스미싱으로, KISA C-TAS에 신고된 전적이 있습니다.",
    "기타":     "이 URL은 KISA C-TAS에 악성 URL로 신고된 전적이 있습니다.",
}
# category는 블랙리스트 DB의 category 컬럼(C-TAS smType)에서 읽어옴
```

---

## 8. DB 스키마

> 컬럼 설계 원칙: 파이프라인이 실제로 읽는 컬럼만 남긴다. 심사 근거 목적 컬럼은 유지, 미사용 컬럼은 삭제.

### blacklist

| 컬럼 | 용도 | 비고 |
|------|------|------|
| `url_hash` | 조회 키 1 — SHA256 O(1) | UNIQUE |
| `domain` | 조회 키 2 — 도메인 매칭 | 인덱스 필요 |
| `category` | evidence 생성 + 폴백 템플릿 선택 | smType 값 |
| `url` | 디버깅 / 역추적용 | 분석엔 미사용 |
| `source` | 심사 근거 ("C-TAS") | 분석엔 미사용 |
| `reported_at` | 심사 근거 (신고일) | 분석엔 미사용 |
| ~~`raw_message`~~ | ~~삭제~~ | category로 대체 충분 |

```sql
CREATE TABLE IF NOT EXISTS blacklist (
    url_hash    TEXT NOT NULL UNIQUE,
    domain      TEXT NOT NULL,
    category    TEXT,
    url         TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT 'C-TAS',
    reported_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bl_domain ON blacklist(domain);
-- id PK 생략: url_hash UNIQUE → SQLite rowid 자동 생성으로 충분
```

### whitelist

| 컬럼 | 용도 | 비고 |
|------|------|------|
| `domain` | 매칭 키 | UNIQUE |
| `match_mode` | 매칭 로직에서 직접 읽음 | exact/suffix/pattern |
| `category` | 유사도 결과 evidence 보강 | "카카오 계열" 등 |
| `source` | 심사 근거 | 분석엔 미사용 |
| `added_at` | 심사 근거 | 분석엔 미사용 |
| ~~`risk_level`~~ | ~~삭제~~ | 관련 파이프라인 로직 없음 |
| ~~`note`~~ | ~~삭제~~ | 관련 파이프라인 로직 없음 |

```sql
CREATE TABLE IF NOT EXISTS whitelist (
    domain      TEXT NOT NULL UNIQUE,
    category    TEXT NOT NULL,
    match_mode  TEXT NOT NULL,   -- 'exact' | 'suffix' | 'pattern'
    source      TEXT NOT NULL DEFAULT 'manual',
    added_at    TEXT NOT NULL
);
```

### suspicious_cache (Sprint 5C 신규)

| 컬럼 | 용도 | 비고 |
|------|------|------|
| `url_hash` | 캐시 조회 키 | UNIQUE |
| `domain` | 도메인 단위 조회 | 인덱스 필요 |
| `cached_reason` | 캐시 히트 시 Flutter에 반환할 텍스트 | Gemini 번역본 or 템플릿 |
| `hit_count` | 누적 조회 횟수 — 블랙리스트 후보 판단 기준 | |
| `first_seen` | 첫 분석 시각 | ISO8601 |
| `expires_at` | TTL 만료 시각 (first_seen + 7일) | 조회 필터 기준 |
| ~~`is_bl_candidate`~~ | ~~삭제~~ | `WHERE hit_count >= 3` 쿼리로 대체 가능 — 컬럼 불필요 |
| ~~`last_seen`~~ | ~~삭제~~ | expires_at으로 대체 |

```sql
CREATE TABLE IF NOT EXISTS suspicious_cache (
    url_hash        TEXT    NOT NULL UNIQUE,
    domain          TEXT    NOT NULL,
    cached_reason   TEXT    NOT NULL,
    hit_count       INTEGER NOT NULL DEFAULT 1,
    first_seen      TEXT    NOT NULL,
    expires_at      TEXT    NOT NULL   -- first_seen + 7일, WHERE expires_at > now() 로 유효성 판단
);
CREATE INDEX IF NOT EXISTS idx_cache_domain ON suspicious_cache(domain);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON suspicious_cache(expires_at);
```

> 블랙리스트 후보 조회: `SELECT domain, url_hash, hit_count FROM suspicious_cache WHERE hit_count >= 3 ORDER BY hit_count DESC`

### user_reports (Sprint 5C 신규)

| 컬럼 | 용도 | 비고 |
|------|------|------|
| `url` | 신고 대상 원본 URL | SHA256 역추적 불가이므로 url 직접 저장 |
| `domain` | 신고 도메인 | |
| `reported_at` | 신고 시각 | ISO8601 |
| ~~`url_hash`~~ | ~~삭제~~ | SHA256은 복호화 불가 — 신고 목적에 원본 URL 필요 |
| ~~`memo`~~ | ~~삭제~~ | UI 입력창 미구현, 활용 로직 없음 |

```sql
CREATE TABLE IF NOT EXISTS user_reports (
    url         TEXT NOT NULL,
    domain      TEXT NOT NULL,
    reported_at TEXT NOT NULL
);
```

### DB 커넥션 분리 정책

목적: **동시성 안전성** (보안 아님). 분석 파이프라인 읽기 중 캐시 쓰기가 충돌해 `database is locked` 에러 방지.

```python
# 읽기전용 (분석 파이프라인) — 코드 버그로 인한 실수 쓰기 원천 차단
read_conn = sqlite3.connect("security_hub.db", check_same_thread=False)
read_conn.execute("PRAGMA query_only = ON")

# 쓰기 (캐시 저장, 신고 적재)
write_conn = sqlite3.connect("security_hub.db", check_same_thread=False)
write_conn.execute("PRAGMA journal_mode = WAL")
```

### 화이트리스트 무결성 보안

화이트리스트가 오염되면 피싱 사이트를 안전으로 판정 → 앱 신뢰성 붕괴. 3단계로 방어한다.

**1단계 — 수정 API 엔드포인트 없음**
화이트리스트·블랙리스트 수정 API를 외부에 노출하지 않음. 적재는 백엔드 스크립트(`load_whitelist_csv.py`)로만 수행 → 외부에서 API로 오염시킬 경로 자체가 없음.

**2단계 — 읽기전용 커넥션 강제**
분석 파이프라인은 `PRAGMA query_only = ON` 커넥션만 사용 → 코드 버그로 실수 쓰기 불가.

**3단계 — 서버 시작 시 체크섬 검증**
```python
import hashlib, json

def generate_whitelist_checksum(conn) -> str:
    rows = conn.execute(
        "SELECT domain, match_mode FROM whitelist ORDER BY domain"
    ).fetchall()
    return hashlib.sha256(
        json.dumps(rows, ensure_ascii=False).encode()
    ).hexdigest()

def verify_whitelist_integrity(conn, expected: str) -> bool:
    """서버 시작 시 호출. 불일치 시 서버 구동 중단."""
    if generate_whitelist_checksum(conn) != expected:
        raise RuntimeError("화이트리스트 무결성 검증 실패 — DB 변조 의심")
    return True
```
최초 적재 후 체크섬을 `.env`에 저장. 서버 시작마다 비교 → DB 파일이 외부에서 직접 변조되면 서버가 뜨지 않음.

> 심사 답변: "수정 API 없음 + 읽기전용 커넥션 + 체크섬 검증 3단계로 화이트리스트 무결성을 보장합니다."

### DB 관리 도구

**DB Browser for SQLite** (무료) — `security_hub.db` 파일을 직접 열어 테이블 내용을 GUI로 조회.
코드 변경 없이 블랙리스트·화이트리스트·캐시 현황 확인 가능. DB 조작(적재/삭제)은 백엔드 스크립트로만 수행.

> 심사 시연: "DB 관리는 DB Browser for SQLite로 합니다" — 실제로 열어서 보여줄 수 있음.

---

## 9. C-TAS 블랙리스트 데이터

| 지표 | 2024년 | 2026년 |
|------|--------|--------|
| 전체 URL 수 | 28,443건 | 154건 |
| 고유 URL 수 | 5,886개 (79% 중복) | 84개 |
| 단축 URL | 4,712건 (16%) | 2건 |
| smType 1위 | 택배 | 공공기관 (71%) |

**단축 URL 도메인 분포 (C-TAS 기준):** bit.ly 66%, w0q.de 14%, ph.link 5%, 기타 15%

---

## 10. URL 추출 및 정규화 설계

> 컨텍스트에 미포함된 구멍 — 2026-04-17 신규 추가 (DC-16)

### 문제

스미싱 문자에서 URL은 세 가지 형태로 올 수 있다. 현재 http/https로 시작하는 URL만 잡으면 ③④가 누락된다.

```
① http://gov.oe3m.me/abc    → 프로토콜 있음 ✅ 탐지 가능
② https://naver.com/event   → 프로토콜 있음 ✅ 탐지 가능
③ gov.oe3m.me/abc           → 프로토콜 없음 ❌ 현재 누락
④ bit.ly/3xAbc              → 단축 URL + 프로토콜 없음 ❌ 현재 누락
```

C-TAS `firstURL` 컬럼에도 프로토콜 없는 URL이 다수 존재 → DB에 `gov.oe3m.me`로 저장된 것과 입력 `http://gov.oe3m.me`의 url_hash가 달라져 매칭 실패.

### 해결 — 2단계 URL 추출

```python
import re
from urllib.parse import urlparse
import hashlib

# 1단계: 프로토콜 있는 URL
PATTERN_WITH_PROTO = re.compile(r'https?://[^\s\u3000\u200b]+')

# 2단계: 프로토콜 없는 도메인 (알려진 TLD로 오탐 최소화)
KNOWN_TLDS = r'(?:com|kr|net|org|io|me|link|ly|de|info|biz|co)'
PATTERN_WITHOUT_PROTO = re.compile(
    r'(?<![/\w])([a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9]'
    r'\.' + KNOWN_TLDS + r'(?:\.[a-zA-Z]{2})?(?:/[^\s\u3000\u200b]*)?)'
)

def extract_urls(text: str) -> list[str]:
    urls = []
    with_proto = PATTERN_WITH_PROTO.findall(text)
    urls.extend(with_proto)
    # 이미 추출된 구간 제거 후 2단계 적용 (중복 방지)
    remaining = text
    for u in with_proto:
        remaining = remaining.replace(u, ' ')
    without_proto = PATTERN_WITHOUT_PROTO.findall(remaining)
    urls.extend(f'https://{u}' for u in without_proto)
    return urls
```

> TLD 화이트리스트가 없으면 `오늘.날씨`, `안녕.해` 같은 일반 문장도 URL로 오탐됨.

### url_hash 정규화 원칙

`http://`, `https://`, 프로토콜 없음 세 가지가 동일한 hash를 갖도록 **프로토콜 제거 후 해시** 생성.

```python
def normalize_and_hash(url: str) -> tuple[str, str]:
    """프로토콜 제거 후 도메인+경로로 해시 생성. 일관된 매칭 보장."""
    parsed = urlparse(url if '://' in url else f'https://{url}')
    normalized = (parsed.netloc + parsed.path).rstrip('/').lower()
    url_hash = hashlib.sha256(normalized.encode()).hexdigest()
    return normalized, url_hash
# 결과: http://gov.oe3m.me == https://gov.oe3m.me == gov.oe3m.me → 동일 hash
```

> ⚠️ 기존 blacklist DB 적재 스크립트(`load_ctas_csv.py`)도 이 정규화 로직 적용 필요 — 불일치 시 매칭 실패.

---

## 11. 가상 샌드박스 설계 (Sprint 7)

**현재 상태:** 미착수. W3 선행 작업: Playwright 환경 세팅 (멤버 C).

### 샌드박스 구성 — Browserless + Playwright (Q-08)

- **현재 계획**: Playwright 단독으로 서버에서 Chromium 직접 실행
- **문제**: 동시 사용자 증가 시 Chromium 프로세스 수 비례 증가 → 메모리 과부하
- **개선 방향**: Browserless(Docker)가 Chromium 실행, Playwright가 WebSocket으로 원격 제어
  - 프로세스 격리 강화, 최대 동시 세션 수 Browserless 설정으로 제한 가능
  - Docker 세팅 부담 있어 Sprint 7 착수 전 도입 여부 확정 필요 (Q-08)

### 7-A: 직접 탐방 모드
- 격리된 가상 브라우저에서 사용자가 직접 탐색
- 상시 경고 배너: "이 화면은 가상 환경입니다. 실제 개인정보를 절대 입력하지 마세요."
- End 처리: 닫으면 끝. 리포트/판정 없음.

### 7-B: AI 자동 테스트 모드
- AI가 가짜 개인정보 주입 → 사이트 반응 관찰
- 3단계 스크린샷: 접속 전 / 입력 중 / 제출 후
- End 처리 (Q-01 확정): 의심 행동 목록을 일반 언어로 표시
- 신규 위협 발견 시 → KISA 신고 안내 (블랙리스트 미등록이므로 신고 의미 있음)
- ⚠️ bot detection 사이트에서 headless 차단 시 → "봇 차단 감지됨" 처리로 폴백

---

## 11. E2E 시나리오

### 시나리오 A: 위험
```
입력: [Web발신][정부24] 벌점통지서발송. gov.oe3m.me
→ URL 추출 → SHA256 → 블랙리스트 히트 (category: 공공기관)
→ evidence 생성 → Gemini 번역
→ 위험 화면 (신호등 빨강) → 발신번호 차단하기
응답 ~5초 이하 | Gemini ✅
```

### 시나리오 B: 의심 (캐시 미스)
```
입력: [CU팡] 배송 실패. coupang-delivery.info/recheck
→ 블랙리스트 미스 → 화이트리스트 미스 → 캐시 미스
→ 유사도: coupang.com과 distance 2 → evidence 생성 → Gemini 번역 → 캐시 저장
→ 의심 화면 (신호등 노랑) → 가상 샌드박스 or 신고
응답 ~5초 이하 | Gemini ✅
```

### 시나리오 B-2: 의심 (캐시 히트)
```
동일 URL 재입력 → suspicious_cache 히트 → hit_count += 1 → 캐시 응답
응답 ~150ms | Gemini ❌
```

### 시나리오 C: 안전
```
입력: [국민건강보험] 검진 안내. www.nhis.or.kr
→ 블랙리스트 미스 → 화이트리스트 히트 (위험 패턴 없음)
→ 안전 즉시 반환 → 5초 카운트다운 → URL 열기
응답 ~100ms | Gemini ❌
```

---

## 12. 설계 변경 이력 (Design Change Log)

| # | 원문 | 변경 내용 | 변경 사유 | 날짜 |
|---|------|---------|---------|------|
| DC-01 | "화이트리스트 → 공식 사이트 안내" | 공식 사이트 안내 폐기 | 오매핑 시 피해 유발 | 2026-03-26 |
| DC-02 | "DANGER 시 KISA 신고 버튼" | 블랙리스트 DANGER에서 KISA 신고 제거 | 이미 신고된 URL — 재신고 논리 모순 | 2026-03-29 |
| DC-03 | "VirusTotal / Google Safe Browsing 활용" | 초기 버전은 C-TAS만 사용 | 졸업작품 범위 한정 | 2026-03-29 |
| DC-04 | "Gemini가 판정" | Gemini는 evidence 번역만 | AI 오판 시 앱이 피해에 공모. 보수적 접근 | 2026-03-30 |
| DC-05 | "DANGER 시 항상 KISA 신고" | 샌드박스 신규 위협 발견 시에만 KISA 신고 | 블랙리스트 히트 = 이미 신고됨 | 2026-03-30 |
| DC-06 | "SUSPICIOUS 시 Gemini 미호출" | SUSPICIOUS 시에도 evidence 번역 수행 | 사용자가 왜 의심인지 알아야 함 | 2026-03-30 |
| DC-07 | "Gemini가 의심 사유 자체 생성" | 파이프라인이 evidence 생성, Gemini는 번역만 | 할루시네이션 방지. 교수 피드백 반영 | 2026-04-14 |
| DC-08 | "화이트리스트 히트 = 무조건 SAFE" | 위험 쿼리스트링 포함 시 SUSPICIOUS 강등 | 쿼리스트링 기반 공격 대응 | 2026-04-14 |
| DC-09 | "URL 풀매치 + 도메인 매칭만" | Levenshtein 유사도 검사 추가 | 타이포스쿼팅 탐지 | 2026-04-14 |
| DC-10 | "매 요청마다 전체 재분석" | suspicious_cache 도입 | Gemini RPD 절약 + 응답 속도 개선 | 2026-04-14 |
| DC-11 | "구성도에 분석 파이프라인만" | Share Intent/클립보드, 공유 경로 추가 | 교수 피드백 반영 | 2026-04-14 |
| DC-12 | 구성도에 "Gemini" 표기 | "AI 설명 서비스(LLM)" 또는 "AI Service"로 표기 | 특정 벤더 종속성 노출 방지 | 2026-04-14 |
| DC-13 | DANGER/SUSPICIOUS/SAFE 레이블 영문 사용 | UI·문서는 위험/의심/안전으로 한글화. 코드 내부 enum·API 필드는 영어 유지 | 사용자 대면 문자열에 영문 용어 불필요 | 2026-04-17 |
| DC-14 | Open Redirect 패턴과 위험 쿼리스트링 별도 관리 | SUSPICIOUS_QUERY_PATTERNS 하나로 통합 | 로직 중복, 동일한 처리 결과 (의심 강등) — 분리 이유 없음 | 2026-04-17 |
| DC-15 | DB 컬럼 설계 (raw_message, risk_level, note, last_seen 등) | 파이프라인 미사용 컬럼 삭제, last_seen → expires_at 교체, 짧은 도메인(≤5자) 유사도 스킵 추가 | 실제 쓰임새 기준으로 최소화. TTL 계산 단순화. 짧은 도메인 오탐(op.gg vs dak.gg) 방지 | 2026-04-17 |
| DC-16 | URL 추출 시 http/https만 탐지 | 프로토콜 없는 URL도 TLD 기반 정규식으로 추출 + 프로토콜 제거 후 해시 정규화 | C-TAS 데이터 및 실제 스미싱 문자에 프로토콜 없는 URL 다수 존재 — 미탐지 시 블랙리스트 매칭 실패 | 2026-04-17 |
| DC-17 | suspicious_cache `is_bl_candidate` 컬럼 | 컬럼 삭제 → `WHERE hit_count >= 3` 쿼리로 대체 | 별도 컬럼 없이 동일 결과 조회 가능 — 불필요한 복잡성 제거 | 2026-04-17 |
| DC-18 | ERD에 관리자 액터 없음 | ERD/구성도에 관리자 행위 및 데이터 흐름 추가 | 교수 피드백 — "관리자 관련이 ERD에 어디 있냐" | 2026-04-17 |

---

## 13. 테스트 케이스 (TC)

**원칙**: TC-First. Happy Path만 테스트하지 않는다. 경계값·에러 케이스 필수.
**TC-ID 형식**: `[구분]-[번호]` — D(위험), S(안전), SU(의심), E(경계값), P(성능)

### TC-D: 위험 판정

| TC-ID | 입력 | 기대 결과 | 검수 포인트 |
|-------|------|---------|------------|
| D-01 | 블랙리스트 url_hash 정확 일치 URL | DANGER + Gemini 번역 | evidence 포함, 폴백 아닌 실제 번역 확인 |
| D-02 | 블랙리스트 도메인 + 경로만 다른 변형 URL | DANGER (domain 2차 매칭) | url_hash 미스 → domain 매칭 동작 확인 |
| D-03 | 단축 URL (bit.ly) → 해제 후 블랙리스트 히트 | DANGER | 해제 전 미스, 해제 후 히트 확인 |
| D-04 | Gemini 키 없음/만료 + 블랙리스트 히트 | DANGER + 템플릿 폴백 | 서비스 중단 없음 |
| D-05 | smType이 DB에 없는 값 ("기타2") | DANGER + "기타" 템플릿 | KeyError 없이 처리 |

### TC-S: 안전 판정

| TC-ID | 입력 | 기대 결과 | 검수 포인트 |
|-------|------|---------|------------|
| S-01 | 화이트리스트 정확 도메인 (`naver.com`) | SAFE + Gemini 미호출 | 응답 100ms 이내 |
| S-02 | `.go.kr` 패턴 도메인 (`www.mois.go.kr`) | SAFE | 패턴 매칭 동작 |
| S-03 | 화이트리스트 도메인 + `?redirect=http://evil.com` | 의심 | SUSPICIOUS_QUERY_PATTERNS 감지 확인 |
| S-04 | 화이트리스트 도메인 + `?token=xxxx` | 의심 | SUSPICIOUS_QUERY_PATTERNS 감지 확인 |
| S-05 | 화이트리스트 도메인 + `?download=malware.apk` | 의심 | SUSPICIOUS_QUERY_PATTERNS 감지 확인 |
| S-06 | `coupang.com` vs `coupang-delivery.com` | 각각 SAFE / SUSPICIOUS | 유사 도메인 혼동 없음 |

### TC-SU: 의심 판정

| TC-ID | 입력 | 기대 결과 | 검수 포인트 |
|-------|------|---------|------------|
| SU-01 | 블랙·화이트 모두 미스 (캐시 없음) | SUSPICIOUS + Gemini 번역 | evidence 기반 번역, 할루시네이션 없음 |
| SU-02 | 동일 URL 재요청 (캐시 있음) | SUSPICIOUS + 캐시 응답 | Gemini 미호출, 150ms 이내 |
| SU-03 | 화이트리스트 유사 도메인 (`kakaoo.com`) | SUSPICIOUS + 유사 도메인 플래그 | edit_distance 계산 정확도 |
| SU-04 | 단축 URL 해제 실패 (타임아웃) | 원본 URL로 SUSPICIOUS | 폴백 동작, 서비스 중단 없음 |
| SU-05 | URL 없이 텍스트만 ("내일 저녁 먹자") | SUSPICIOUS + 안내 문구 | URL 추출 실패 처리 |

### TC-E: 경계값 및 예외

| TC-ID | 입력 | 기대 결과 | 검수 포인트 |
|-------|------|---------|------------|
| E-01 | 빈 문자열 | 프론트 차단 (SnackBar) | 서버 요청 미발생 |
| E-02 | 공백만 ("   ") | 프론트 차단 | trim() 후 검증 |
| E-03 | 10,000자 이상 입력 | 서버 graceful 처리 (400 or truncate) | 앱 크래시 없음 |
| E-04 | 서버 다운 상태 | 에러 SnackBar (타임아웃 후) | 메시지 명확히 표시 |
| E-05 | 동일 URL 연속 10회 | 정상 처리 or Rate Limit 안내 | 앱 크래시 없음 |
| E-06 | 한글 포함 URL (`http://정부.kr`) | 정상 처리 (punycode or SUSPICIOUS) | UnicodeDecodeError 없음 |
| E-07 | `javascript:alert(1)` | SUSPICIOUS 또는 URL 무효 처리 | XSS 벡터 실제 실행 안 됨 |
| E-08 | IP 주소 URL (`http://123.456.78.9/login`) | SUSPICIOUS | SAFE 반환 안 함 |
| E-09 | 단축 URL 체인 (해제 결과가 또 단축 URL) | 1회 해제 후 결과로 매칭 | 무한 루프 없음 |
| E-10 | Gemini RPD 250건 소진 후 요청 | 템플릿 폴백으로 정상 응답 | 에러 사용자에게 미노출 |
| E-11 | `naver.com.evil.kr` | SUSPICIOUS + 유사 도메인 플래그 | SAFE 오판 안 함 |
| E-12 | 화이트리스트 도메인 + `?auth=token123` | SUSPICIOUS | 화이트리스트 히트여도 SAFE 반환 안 함 |
| E-13 | suspicious_cache hit_count=3 도달 | `WHERE hit_count >= 3` 조회 시 해당 URL 포함 | 블랙리스트 후보 쿼리 정상 동작 확인 |

### TC-P: 성능

| TC-ID | 시나리오 | 기준 |
|-------|---------|------|
| P-01 | SAFE 경로 응답 | 100ms 이하 |
| P-02 | SUSPICIOUS 캐시 히트 응답 | 150ms 이하 |
| P-03 | DANGER/SUSPICIOUS 캐시 미스 응답 | 5초 이하 |
| P-04 | 동시 3건 요청 | 교차 오염 없음, 모두 정상 응답 |

---

## 14. 스프린트 진행 상황

```
Sprint 1  ✅ FastAPI 백엔드 뼈대
Sprint 2  ✅ Gemini 연동
Sprint 3  ✅ Flutter E2E 연결
Sprint 4  ✅ 블랙리스트 DB (C-TAS 2024/2025/2026 적재 완료)

Sprint 5A ✅ 파이프라인 고도화
  - 단축 URL 해제 (url_expander.py)
  - 화이트리스트 DB (exact/suffix/pattern 3모드, Open Redirect 처리)
  - analysis_service.py 리팩토링 (Gemini = 설명자 원칙)

Sprint 5B ✅ C-TAS 데이터 대량 적재 + 품질 검증

Sprint 5C 🔲 DB 설계 강화 (W3~W4 목표)
  - 쿼리스트링 위험 패턴 감지 (whitelist_service.py)
  - 도메인 유사도 (domain_similarity.py — Levenshtein)
  - suspicious_cache + user_reports 테이블 신설
  - DB 커넥션 읽기/쓰기 분리
  - Gemini 프롬프트 → evidence 번역자로 전면 교체

Sprint 6  ⚠️ 액션 버튼 (부분 완료)
  - SAFE: 면책 고지 + URL 열기 ✅ (카운트다운 미완)
  - SUSPICIOUS: VirtualSandboxScreen 라우팅 ✅
  - DANGER: 발신번호 차단 다이얼로그만 (url_launcher 연결 미완) 🔲
  - 발신번호 입력 필드 추가 🔲
  - 결과 공유 (카카오톡/문자) 🔲

Sprint 7  🔲 가상 샌드박스 (W7~W9)
  - 선행: Playwright 환경 세팅 (W3, 멤버 C)
  - 7-A: 직접 탐방 모드
  - 7-B: AI 자동 테스트 모드

Sprint 8  🔲 최종 마무리 및 심사 준비 (W10~W11)
```

---

## 15. 주차별 일정

| 주차 | 기간 | 멤버 A (Frontend) | 멤버 B (Backend + 통합) | 멤버 C (Data + Sandbox) |
|------|------|-----------------|----------------------|----------------------|
| W3 | 4/13~4/19 | 결과 화면 UI 구현 | Gemini 프롬프트 교체 (번역자 전환) | **Playwright 선행 세팅** · 쿼리스트링 패턴 |
| W4 | 4/20~4/26 | 결과 화면 완성 · API 연결 | suspicious_cache · **E2E 테스트 #1** | 도메인 유사도 모듈 · DB 커넥션 분리 |
| W5 | 4/27~5/3 | 번호 차단 UI · DANGER 액션 | 통합 점검 · PR 리뷰 | 화이트리스트 큐레이션 · DB 품질 검증 |
| W6 | 5/4~5/10 | SAFE 카운트다운 · SUSPICIOUS 화면 · 공유 | API 스키마 갱신 · **E2E 테스트 #2** | Playwright Chromium headless 검증 |
| W7 | 5/11~5/17 | 7-A 직접 탐방 화면 · 경고 배너 | API 스키마 갱신 · PR 리뷰 | 7-A 직접 탐방 모드 · 격리 세션 관리 |
| W8 | 5/18~5/24 | 7-B AI 테스트 결과 화면 · 탐지 카드 UI | API 스키마 갱신 · PR 리뷰 | 7-B AI 자동 테스트 · 가짜정보 주입 · 스크린샷 |
| W9 | 5/25~5/31 | 샌드박스 7-A·7-B 통합 완성 | **E2E 테스트 #3** · 샌드박스 ↔ Flutter 검증 | 7-B 리포트 생성 · 버그 수정 |
| W10 | 6/1~6/7 | UI 버그 수정 · UX Polish | **전체 E2E 테스트** · 시나리오 전수 검증 | DB 정합성 확인 · 샌드박스 검수 |
| W11 | 6/8~6/12 | 심사용 시연 시나리오 준비 | 최종 통합 검증 · 문서 제출 | 데이터 최종 확인 · 시연 지원 |

> 🔴 W10~W11: 신규 개발 없음. 테스트·검수·심사 준비만.

---

## 16. 멤버 역할 분담

| 멤버 | 역할 | 담당 |
|------|------|------|
| 멤버 A | Frontend 전담 | 홈 화면, 결과 화면, 가상 샌드박스 화면, `api_service.dart`, 공유 UI |
| 멤버 B | Backend + 인티그레이터 | 파이프라인, evidence 생성, Gemini 번역 서비스, API 스키마, E2E 통합 테스트, PR 리뷰 |
| 멤버 C | Data & Sandbox 전담 | URL 해제, 블랙/화이트 DB, 도메인 유사도, suspicious_cache, Playwright 샌드박스 |

---

## 17. 미결 사항 (Open Questions)

| # | 질문 | 결정 시점 |
|---|------|----------|
| Q-01 | ~~7-B End 처리~~ | ✅ 확정 — 의심 행동 목록 일반 언어로 표시 |
| Q-02 | VirusTotal / Google Safe Browsing 연동 여부 | 시간 여유 판단 후 |
| Q-03 | APScheduler 자동 크롤링 구현 여부 | 시간 여유 판단 후 |
| Q-04 | URL 없이 전화번호만 있는 스미싱 처리 | Sprint 6 |
| Q-05 | suspicious_cache TTL 7일 적정성 | Sprint 5C 구현 시 |
| Q-06 | 도메인 유사도 임계값 실측 FP 측정 | Sprint 5C TC 실행 후 |
| Q-07 | 결과 공유 기능 (카카오톡/문자) Sprint 배정 | Sprint 6 |
| Q-08 | Browserless + Playwright 구성 도입 여부 | Sprint 7 착수 전 |

### 미결 사항 상세

**Q-02 — VirusTotal / Google Safe Browsing 연동**
현재 블랙리스트는 C-TAS만 사용. VirusTotal은 70개 이상 백신 엔진 결과 반환, Google Safe Browsing은 구글 피싱 DB 제공. 연동 시 탐지율 향상되나 API 호출 지연·비용 추가. Sprint 7 이후 여유 시 검토.

**Q-03 — APScheduler 자동 크롤링**
C-TAS 최신 CSV를 현재 수동 적재 중. 자동화 시 최신 피싱 URL 즉시 반영 가능하나, KISA C-TAS는 공개 API 없이 웹 로그인 필요 구조라 구현 복잡. 데모 수준에서는 수동 적재로 충분.

**Q-04 — URL 없이 전화번호만 있는 스미싱**
"대출 한도 확인: 010-1234-5678로 전화하세요" 형태. URL 추출 결과 없을 때 현재는 "URL을 찾을 수 없습니다" 처리. Sprint 6에서 전화번호 패턴 감지 후 "보이스피싱 의심" 별도 안내 로직 추가 필요.

**Q-05 — suspicious_cache TTL 7일 적정성**
7일 기준은 임의값. 피싱 사이트는 탐지 후 빠르게 도메인 교체 → 7일이 너무 길면 이미 사라진 사이트를 계속 캐싱. Sprint 5C 구현 시 C-TAS 데이터 기반 피싱 사이트 평균 생존 기간 참고 후 조정.

**Q-06 — 도메인 유사도 임계값 실측 FP**
현재 임계값(6~15자→distance ≤2, 16자 이상→distance ≤3, ≤5자 스킵)은 이론값. 화이트리스트 200건 전체를 실제로 돌려 FP 비율 측정 후 조정 필요. Sprint 5C TC 실행 후 결정.

**Q-07 — 결과 공유 기능**
분석 결과를 카카오톡/문자로 공유하는 기능. Flutter `share_plus` 패키지로 구현 가능. Sprint 6 미완 항목이 많아 Sprint 7로 밀릴 가능성 높음.

**Q-08 — Browserless + Playwright 구성**
현재 Playwright 단독으로 서버에서 Chromium 직접 실행 예정. 문제: 동시 사용자 증가 시 Chromium 프로세스가 사용자 수만큼 생성 → 메모리 과부하. Browserless는 Chromium을 Docker 컨테이너에서 실행, Playwright가 WebSocket으로 원격 제어하는 구조. 프로세스 격리 + 최대 동시 세션 수 제한 가능. Docker 세팅 부담 감안하여 Sprint 7 착수 전 도입 여부 결정 필요.

---

## 18. 검수자 페르소나 — 김검수

> Claude는 **모든 응답에서** 아래 기준을 자동 적용한다. "검수해줘"를 치지 않아도 작동한다.

**"김검수" — 실무 10년차 보안 엔지니어 겸 한이음 기술 심사위원.**
감정 없이 기술적 사실만 본다. 졸업 작품이라 봐주지 않는다.

### 18-1. 자동 검수 항목 (코드·설계 작성마다 체크)

| 항목 | 검수 질문 |
|-----|---------|
| 예외 처리 | DB 연결 실패와 조회 결과 없음을 코드에서 구분하나? |
| 경계값 | 빈 입력, 10,000자, `javascript:` 스킴, IP형 URL은 처리하나? |
| 폴백 | Gemini 쿼터 소진 / 타임아웃 시 서비스가 멈추지 않나? |
| 보안 | `naver.com.evil.kr` 같은 서브도메인 스푸핑을 SAFE로 오판하지 않나? |
| 자원 관리 | Playwright 동시 요청 시 프로세스 누수가 없나? |
| TC 완결성 | Happy Path만 있고 에러·경계값 TC가 빠지지 않았나? |
| 설계 근거 | 이 결정을 교수 앞에서 30초 안에 설명할 수 있나? |

### 18-2. 예상 심사 질문 목록

**설계 관련**
- "쿼리스트링 위험 패턴이 고정값이면 새로운 패턴 나왔을 때 코드 수정 없이 대응 가능한가요?"
- "suspicious_cache TTL 7일 기준은 어떻게 정했나요? 피싱 사이트가 7일 후 URL 바꾸면요?"
- "edit distance 임계값 2/3은 실측 FP 데이터가 있나요? 없으면 어떻게 정당화하나요?"
- "단축 URL 해제가 1회면 2단계 리다이렉트 체인은 탐지 못하는 거 아닌가요?"
- "Playwright가 서버에서 돌면 여러 사용자 동시 접속 시 자원 관리는요?"
- "화이트리스트 200건으로 한국 주요 합법 사이트를 충분히 커버하나요?"

**구현 관련**
- "DB 커넥션 읽기/쓰기 분리했는데, SQLite WAL 모드에서 동시 쓰기 충돌은요?"
- "User-Agent 설정해도 bot detection을 100% 우회 못하면 단축 URL 해제 실패율은?"
- "2026년 C-TAS가 154건뿐인데, 최신 피싱 탐지 실효성이 있나요?"

**TC 관련**
- "Happy Path 테스트만 통과하면 뭐가 달라지나요? 공격자가 `naver.com.phish.kr` 넣으면 어떻게 반응하나요?"
- "에러 케이스 TC가 없네요. 서버 내려갔을 때 앱이 어떻게 되는지 테스트해봤어요?"

### 18-3. 검수 심화 트리거

아래 키워드 입력 시 Claude는 **김검수 시뮬레이션 모드**로 전환한다:
- `"검수해줘"`, `"태클 걸어줘"`, `"이거 괜찮아?"`, `"심사 준비"`, `"TC 추가해줘"`, `"예외 케이스 뭐 있어?"`
- 새로운 기능 설계 제안 시 (설계 정리 먼저 → 김검수 검토 병행)

**시뮬레이션 포맷:**
```
🔍 [김검수 검토]
✅ 통과: (문제없는 부분)
⚠️ 태클: (허점 및 보완 필요 부분)
💬 예상 심사 질문: "..."
🛠 권고: (구체적 보완 방법)
```

---

## 19. 발표 구조 가이드 (교수 피드백 반영)

### 슬라이드 권장 구성
```
[슬라이드 1] 전체 일정 + 진행 상황 (✅ 완료 / ⚠️ 진행 중 / 🔲 미착수)
[슬라이드 2] 완료된 기능 (시연 가능)
[슬라이드 3] 남은 것 + 이유 + 언제까지
[슬라이드 4] 주요 설계 결정 (DC 로그 기반 — 왜 바꿨는지)
```

### 진행 상황 표현 템플릿

| 상태 | 표현 |
|------|------|
| 완료 | "완료했습니다. 시연 가능합니다." |
| 부분 완료 | "X는 완료, Y는 Z 이유로 W4로 이동했습니다." |
| 미착수 | "미착수입니다. W7 착수 예정이고, 선행 작업은 W3에 앞당겼습니다." |
| 설계 변경 | "교수님 피드백 반영해서 A → B로 변경했습니다. 이유는 C입니다." |

### 시스템 구성도 수정 필요 항목
- 입력 경로: SMS → Share Intent / 클립보드 캐치 → 앱 진입 추가
- 출력 경로: 분석 결과 → 카카오톡/문자 공유 추가
- Gemini → "AI 설명 서비스(LLM)" 표기 변경
- DB 레이어에 suspicious_cache 레이어 추가
- **ERD/구성도에 관리자 액터 및 데이터 흐름 추가** (교수 피드백 — "관리자 관련이 ERD에 없다")
  - 관리자 → CSV 적재 스크립트 → blacklist / whitelist INSERT
  - 관리자 → suspicious_cache `hit_count >= 3` 조회 → blacklist 승급 검토
  - 일반 사용자 → user_reports INSERT (신고)

---

*이 파일은 새 대화를 시작할 때마다 첨부하여 컨텍스트를 유지한다.*
*코드 변경이 생기면 "CLAUDE_CONTEXT.md 업데이트해줘"라고 요청한다.*
