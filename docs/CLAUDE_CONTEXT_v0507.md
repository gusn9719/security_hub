# CLAUDE_CONTEXT.md — Security Hub
# AI기반 피싱 탐지 및 가상 환경 테스트 앱 | 한이음 ICT 드림업 2026
# 마지막 업데이트: 2026-05-07 (v14 — Sprint 5E 완료: 파이프라인 0~8단계 확정 + 프론트 클립보드/세션만료 완료)
# 새 대화 시작 시 이 파일을 첨부하여 컨텍스트를 유지한다.

---

## 1. 프로젝트 개요

| 항목 | 내용 |
|------|------|
| **프로젝트명** | AI기반 피싱 탐지 및 가상 환경 테스트 앱 |
| **성격** | 한이음 ICT 드림업 2026 졸업 작품 (실제 심사 대상) |
| **핵심 목표** | 의심 문자/URL → 다신호 스코어링 기반 필터링 → 안전/의심/위험 판정 → 가상환경 테스트 제공 |
| **앱명** | `security_hub` (pubspec.yaml 기준) |
| **레포 루트** | `C:/dev/security_hub/` (GitHub 레포 루트) |
| **Flutter 루트** | `C:/dev/security_hub/frontend/` |
| **백엔드 루트** | `C:/dev/security_hub/backend/` |
| **데이터/샌드박스 루트** | `C:/dev/security_hub/data/` |
| **현재 주차** | W6 (Sprint 5E 완료 / Sprint 6·7 진행 중) — 2026-05-04~05-10 |

---

## 2. 기술 스택

| 레이어 | 기술 | 역할 |
|--------|------|------|
| 프론트엔드 | Flutter (Dart) | 모바일 UX, 신호등 UI, 결과 화면 |
| 백엔드 | Python 3.14 + FastAPI + Uvicorn | API 서버, 분석 파이프라인 |
| AI | Gemini 2.5 Flash (`google-genai` SDK) | **7-B findings 자연어 요약만** (파이프라인 판정·번역 역할 없음) |
| 샌드박스 7-A | `kasmweb/chromium:1.14.0` (Docker) | 직접 탐방 — KasmVNC로 Chromium 화면 스트리밍, Flutter WebView가 noVNC URL 로드 |
| 샌드박스 7-B | Playwright + `ghcr.io/browserless/chromium` (Docker) | AI 자동 테스트 — Playwright가 WebSocket CDP로 Browserless Chromium 제어 |
| DB | SQLite (`backend/security_hub.db`) | 블랙리스트 / 화이트리스트 / 평판캐시 / 투표 / 샌드박스결과 |

### 패키지 현황

**Flutter (pubspec.yaml)**
- `cupertino_icons ^1.0.8`
- `http 1.6.0`
- `url_launcher 6.3.2`
- `permission_handler ^11.3.1`
- `flutter_inappwebview ^6.1.5`

**Python (requirements.txt)**
- `fastapi==0.135.2`, `uvicorn[standard]==0.42.0`, `pydantic==2.7.4`
- `python-dotenv==1.0.1`
- `google-genai` (신규 SDK — `google-generativeai`는 deprecated)
- `requests` (단축 URL 해제)
- `python-Levenshtein` (도메인 유사도)
- `python-whois==0.9.5` (ANL-05 도메인 등록일 조회)
- `tldextract==5.1.2` (registered_domain 추출)
- `docker` (Docker SDK, 컨테이너 생성/관리)
- `unicodedata2` (동형문자 탐지)

### Gemini 모델
- 사용 모델: `gemini-2.5-flash`
- ⚠️ `gemini-2.0-flash`, `gemini-2.0-flash-lite` — deprecated, 2026-06-01 완전 종료. **사용 금지.**

---

## 3. 아키텍처 불변 원칙

> 이 원칙들은 어떤 상황에서도 바꾸지 않는다.

1. **Gemini는 7-B 요약자다.** 판정 권한 없음. 파이프라인(/analyze)에서 완전 제거. 7-B findings 목록을 자연어로 요약하는 역할만.
2. **모르면 무조건 의심.** 블랙/화이트 모두 미스인 URL은 판정 없이 의심 반환.
3. **블랙리스트 히트 URL을 KISA에 재신고하지 않는다.** 이미 신고된 URL — 논리적 모순.
4. **안전 화면에서 "공식 사이트로 이동" 버튼을 만들지 않는다.** 오매핑 시 앱이 피해에 공모.
5. **Gemini 호출은 7-B 1회만.** /analyze 엔드포인트에서는 0원. 7-B findings 요약 시에만 호출.
6. **판정 설명은 사전 검증된 딕셔너리로만.** `explanation_service.py`의 `EXPLANATION_DICT`에서만 꺼냄. LLM 즉석 생성 금지 — 할루시네이션 방지.

### 판정 레이블 정책

| 코드 내부 (Enum/API) | UI 표시 / 문서 | 신호등 |
|---------------------|--------------|--------|
| `danger` | 위험 | 빨강 |
| `suspicious` | 의심 | 노랑 |
| `safe` | 안전 | 초록 |

---

## 4. 코딩 규칙

### 4-1. 디렉토리 구조

**전체 레포 구조 (GitHub 루트)**
```
security_hub/
├── frontend/                        ← 멤버 A 전담
├── backend/                         ← 멤버 B 전담
├── data/                            ← 멤버 C 전담
├── docs/
│   └── CLAUDE_CONTEXT_v0507.md
├── .gitignore
└── README.md
```

**frontend/ — 멤버 A**
```
frontend/
├── lib/
│   ├── main.dart
│   ├── models/
│   │   └── analysis_result.dart         # AnalysisResult, RiskStatus
│   ├── services/
│   │   └── api_service.dart
│   ├── screens/
│   │   ├── home_screen.dart             # 홈 화면 + 클립보드 배너 (setState 인트리, ✅ Sprint 5E)
│   │   ├── sandbox_browse_screen.dart   # 7-A 직접 탐방 + 투표 모달 + Kasm 세션 만료 처리 (✅ Sprint 5E)
│   │   └── virtual_sandbox_screen.dart  # 7-B AI 자동 테스트
│   └── widgets/
│       └── traffic_light.dart
├── pubspec.yaml
└── README.md
```

**backend/ — 멤버 B**
```
backend/
├── main.py                      # FastAPI 진입점, CORS, lifespan, 보안 미들웨어
├── config.py                    # 상수 관리
├── requirements.txt
├── .env                         # GEMINI_API_KEY (Git 제외)
├── security_hub.db              # SQLite DB (Git 제외)
├── routers/
│   ├── analyze.py               # POST /analyze
│   └── sandbox.py               # POST /sandbox/browse, DELETE /sandbox/browse/{id}, POST /sandbox/auto-test
├── schemas/
│   └── analysis.py              # Pydantic 요청/응답 스키마
├── services/
│   ├── analysis_service.py      # 파이프라인 오케스트레이터 (0~8단계)
│   ├── url_validator.py         # 신규: 위험 스킴·IP URL·서브도메인 스푸핑·동형문자 탐지
│   ├── url_expander.py          # 단축 URL 해제 (최대 3단계 체인)
│   ├── heuristic_scorer.py      # 신규: 다신호 위험도 점수 계산
│   ├── explanation_service.py   # 신규: 딕셔너리 기반 판정 설명 생성
│   ├── gemini_service.py        # 역할 변경: 7-B findings 자연어 요약 전용
│   ├── domain_similarity.py     # Levenshtein 유사도
│   ├── domain_reputation_service.py  # ANL-05 도메인 평판 분석
│   ├── browse_service.py        # 7-A: kasmweb 컨테이너 생성/관리
│   └── sandbox_service.py       # 7-B: Browserless + Playwright 자동 분석
├── database/
│   ├── db_init.py               # SQLite 연결 + 테이블 초기화
│   ├── blacklist_service.py     # 블랙리스트 3단계 조회
│   ├── whitelist_service.py     # 화이트리스트 조회 + 쿼리스트링 패턴
│   ├── reputation_cache_service.py  # 신규: domain_reputation_cache 읽기/쓰기
│   └── vote_service.py          # 신규: url_votes 저장/집계
│   # 삭제: cache_service.py (suspicious_cache 삭제로 불필요)
├── tests/
│   ├── test_domain_reputation.py
│   └── test_heuristic_scorer.py # 신규: 스코어링 TC
└── README.md
```

**data/ — 멤버 C**
```
data/
├── scripts/
│   ├── load_ctas_csv.py         # C-TAS CSV → blacklist DB 적재 (registered_domain 포함)
│   ├── load_whitelist_csv.py    # 화이트리스트 CSV 적재
│   └── migrate_db.py            # 신규: DB 마이그레이션 스크립트
├── sandbox/
│   └── playwright_runner.py
├── raw/                         # C-TAS CSV 원본 (Git 제외)
└── README.md
```

### 4-2. 명명 규칙
- Dart: `camelCase` (변수/함수), `PascalCase` (클래스/Widget/Enum)
- Python: `snake_case` (변수/함수), `PascalCase` (클래스/Pydantic 모델)

### 4-3. 방어적 프로그래밍 (필수)
- 모든 외부 통신(Gemini, DB, URL 해제)은 `try-catch` + 폴백 처리.
- 빈 입력값은 서버 전송 전에 프론트에서 먼저 차단.
- `mounted` 체크: 비동기 완료 후 위젯 소멸 시 setState 방지.
- DB 조회 실패 → SUSPICIOUS 반환 (보수적 폴백).
- Gemini 실패 → findings 목록 그대로 노출 (서비스 중단 없음).
- DB 커넥션: 읽기전용(분석용) / 쓰기(캐시·투표 적재) 분리.

### 4-4. 문서화
- 핵심 클래스·함수 상단에 Docstring 필수 (역할, 파라미터, 반환값).
- TODO 형식: `// TODO: [스프린트명] 설명`

### 4-5. 개발 프로세스
- **TC-First**: 새 기능 코드 전에 TC를 먼저 작성한다.
- **DC 로그 원칙**: 설계가 바뀌면 반드시 이유를 DC 로그로 기록한다.
- **코드 제공**: 복사해서 덮어쓸 수 있는 완전한 코드 블록으로 제공.
- **PowerShell 환경**: 모든 터미널 명령어는 PowerShell 문법으로 제공.

---

## 5. 서버 실행 명령어

```powershell
# 백엔드 (venv 활성화 상태)
cd C:\dev\security_hub\backend
venv\Scripts\Activate.ps1
uvicorn main:app --reload --port 8000

# DB 마이그레이션 (최초 1회 또는 스키마 변경 시)
cd C:\dev\security_hub
python data/scripts/migrate_db.py

# CSV 적재 (최초 1회)
$env:PYTHONPATH = "C:\dev\security_hub\backend"
python data/scripts/load_ctas_csv.py --dir data/raw/

# Flutter
cd C:\dev\security_hub\frontend
flutter run
```

> ⚠️ 에뮬레이터 → 백엔드 주소: `http://10.0.2.2:8000`
> ⚠️ kasmweb은 HTTPS(6901) / HTTP(6902). Flutter WebView는 6902 + `android:usesCleartextTraffic="true"` 필요.

---

## 6. 색상 팔레트

| 상태 | Primary | Background | Border |
|------|---------|-----------|--------|
| 안전 | `#0F9B58` | `#ECFDF5` | `#6EE7B7` |
| 의심 | `#D97706` | `#FFFBEB` | `#FCD34D` |
| 위험 | `#DC2626` | `#FEF2F2` | `#FCA5A5` |
| 앱 Primary | `#1A56DB` | `#F8F9FC` | `#E5E7EB` |

---

## 7. 분석 파이프라인 (강화판)

```
[0단계] URL 존재 여부  ✅ Sprint 5E
    URL 없음 → 즉시 SUSPICIOUS. 종료.

[1단계] 위험 스킴 필터  ✅ Sprint 5E  (url_validator.py)
    javascript:, data:, vbscript:, file:/ → 즉시 DANGER. 종료.
    (ftp://, gopher:// 등 → 추후 SUSPICIOUS 강등 가능, 현재 미구현)

[2단계] 단축 URL 해제  ✅ Sprint 5A  (url_expander.py)
    최대 3-hop 체인 추적. SSRF 방어(사설 IP 차단).
    실패 시 → 원본 URL 그대로 3단계로.
    더블 URL 디코딩: unquote(unquote(url)) — %252F 우회 방지
    IDN → ASCII 변환: encode('idna') — 동형문자 Punycode 정규화
    동형문자 탐지: 다중 스크립트 혼용 → evidence 플래그

[3단계] 블랙리스트 매칭  ✅ Sprint 5A+DC-24  (blacklist_service.py)
    1차: url_hash SHA256 정확 일치 (O(1))
    2차: domain 일치 (netloc 전체)
    3차: registered_domain 일치 (m.evil.com → evil.com)
    히트 → DANGER + evidence 생성 + explanation_dict 조회. 종료.

[4단계] 화이트리스트 매칭  ✅ Sprint 5A+DC-08  (whitelist_service.py)
    exact / suffix / pattern 3모드 (registered_domain 기준 Levenshtein)
    서브도메인 스푸핑 검사: naver.com.evil.kr 패턴 → SUSPICIOUS 강등
    히트 + 스푸핑 없음 + 위험 쿼리 없음 → SAFE. Gemini 미호출. 종료.  ← SAFE 유일 경로
    히트 + (스푸핑 OR Open Redirect) → SUSPICIOUS 강등

[5단계] 도메인 평판 캐시 조회  ✅ Sprint 5D+5E  (reputation_cache_service.py)
    registered_domain 기준, TTL 7일
    캐시 히트 → domain_age_days, ssl_valid, ssl_issued_days 반환 → 7단계로
    캐시 미스 → 6단계에서 실조회 후 캐시 저장

[6단계] WHOIS/SSL 실시간 조회  ✅ Sprint 5D  (domain_reputation_service.py)
    캐시 미스 시에만 호출.
    WHOIS → domain_age_days / SSL → ssl_valid, ssl_issued_days
    결과 → domain_reputation_cache 저장 (TTL 7일)
    evidence 보강 (판정 변경 없음 — 7단계 점수에 반영됨)
    ※ ccTLD(.gg 등) creation_date str 반환 버그 수정 완료 (Sprint 5D 버그픽스)
      파싱 포맷 5종 순차 시도: %Y-%m-%d / %Y-%m-%dT%H:%M:%SZ /
      %Y-%m-%d %H:%M:%S / %d-%b-%Y / %d %b %Y

[7단계] 휴리스틱 스코어링  ✅ Sprint 5E  (heuristic_scorer.py)
    다신호 가중합 계산:
    - 도메인 7일 미만    → +40점
    - 도메인 7~30일     → +20점
    - SSL 없음           → +30점
    - SSL 발급 7일 미만  → +20점
    - Levenshtein ≤ 2   → +35점 (registered_domain 기준)
    - 서브도메인 스푸핑  → +40점
    - 위험 스킴          → +50점 (1단계에서 이미 차단, 이중 방어)
    - IP 직접 접속       → +30점
    - 더블 인코딩        → +25점
    - 동형문자           → +30점
    - 위험 쿼리 파라미터 → +15점
    - 사전 url_votes danger 신고 1건+ → +20점
    - 사전 sandbox_results score≥70   → +30점
    score ≥ 60 → DANGER (explanation_dict 조회). 종료.
    score < 60 → SUSPICIOUS (화이트리스트 미스 = 항상 SUSPICIOUS — DC-06)

[8단계] 설명 카드 생성  ✅ Sprint 5E  (explanation_service.py)
    triggered_rules → explanation_service.build_explanation()
    → ExplanationCard(icon, title, desc) 리스트 반환
    → url_votes 집계 포함 (해당 URL 기존 투표 있으면)
    → AnalyzeResponse(cards=[...]) 응답
```

### 파이프라인 설계 원칙
- **Early Return**: 확정 판정 시 즉시 반환.
- **FN 최소화 우선**: 화이트리스트 미스 = 항상 SUSPICIOUS. 절대 SAFE로 폴백하지 않는다. (DC-06)
- **설명 일관성**: 모든 설명은 `EXPLANATION_DICT`에서. LLM 즉석 생성 금지. (DC-25)
- **휴리스틱 단방향**: 스코어링은 DANGER 상향만 가능. SAFE 반환 불가.

---

## 8. DB 스키마 (v2 — 2026-05-03 개편)

### blacklist

```sql
CREATE TABLE IF NOT EXISTS blacklist (
    url_hash          TEXT NOT NULL UNIQUE,   -- SHA256(정규화URL), 1차 조회키
    domain            TEXT NOT NULL,           -- netloc 전체, 2차 조회키
    registered_domain TEXT,                    -- tldextract 결과 (evil.com), 3차 조회키
    category          TEXT,                    -- 공공기관/택배/금융/기타
    url               TEXT NOT NULL,           -- 원본 URL (역추적용)
    source            TEXT NOT NULL DEFAULT 'C-TAS',
    reported_at       TEXT NOT NULL            -- ISO8601
);
CREATE INDEX IF NOT EXISTS idx_bl_domain     ON blacklist(domain);
CREATE INDEX IF NOT EXISTS idx_bl_registered ON blacklist(registered_domain);
```

### whitelist

```sql
CREATE TABLE IF NOT EXISTS whitelist (
    domain            TEXT NOT NULL UNIQUE,    -- 매칭 기준 (naver.com / .go.kr)
    registered_domain TEXT,                    -- Levenshtein 비교 단위
    category          TEXT NOT NULL,           -- 카카오계열/정부기관 등
    match_mode        TEXT NOT NULL,           -- exact | suffix | pattern
    risk_level        TEXT NOT NULL DEFAULT 'normal', -- normal | high_risk (+10점)
    source            TEXT NOT NULL DEFAULT 'manual',
    added_at          TEXT NOT NULL
);
```

### domain_reputation_cache
> suspicious_cache 삭제 후 신설. WHOIS/SSL I/O 결과 캐시. domain 단위, TTL 7일.

```sql
CREATE TABLE IF NOT EXISTS domain_reputation_cache (
    registered_domain TEXT NOT NULL UNIQUE,   -- 조회키 (evil.com 단위)
    domain_age_days   INTEGER,                -- WHOIS 경과일. NULL=조회실패
    ssl_valid         INTEGER,                -- 1=유효 / 0=없음 / NULL=연결실패
    ssl_issued_days   INTEGER,                -- SSL 발급 후 경과일
    cached_at         TEXT NOT NULL,
    expires_at        TEXT NOT NULL           -- cached_at + 7일
);
CREATE INDEX IF NOT EXISTS idx_rep_expires ON domain_reputation_cache(expires_at);
```

### url_votes
> 구 user_reports 테이블 전면 교체. 7-A 직접 탐방 종료 후 투표만 수집.

```sql
CREATE TABLE IF NOT EXISTS url_votes (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    url               TEXT NOT NULL,
    domain            TEXT NOT NULL,
    registered_domain TEXT,                   -- 도메인 단위 집계 기준
    vote_type         TEXT NOT NULL,          -- 'danger' | 'safe'
    session_id        TEXT NOT NULL UNIQUE,   -- FK→sandbox_results. 중복 투표 방지
    voted_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_votes_domain     ON url_votes(domain);
CREATE INDEX IF NOT EXISTS idx_votes_registered ON url_votes(registered_domain);
```

### sandbox_results
> 7-A/7-B 세션 결과 저장. 재테스트 캐시 + url_votes FK 연결.

```sql
CREATE TABLE IF NOT EXISTS sandbox_results (
    session_id        TEXT NOT NULL PRIMARY KEY, -- UUID
    url               TEXT NOT NULL,
    domain            TEXT NOT NULL,
    registered_domain TEXT,
    url_hash          TEXT NOT NULL,             -- 재테스트 캐시 조회키
    mode              TEXT NOT NULL,             -- '7a' | '7b'
    sandbox_score     INTEGER,                   -- 7-B 룰 기반 0~100. 7-A=NULL
    findings_json     TEXT NOT NULL DEFAULT '[]',
    created_at        TEXT NOT NULL,
    expired_at        TEXT NOT NULL              -- created_at + 24h
);
CREATE INDEX IF NOT EXISTS idx_sb_url_hash ON sandbox_results(url_hash);
CREATE INDEX IF NOT EXISTS idx_sb_domain   ON sandbox_results(domain);
CREATE INDEX IF NOT EXISTS idx_sb_expires  ON sandbox_results(expired_at);
```

### DB 커넥션 분리 정책

```python
read_conn  = sqlite3.connect("security_hub.db", check_same_thread=False)
read_conn.execute("PRAGMA query_only = ON")

write_conn = sqlite3.connect("security_hub.db", check_same_thread=False)
write_conn.execute("PRAGMA journal_mode = WAL")
```

### 테이블 관계
```
sandbox_results.session_id  ──(1:N FK)──→  url_votes.session_id
(7-A 세션 종료 후 투표만 연결. 7-B는 url_votes와 무관.)

블랙리스트 후보 집계 쿼리:
SELECT registered_domain, COUNT(*) as danger_votes
FROM url_votes WHERE vote_type='danger'
GROUP BY registered_domain HAVING danger_votes >= 3;
```

---

## 9. C-TAS 블랙리스트 데이터

| 지표 | 2024년 | 2026년 |
|------|--------|--------|
| 전체 URL 수 | 28,443건 | 154건 |
| 고유 URL 수 | 5,886개 | 84개 |
| 단축 URL | 4,712건 (16%) | 2건 |
| smType 1위 | 택배 | 공공기관 (71%) |

---

## 10. URL 추출 및 정규화 설계

### 2단계 URL 추출

```python
PATTERN_WITH_PROTO    = re.compile(r'https?://[^\s\u3000\u200b]+')
KNOWN_TLDS            = r'(?:com|kr|net|org|io|me|link|ly|de|info|biz|co)'
PATTERN_WITHOUT_PROTO = re.compile(
    r'(?<![/\w])([a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9]'
    r'\.' + KNOWN_TLDS + r'(?:\.[a-zA-Z]{2})?(?:/[^\s\u3000\u200b]*)?)'
)
```

### url_hash 정규화 원칙 (강화판)

```python
from urllib.parse import urlparse, unquote
import tldextract

def normalize_and_hash(url: str) -> tuple[str, str, str]:
    """
    URL 정규화 후 해시 계산.
    반환: (normalized, url_hash, registered_domain)
    DB 적재(load_ctas_csv.py)와 반드시 동일 로직 사용.
    """
    # 더블 인코딩 우회 방지: 2회 decode
    url = unquote(unquote(url.strip()))
    if '://' not in url:
        url = f'https://{url}'

    parsed = urlparse(url.lower())

    # IDN → ASCII (Punycode 정규화)
    try:
        netloc = parsed.netloc.encode('idna').decode('ascii')
    except (UnicodeError, UnicodeDecodeError):
        netloc = parsed.netloc

    # 쿼리스트링 제거: path까지만 해시
    normalized = (netloc + parsed.path).rstrip('/')
    url_hash   = hashlib.sha256(normalized.encode()).hexdigest()

    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}" if ext.domain else netloc

    return normalized, url_hash, registered_domain
```

---

## 11. explanation_service.py 설계 (Gemini 대체)

```python
EXPLANATION_DICT = {
    "blacklist_exact":   {"icon": "🚨", "title": "신고된 피싱 사이트",
                          "desc": "KISA에 피싱 사이트로 신고된 URL입니다."},
    "blacklist_domain":  {"icon": "🚨", "title": "피싱 도메인",
                          "desc": "이 도메인의 피싱 사이트가 KISA에 신고된 전적이 있습니다."},
    "new_domain_7d":     {"icon": "⚠️", "title": "신규 도메인 ({days}일)",
                          "desc": "도메인 등록 {days}일. 피싱 사이트는 탐지를 피해 새 도메인을 자주 만듭니다."},
    "new_domain_30d":    {"icon": "⚠️", "title": "단기 도메인 ({days}일)",
                          "desc": "도메인 등록 후 30일이 지나지 않았습니다."},
    "no_ssl":            {"icon": "⚠️", "title": "보안 연결 없음",
                          "desc": "HTTPS를 사용하지 않아 입력 정보가 노출될 수 있습니다."},
    "new_ssl":           {"icon": "⚠️", "title": "신규 SSL ({days}일)",
                          "desc": "인증서 발급 {days}일. 피싱용 인증서 특성입니다."},
    "typosquat":         {"icon": "🚨", "title": "유사 도메인 ({similar})",
                          "desc": "'{input}'은 '{similar}'와 매우 유사한 가짜 주소입니다."},
    "subdomain_spoof":   {"icon": "🚨", "title": "주소 위장 ({known})",
                          "desc": "'{known}'처럼 보이도록 위장했지만 실제 다른 사이트입니다."},
    "dangerous_scheme":  {"icon": "🚨", "title": "위험한 URL 형식",
                          "desc": "정상 사이트에서 사용하지 않는 특수 형식({scheme})입니다."},
    "ip_url":            {"icon": "⚠️", "title": "IP 직접 접속",
                          "desc": "숫자 주소({ip}) 직접 접속. 정상 서비스는 도메인을 사용합니다."},
    "double_encoded":    {"icon": "⚠️", "title": "URL 인코딩 우회",
                          "desc": "비정상적으로 인코딩된 URL. 보안 필터 우회 수법일 수 있습니다."},
    "homograph":         {"icon": "🚨", "title": "동형문자 공격",
                          "desc": "다른 언어 문자를 섞어 정상 주소처럼 위장한 도메인입니다."},
    "redirect_param":    {"icon": "⚠️", "title": "자동 이동 파라미터",
                          "desc": "클릭 시 의도하지 않은 사이트로 이동될 수 있습니다."},
    "prior_danger_vote": {"icon": "⚠️", "title": "사용자 위험 신고 ({count}건)",
                          "desc": "다른 사용자가 이 사이트를 직접 방문 후 위험으로 신고했습니다."},
}

def build_explanation(triggered_rules: list[tuple[str, dict]]) -> list[dict]:
    """triggered_rules: [("typosquat", {"input": "naverr.com", "similar": "naver.com"}), ...]"""
    result = []
    for rule_key, params in triggered_rules:
        tmpl = EXPLANATION_DICT.get(rule_key)
        if tmpl:
            result.append({
                "icon":  tmpl["icon"],
                "title": tmpl["title"].format(**params),
                "desc":  tmpl["desc"].format(**params),
            })
    return result
```

---

## 12. 가상 샌드박스 설계 (Sprint 7)

### 7-A 직접 탐방 — `kasmweb/chromium:1.14.0`

**보안 강화 컨테이너 설정 (DC-27):**
```python
docker run -d
  --name sandbox_{uuid}
  -p 127.0.0.1:{random}:6902   # 로컬호스트 바인딩 강제 (외부 노출 방지)
  -e VNC_PW={uuid4().hex}      # UUID 랜덤 비밀번호 (하드코딩 금지)
  -e LAUNCH_URL={url}
  --shm-size=512m
  --memory=512m                 # 컨테이너 메모리 제한
  --cpus=0.5                    # CPU 제한
  --network sandbox_net_{uuid}  # 격리 네트워크
  --dns=1.1.1.1                 # 외부 DNS만 (DNS 리바인딩 방어)
  kasmweb/chromium:1.14.0
```

**Flutter WebView URL:**
```
http://10.0.2.2:{port}/#/?password={vnc_pw}&autoconnect=1
```

**7-A 투표 기능 (신규):**
```
세션 종료 시 Flutter 모달:
"직접 둘러보신 소감이 어떠세요?"
[🚨 위험해 보여요]   [✅ 안전해 보여요]

→ POST /votes {url, session_id, vote_type}
→ url_votes 저장
→ 다음 조회 시 "사용자 투표: 위험 3 / 안전 1" 표시
```

> 투표 신뢰도: session_id UNIQUE 제약으로 중복 투표 방지. 7-A 직접 탐방 후만 수집.

### 7-B AI 자동 테스트 — `ghcr.io/browserless/chromium`

**헤드리스 탐지 우회 (신규):**
```python
await page.set_extra_http_headers({
    "User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36",
    "Accept-Language": "ko-KR,ko;q=0.9",
})
await page.add_init_script("""
    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
    Object.defineProperty(navigator, 'plugins',   {get: () => [1, 2, 3]});
""")
```

**sandbox_score 계산 (룰 기반):**
```python
# score = 룰 기반 합산 (0~100). Gemini는 findings 자연어 요약만.
score += 30  # form_with_password
score += 40  # external_form_action
score += 50  # auto_download
score += 20  # redirect_count >= 3
score += 25  # clipboard_access
# score >= 70 → user_votes 파이프라인 신호에서 +30점 반영
```

**결과 저장:** → `sandbox_results` 테이블 (TTL 24h 캐시)

### 7-A vs 7-B 비교

| | 7-A 직접 탐방 | 7-B AI 자동 테스트 |
|--|--|--|
| Docker 이미지 | `kasmweb/chromium:1.14.0` | `ghcr.io/browserless/chromium` |
| 사용자 역할 | 직접 조작 | 결과 확인만 |
| 투표 수집 | ✅ 세션 종료 시 | ❌ |
| Gemini 사용 | ❌ | ✅ findings 요약만 |
| 결과 저장 | sandbox_results (mode=7a) | sandbox_results (mode=7b) |

---

## 13-B. Sprint 5E 구현 상세

### schemas/analysis.py 변경

```python
class ExplanationCard(BaseModel):
    icon:  str
    title: str
    desc:  str

class AnalyzeResponse(BaseModel):
    status:      str                      # "safe" | "suspicious" | "danger"
    description: str                      # 하위 호환용 (cards_to_text() 결과)
    cards:       list[ExplanationCard]    # 신규: UI 카드 목록
    evidence:    dict | None = None

def cards_to_text(cards: list[ExplanationCard]) -> str:
    """cards → description 문자열 변환 (하위 호환)"""
    return " / ".join(f"{c.icon} {c.title}: {c.desc}" for c in cards)
```

### frontend/lib/screens/home_screen.dart — 클립보드 배너

```dart
// 상태 변수
bool _clipboardBannerVisible = false;
String _clipboardPendingText = '';
Timer? _clipboardBannerTimer;

// 구조: Scaffold.body = Stack(fit: StackFit.expand)
// if (_clipboardBannerVisible)
//   → Positioned(bottom: padding.bottom + 16) → _buildClipboardBanner()

// Android 12+ 시스템 토스트 충돌 방지: _checkClipboard()에서 1800ms 지연 후 배너 표시
// URL 없는 텍스트 → "URL이 포함되어 있지 않습니다" 안내 후 차단
// 배너 자동 소멸: 7초 Timer (_clipboardBannerTimer)
// dispose()에서 _clipboardBannerTimer?.cancel()
```

### frontend/lib/screens/sandbox_browse_screen.dart — Kasm 세션 만료

```dart
// bool _sessionExpired 상태
// onVncDisconnect JS 핸들러 → setState(() => _sessionExpired = true)
// onLoadStop: JS 인젝션 (30초 시작 지연, 8초 폴링 + MutationObserver)
//   감지: #noVNC_status 텍스트 disconnect/failed
//       또는 DOM에 "session+expired/timeout/idle" 텍스트 포함 노드
// _buildSessionExpiredOverlay(): "세션이 종료되었습니다" + "새 세션 시작" 버튼
// 오류 오버레이보다 세션 만료 오버레이가 우선 렌더링
```

---

## 13. 백엔드 보안 설정 (Sprint 5E 완료)

```python

class BlockDangerousMethodsMiddleware(BaseHTTPMiddleware):
    """TRACE / CONNECT / TRACK 405 차단 (KISA 불필요한 Method 항목)"""
    async def dispatch(self, request: Request, call_next):
        if request.method in ("TRACE", "CONNECT", "TRACK"):
            return JSONResponse(status_code=405, content={"detail": "Not Allowed"})
        return await call_next(request)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """보안 응답 헤더 주입"""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]         = "DENY"
        response.headers["X-XSS-Protection"]        = "1; mode=block"
        response.headers["Referrer-Policy"]         = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

@app.exception_handler(Exception)
async def suppress_internal_errors(request, exc):
    """전역 예외 핸들러 — 스택 트레이스/DB 경로/내부 IP 미노출 (KISA EP 항목)"""
    logger.error(f"[Internal] {type(exc).__name__}: {exc}", exc_info=True)
    return JSONResponse(status_code=500,
                        content={"detail": "서버 오류. 잠시 후 다시 시도해주세요."})

# lifespan: 시작 시 init_db() + purge_expired(), 종료 시 shutdown_all_sessions()
```

---

## 14. 정량 목표 지표

| 지표 | 목표 | 측정 방법 |
|------|------|----------|
| CTAS 블랙리스트 탐지율 | ≥ 95% | C-TAS 84개 URL 전수 검증 TC |
| 위험 스킴 차단율 | 100% | javascript:/file:// 등 10케이스 TC |
| 서브도메인 스푸핑 탐지율 | ≥ 85% | 수동 생성 20케이스 |
| 오탐률 (FP Rate) | < 5% | 화이트리스트 도메인 100개 TC |
| 동형문자 탐지율 | ≥ 80% | 키릴/그리스 혼용 10케이스 |

> CTAS 탐지율 95%: 외부 의존성(WHOIS 타임아웃, 단축URL 해제 실패) 감안. 정규화 버그 수정 후 코드 제어 범위 내 100% 목표.

---

## 15. E2E 시나리오

### 시나리오 A: 위험 (블랙리스트)
```
입력: [Web발신][정부24] 벌점통지서발송. gov.oe3m.me
→ 1단계: 위험 스킴 아님 → 통과
→ 2단계: 단축 URL 해제 (해당 없음)
→ 3단계: url_hash 블랙리스트 히트 (category: 공공기관)
→ explanation_dict 조회 → "신고된 피싱 사이트" 카드
→ 위험 화면 | 응답 ~100ms
```

### 시나리오 B: 위험 (휴리스틱)
```
입력: http://naverr.com/login (CTAS 미등록 신규 피싱)
→ 블랙/화이트 미스
→ 7단계: 도메인 3일(+40) + SSL 없음(+30) + Levenshtein 1(+35) = 105점 ≥ 60
→ DANGER + explanation_dict ["typosquat", "new_domain_7d", "no_ssl"]
→ 위험 화면 | Gemini 미호출
```

### 시나리오 C: 안전
```
입력: [국민건강보험] 검진 안내. www.nhis.or.kr
→ 화이트리스트 히트 (위험 쿼리 없음, 스푸핑 없음)
→ 안전 즉시 반환 | 응답 ~50ms
```

### 시나리오 D: 의심
```
입력: http://coupang-delivery.info/recheck
→ 블랙/화이트 미스
→ 7단계: score=20 (60 미만) → SUSPICIOUS
→ 8단계: explanation_dict ["redirect_param"] → 의심 화면
→ 7-A 직접 탐방 후 투표 → url_votes 저장
```

---

## 16. 설계 변경 이력 (DC 로그)

| # | 원문/이전 | 변경 내용 | 변경 사유 | 날짜 |
|---|---------|---------|---------|------|
| DC-01 | "화이트리스트 → 공식 사이트 안내" | 폐기 | 오매핑 시 피해 유발 | 2026-03-26 |
| DC-02 | "DANGER 시 KISA 신고" | 블랙리스트 DANGER 재신고 제거 | 이미 신고된 URL — 모순 | 2026-03-29 |
| DC-03 | "VirusTotal/GSB 활용" | 초기 C-TAS만 사용 | 범위 한정 | 2026-03-29 |
| DC-04 | "Gemini가 판정" | Gemini = evidence 번역만 | AI 오판 시 피해 공모 | 2026-03-30 |
| DC-05 | "DANGER 시 항상 KISA 신고" | 샌드박스 신규 위협 시만 | 블랙리스트 히트=이미 신고 | 2026-03-30 |
| DC-06 | "SUSPICIOUS 시 Gemini 미호출" | 의심에도 번역 수행 | 사유 설명 필요 | 2026-03-30 |
| DC-07 | "Gemini가 사유 생성" | 파이프라인 evidence, Gemini 번역만 | 할루시네이션 방지 | 2026-04-14 |
| DC-08 | "화이트 히트=무조건 SAFE" | 위험 쿼리 포함 시 SUSPICIOUS | 쿼리 기반 공격 대응 | 2026-04-14 |
| DC-09 | "URL 풀매치만" | Levenshtein 유사도 추가 | 타이포스쿼팅 탐지 | 2026-04-14 |
| DC-10 | "매번 전체 재분석" | suspicious_cache 도입 | Gemini 절약+속도 | 2026-04-14 |
| DC-11 | "구성도 파이프라인만" | Share Intent/클립보드 추가 | 교수 피드백 | 2026-04-14 |
| DC-12 | "구성도 Gemini 표기" | "AI 설명 서비스(LLM)"로 | 벤더 종속 노출 방지 | 2026-04-14 |
| DC-13 | "영문 레이블" | UI/문서 한글화 | 심사 가독성 | 2026-04-14 |
| DC-14 | "단일 임계값" | Levenshtein ≤2 (짧은), ≤3 (긴) | FP 감소 | 2026-04-14 |
| DC-15 | "캐시 무기한" | TTL 7일 | 피싱 사이트 평균 생존 7일 | 2026-04-16 |
| DC-16 | "http/https만 추출" | KNOWN_TLDS 기반 프로토콜 없는 도메인도 | C-TAS 다수 존재 | 2026-04-17 |
| DC-17 | "단일 커넥션" | 읽기/쓰기 분리 | 동시성 안전 | 2026-04-17 |
| DC-18 | "5단계 파이프라인" | ANL-05 도메인 평판 6단계 삽입 | 신규 피싱 탐지 강화 | 2026-04-27 |
| DC-19 | "Playwright 단독" | Browserless+Playwright CDP | 동시성 과부하 방지 | 2026-04-27 |
| DC-20 | "프론트 http/https만" | KNOWN_TLDS 기반 확장 | 백엔드 불일치 해소 | 2026-04-28 |
| DC-21 | "7-A = Browserless" | kasmweb/chromium:1.14.0으로 변경 | Browserless noVNC 미지원 확인 | 2026-04-28 |
| DC-22 | "sandbox_service에 7-A 포함" | browse_service.py 분리 | 책임 분리 원칙 | 2026-05-02 |
| DC-23 | "normalize_url() 단순화" | 더블 디코딩+IDN+쿼리 제거 통합 | 블랙리스트 해시 미매칭 FN 방지 | 2026-05-03 |
| DC-24 | "블랙리스트 2단계 매칭" | registered_domain 3차 매칭 추가 | m.evil.com 서브도메인 갭 FN 방지 | 2026-05-03 |
| DC-25 | "Gemini = 분석 번역자" | Gemini = 7-B findings 요약만. /analyze 완전 제거 | 할루시네이션 0. 딕셔너리로 일관성·속도 향상 | 2026-05-03 |
| DC-26 | "suspicious_cache" | 삭제 → domain_reputation_cache 신설 | Gemini 제거로 캐시 대상이 WHOIS/SSL I/O로 변경 | 2026-05-03 |
| DC-27 | "VNC_PW=sandbox 하드코딩" | UUID 랜덤 비밀번호 + 127.0.0.1 바인딩 | 컨테이너 무단 접근 벡터 제거 (KISA) | 2026-05-03 |
| DC-28 | "user_reports (신고만)" | url_votes (투표)로 전면 교체 | 7-A 직접 탐방 후 danger/safe 투표. safe도 수집 필요 | 2026-05-03 |
| DC-29 | "파이프라인 7단계" | 0단계 위험 스킴 + 5단계 휴리스틱 스코어링 추가 | CTAS 단일 의존 → 다신호 판정으로 보안 앱 기준 충족 | 2026-05-03 |

---

## 17. TC (테스트 케이스)

### TC-D: 위험 판정

| TC-ID | 입력 | 기대 결과 | 검수 포인트 |
|-------|------|---------|------------|
| D-01 | C-TAS 블랙리스트 URL (url_hash 정확 일치) | DANGER + explanation 카드 | blacklist_exact 설명 노출 |
| D-02 | C-TAS URL (registered_domain 일치, 서브도메인 다름) | DANGER | 3차 매칭 동작 |
| D-03 | 단축 URL → 해제 → 블랙리스트 히트 | DANGER | 해제 후 재매칭 |
| D-04 | `javascript:alert(1)` | DANGER (0단계 즉시) | Gemini 미호출, 100ms 이하 |
| D-05 | `file:///etc/passwd` | DANGER (0단계 즉시) | |
| D-06 | CTAS 미등록 + score≥60 | DANGER (휴리스틱) | triggered_rules 리스트 확인 |

### TC-S: 안전 판정

| TC-ID | 입력 | 기대 결과 | 검수 포인트 |
|-------|------|---------|------------|
| S-01 | 화이트리스트 exact (`naver.com`) | SAFE | Gemini 미호출 |
| S-02 | 화이트리스트 suffix (`m.naver.com`) | SAFE | suffix 모드 동작 |
| S-03 | 화이트리스트 + 정상 경로 | SAFE | |
| S-04 | 화이트리스트 + 정상 쿼리 | SAFE | |
| S-05 | 화이트리스트 + `?download=malware.apk` | SUSPICIOUS | 위험 쿼리 강등 |
| S-06 | `naver.com.evil.kr` | SUSPICIOUS (서브도메인 스푸핑) | SAFE 오판 안 함 |

### TC-SU: 의심 판정

| TC-ID | 입력 | 기대 결과 | 검수 포인트 |
|-------|------|---------|------------|
| SU-01 | 블랙·화이트 미스 + score<30 | SUSPICIOUS + explanation 카드 | Gemini 미호출 |
| SU-02 | 단축 URL 해제 실패 (타임아웃) | 원본 URL로 SUSPICIOUS | 폴백 동작 |
| SU-03 | URL 없이 텍스트만 | SUSPICIOUS + 안내 문구 | URL 추출 실패 처리 |
| SU-04 | `ftp://evil.com` | SUSPICIOUS (0단계) | |

### TC-E: 경계값 및 예외

| TC-ID | 입력 | 기대 결과 | 검수 포인트 |
|-------|------|---------|------------|
| E-01 | 빈 문자열 | 프론트 차단 | 서버 요청 미발생 |
| E-02 | 공백만 | 프론트 차단 | trim() 후 검증 |
| E-03 | 10,000자 이상 | 서버 graceful 처리 | 앱 크래시 없음 |
| E-04 | 서버 다운 | 에러 SnackBar | 타임아웃 후 표시 |
| E-05 | 동일 URL 연속 10회 | 정상 처리 | 앱 크래시 없음 |
| E-06 | 한글 포함 URL | 정상 처리 (IDN 변환) | UnicodeError 없음 |
| E-07 | `javascript:alert(1)` | DANGER (0단계) | XSS 실행 안 됨 |
| E-08 | `http://192.168.0.1/login` (사설 IP) | SUSPICIOUS + ip_url 플래그 | SAFE 반환 안 함 |
| E-09 | 단축 URL 2단계 체인 | 최종 URL로 매칭 | 무한 루프 없음 (max 3) |
| E-10 | Gemini 쿼터 소진 | findings 목록 노출 | 서비스 중단 없음 |
| E-11 | `naver.com.evil.kr` | SUSPICIOUS + subdomain_spoof | SAFE 오판 안 함 |
| E-12 | 화이트 + `?auth=token123` | SUSPICIOUS | 화이트 히트여도 강등 |
| E-13 | `аpple.com` (Cyrillic a) | SUSPICIOUS + homograph 플래그 | IDN 처리 + 탐지 |
| E-14 | `http://evil.com/%252fphishing` | 더블 디코딩 후 정상 매칭 | FN 방지 확인 |
| E-15 | `file:///etc/passwd` | DANGER (0단계) | |
| E-16 | TRACE 메서드 요청 | 405 응답 | 스택 트레이스 미노출 |

### TC-SCORE: 휴리스틱 스코어링

| TC-ID | 입력 조건 | 기대 결과 | 검수 포인트 |
|-------|---------|---------|------------|
| SC-01 | domain_age=3 + no_ssl + typosquat | score=105 → DANGER | triggered_rules 3개 |
| SC-02 | domain_age=60 + ssl_valid=True | score=0 → SUSPICIOUS (미달) | 오탐 없음 |
| SC-03 | domain_age=5만 | score=40 → SUSPICIOUS (30~59) | DANGER 오판 안 함 |
| SC-04 | ip_url + double_encoded | score=55 → SUSPICIOUS | |
| SC-05 | prior_votes danger=3 + domain_age=10 | score=40+20=60 → DANGER | 사용자 신호 파이프라인 편입 |

### TC-ANL: 도메인 평판

| TC-ID | 입력 | 기대 결과 | 검수 포인트 |
|-------|------|---------|------------|
| ANL-01 | 등록 15일 도메인 | `domain_age_days=15` | 판정 변경 없음, score에 반영 |
| ANL-02 | 등록 365일+ | `domain_age_days=365+` | new_domain 플래그 없음 |
| ANL-03 | `http://` 도메인 | `ssl_valid=False` | |
| ANL-04 | domain_age≤30 AND ssl_issued≤7 | `fresh_infrastructure=True` | |
| ANL-05 | WHOIS + rdap 모두 실패 | `domain_age_days=None`, 서비스 중단 없음 | graceful 처리 |
| ANL-06 | WHOIS 레코드 없는 도메인 | `whois_no_record=True` | None과 구분 |
| ANL-07 | 서브도메인 포함 URL | registered_domain 추출 후 조회 | 서브도메인째 호출 안 함 |
| ANL-08 | IP 주소 URL | WHOIS/SSL 스킵 | 호출 횟수 assert |
| ANL-09 | `.kr` 도메인 | WHOIS/SSL 스킵 | SKIP_WHOIS_TLDS 동작 |
| ANL-10 | SSL 없음 (연결 성공) | `ssl_valid=False` (None 아님) | 연결실패(None)와 구분 |

### TC-SB: 샌드박스

| TC-ID | 입력 | 기대 결과 | 검수 포인트 |
|-------|------|---------|------------|
| SB-01 | POST /sandbox/browse (정상 URL) | 200 + noVNC URL + session_id | 컨테이너 생성 확인 |
| SB-02 | DELETE /sandbox/browse/{id} | 200 + 컨테이너 종료 | 좀비 컨테이너 없음 |
| SB-03 | Docker Desktop 미실행 | 503 + 명확한 에러 | 앱 크래시 없음 |
| SB-04 | 연속 3회 요청 | 독립 컨테이너 + 독립 포트 | 포트 충돌 없음 |
| SB-05 | 5분 비활성 후 세션 | 컨테이너 자동 종료 | 좀비 방지 |
| SB-06 | 7-A 종료 후 danger 투표 | url_votes 저장 확인 | session_id 중복 투표 방지 |
| SB-07 | 동일 session_id로 재투표 시도 | 409 Conflict | UNIQUE 제약 동작 |
| SB-08 | 동일 URL 7-B 재테스트 (24h 이내) | sandbox_results 캐시 히트 | 재실행 안 함 |

### TC-P: 성능

| TC-ID | 시나리오 | 기준 |
|-------|---------|------|
| P-01 | SAFE 경로 | 100ms 이하 |
| P-02 | 위험 스킴 차단 (0단계) | 50ms 이하 |
| P-03 | 휴리스틱 DANGER (Gemini 미호출) | 3초 이하 |
| P-04 | SUSPICIOUS (캐시 미스) | 5초 이하 |
| P-05 | 동시 3건 요청 | 교차 오염 없음 |

---

## 18. 스프린트 진행 상황

```
Sprint 1  ✅ FastAPI 백엔드 뼈대
Sprint 2  ✅ Gemini 연동
Sprint 3  ✅ Flutter E2E 연결
Sprint 4  ✅ 블랙리스트 DB (C-TAS 2024/2025/2026 적재 완료)

Sprint 5A ✅ 파이프라인 고도화
  - 단축 URL 해제 (url_expander.py)
  - 화이트리스트 DB (exact/suffix/pattern 3모드)
  - analysis_service.py 리팩토링

Sprint 5B ✅ C-TAS 데이터 대량 적재 + 품질 검증

Sprint 5C 🔲 DB 설계 강화
  - 쿼리스트링 위험 패턴 감지
  - 도메인 유사도 (Levenshtein)
  - DB 커넥션 읽기/쓰기 분리
  ※ suspicious_cache → 삭제 확정 (DC-26)
  ※ explanation_service.py / heuristic_scorer.py / url_validator.py 신규 추가로 교체

Sprint 5D ✅ ANL-05 도메인 평판 분석
  - domain_reputation_service.py
  - TC-ANL 10개

Sprint 5E ✅ 보안 강화 (Sprint 5E 완료)
  - analysis_service.py: Gemini /analyze 완전 제거. 0~8단계 파이프라인 확정.
  - url_validator.py: 위험 스킴(0단계), IP URL, 서브도메인 스푸핑, 동형문자
  - heuristic_scorer.py: 다신호 스코어링 (score ≥ 60 → DANGER)
  - explanation_service.py: ExplanationCard 딕셔너리 기반 설명 생성
  - schemas/analysis.py: ExplanationCard Pydantic 모델 + cards 필드 + cards_to_text()
  - domain_reputation_service.py: ccTLD str 반환 버그픽스 (포맷 5종 순차 파싱)
  - main.py v0.5.0: BlockDangerous/SecurityHeaders 미들웨어 분리, lifespan 정비
  - home_screen.dart: 클립보드 배너 3차 수정 완료 (setState 인트리 방식)
  - sandbox_browse_screen.dart: Kasm 세션 만료 처리 완료 (JS 인젝션 + 오버레이)

Sprint 6  ⚠️ 액션 버튼 (부분 완료)
  - SAFE: 면책 고지 + URL 열기 ✅
  - SUSPICIOUS: VirtualSandboxScreen 라우팅 ✅
  - DANGER: url_launcher 연결 🔲
  - 발신번호 입력 필드 🔲
  - 결과 공유 🔲

Sprint 7  ⚠️ 가상 샌드박스 (부분 완료)
  7-A:
    ✅ browse_service.py (kasmweb)
    ✅ sandbox.py 라우터
    ✅ sandbox_browse_screen.dart
    🔲 투표 모달 + /votes 엔드포인트
  7-B:
    ✅ sandbox_service.py
    ✅ virtual_sandbox_screen.dart
    🔲 /sandbox/run ↔ Flutter E2E 검증 미완

Sprint 8  🔲 최종 마무리 및 심사 준비 (W10~W11)
```

---

## 19. 주차별 일정

| 주차 | 기간 | 멤버 A | 멤버 B | 멤버 C |
|------|------|--------|--------|--------|
| W6 | 5/4~5/10 | SAFE 카운트다운 · 공유 | E2E #2 · API 스키마 갱신 | kasmweb/Browserless 검증 |
| W7 | 5/11~5/17 | 투표 모달 (7-A 종료 후) | Sprint 5E 보안 강화 전체 · migrate_db.py | DB 마이그레이션 실행 · 7-A 격리 검증 |
| W8 | 5/18~5/24 | 7-B 결과 화면 · explanation 카드 UI | API 스키마 갱신 · PR 리뷰 | 7-B 자동 테스트 · sandbox_score |
| W9 | 5/25~5/31 | 7-A·7-B 통합 완성 | E2E #3 · 샌드박스 ↔ Flutter 검증 | 7-B 리포트 · 버그 수정 |
| W10 | 6/1~6/7 | UI 버그 수정 | 전체 E2E · 시나리오 전수 | DB 정합성 · 샌드박스 검수 |
| W11 | 6/8~6/12 | 심사 시연 준비 | 최종 통합 · 문서 | 데이터 확인 · 시연 지원 |

> 🔴 W10~W11: 신규 개발 없음.

---

## 20. 멤버 역할 분담

| 멤버 | 역할 | 담당 |
|------|------|------|
| 멤버 A | Frontend | 홈·결과·샌드박스 화면, explanation 카드 UI, 투표 모달 |
| 멤버 B | Backend + 인티그레이터 | 파이프라인, 보안 강화, API 스키마, E2E 통합 |
| 멤버 C | Data & Sandbox | DB 적재/마이그레이션, Playwright 샌드박스, sandbox_score |

---

## 21. GitHub 협업 규칙

```
main  ← 심사용 최종본. 직접 push 금지.
dev   ← 통합 브랜치.
  ├── feat/frontend-*
  ├── feat/backend-*
  └── feat/data-*
```

커밋 메시지: `feat/fix/refactor/docs/test/chore: 설명`

---

## 22. 미결 사항 (Open Questions)

| # | 질문 | 결정 시점 |
|---|------|----------|
| Q-02 | VirusTotal / Google Safe Browsing 연동 여부 | 시간 여유 후 |
| Q-03 | APScheduler 자동 크롤링 구현 여부 | 시간 여유 후 |
| Q-04 | URL 없이 전화번호만 있는 스미싱 처리 | Sprint 6 |
| Q-06 | 도메인 유사도 임계값 실측 FP | Sprint 5C TC 실행 후 |
| Q-07 | 결과 공유 기능 Sprint 배정 | Sprint 6 |
| Q-10 | kasmweb LAUNCH_URL v1.14 동작 여부 | W6 실제 테스트 후 |
| Q-11 | kasmweb 포트 6902 Flutter WebView 호환성 | W6 실제 테스트 후 |
| Q-12 | ~~domain_reputation_cache TTL 24h 적정성~~ | ✅ 해소: TTL 7일로 확정 (DC-15 피싱 평균 생존 7일 기준) |
| Q-13 | 휴리스틱 DANGER 임계값 60점 FP 실측 조정 여부 | Sprint 5E TC 후 |
| Q-14 | kasmweb 1.14.0 CVE 확인 및 심사 대응 문서화 | W7 |

---

## 23. 검수자 페르소나 — 김검수

**실무 10년차 보안 엔지니어 겸 한이음 기술 심사위원.**
감정 없이 기술적 사실만 본다. "실제로 서비스하면 어떤 일이 벌어지냐"는 관점.

### 자동 검수 항목

| 항목 | 검수 질문 |
|-----|---------|
| 예외 처리 | DB 연결 실패와 조회 결과 없음을 코드에서 구분하나? |
| 경계값 | 빈 입력, 10,000자, `javascript:` 스킴, IP형 URL은 처리하나? |
| FN 최소화 | 진짜 피싱을 통과시키는 경우가 있나? |
| 폴백 | Gemini 쿼터 소진 시 서비스가 멈추지 않나? |
| 보안 | `naver.com.evil.kr` 같은 서브도메인 스푸핑을 SAFE로 오판하지 않나? |
| 자원 관리 | kasmweb 동시 요청 시 컨테이너 누수가 없나? |
| TC 완결성 | Happy Path만 있고 에러·경계값 TC가 빠지지 않았나? |
| 설계 근거 | 교수 앞에서 30초 안에 설명할 수 있나? |

### 검수 심화 트리거
`"검수해줘"`, `"태클 걸어줘"`, `"이거 괜찮아?"`, `"심사 준비"`, `"TC 추가해줘"`, `"예외 케이스 뭐 있어?"`

**포맷:**
```
🔍 [김검수 검토]
✅ 통과: ...
⚠️ 태클: ...
💬 예상 심사 질문: "..."
🛠 권고: ...
```

---

## 24. 발표 구조 가이드

```
[슬라이드 1] 전체 일정 + 진행 상황
[슬라이드 2] 완료된 기능 (시연 가능)
[슬라이드 3] 남은 것 + 이유 + 언제까지
[슬라이드 4] 주요 설계 결정 (DC 로그 기반)
[슬라이드 5] 정량 목표 지표 (탐지율, 오탐률 등)
```

---

*이 파일은 새 대화를 시작할 때마다 첨부하여 컨텍스트를 유지한다.*
*코드 변경이 생기면 "CLAUDE_CONTEXT.md 업데이트해줘"라고 요청한다.*
*현재 파일명: CLAUDE_CONTEXT_v0507.md*
