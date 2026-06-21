# Security Hub — CLAUDE_CONTEXT v0610

> 새 대화 시작 시 본 파일을 첨부하여 프로젝트 전체 맥락을 전달한다.
> v0531 → v0610: P1-1(SSRF IP 정규화), P1-3(userinfo %40 우회), 단축URL FP 수정 완료 + 홀드아웃 독립 평가 구축 + 보안 감사 갱신

---

## 0. 문서 정보

| 항목 | 내용 |
|------|------|
| 문서명 | CLAUDE_CONTEXT |
| 버전 | v0610 (2026-06-10) |
| 이전 버전 | v0531 (2026-05-31) — 봉인 |
| 대상 SRS | v11 + `SRS_v11_to_v12_diff.md` |
| 대상 CLAUDE.md | 2026-05-27 갱신본 |
| 다음 갱신 시점 | 큰 결정 발생 시 또는 6월 심사 직전 |
| 진실의 출처 | **코드** > 본 문서 > SRS v11 (코드와 충돌 시 코드 우선) |

---

## 1. 프로젝트 정체성

**이 프로젝트는 단순 피싱 차단 도구가 아니다.**

> **사용자 즉각 피드백 기반 학습형 위협 인텔리전스 시스템**
>
> KISA C-TAS가 못 잡은 신규 위협을 사용자 집단지성(7-A 직접 탐방 + 투표)으로 발견하고, 그 결과가 다음 분석에 즉시 반영되는 피드백 순환 구조.

### 1-1. 차별화 시연 시나리오

1. `evil-bank.kr` 분석 → SUSPICIOUS (휴리스틱 점수 35)
2. 7-A 진입 → 5초 둘러보고 "danger 투표"
3. 같은 URL 재분석 → DANGER (점수 70, prior_danger_vote 시그널 발동)

---

## 2. 기술 스택

| 레이어 | 기술 |
|--------|------|
| 프론트엔드 | Flutter (Android only, APK 직배포, minSdkVersion=21) |
| 백엔드 | Python 3.12 + FastAPI + Uvicorn |
| AI | Google Gemini 2.5 Flash (7-B findings 요약 전용) |
| DB | SQLite (`backend/security_hub.db`, WAL 모드, 부분 인덱스) |
| 7-A 샌드박스 | kasmweb/chromium:1.14.0 (사용자 직접 탐방, noVNC) |
| 7-B 샌드박스 | Browserless + Playwright (AI 자동 테스트) |
| 개발 환경 | Windows PowerShell, `backend/venv/` |

---

## 3. 아키텍처 불변 원칙

**절대 바꾸지 않는다.**

1. **Gemini는 7-B 요약자다.** `/analyze` 파이프라인에서 완전 제거됨 (DC-25).
2. **SAFE는 화이트리스트 히트 단 하나의 경로뿐.** 휴리스틱 점수가 0 이하여도 SAFE 반환 불가 (DC-06, v0527 0 클램프로 강화).
3. **판정 설명 카드는 EXPLANATION_DICT 에서만.** LLM 즉석 생성 금지 (DC-25).
4. **블랙리스트 히트 URL은 KISA 재신고하지 않는다.** (DC-05)
5. **Gemini 모델은 `gemini-2.5-flash`만.** 2.0 시리즈 deprecated.
6. **LLM이 추론한 '공식 사이트'로 이동하는 버튼 없다.** (DC-01) — 단, 화이트리스트 히트로 SAFE 판정된 URL을 사용자가 직접 여는 것은 허용.
7. **KISA Web App 21개 코드는 우리 서버 자가진단 표일 뿐.** 외부 URL 분류 시그널과 직접 매핑되지 않음 (DC-36).

---

## 4. 분석 파이프라인 (실제 코드 단계)

`analysis_service.py` Early Return 구조.

| 단계 | 담당 | 동작 |
|------|------|------|
| 0 | `blacklist_service.extract_urls()` | URL 없음 → SUSPICIOUS |
| 1 | `url_validator.check_dangerous_scheme()` | `javascript:/data:/vbscript:/file:/blob:` → DANGER |
| 2 | `url_expander.expand_url()` | 단축 URL 해제 (최대 3-hop, SSRF 방어). `asyncio.to_thread()` 래핑으로 블로킹 I/O 해소 (DC-42). **DC-49: 10진수·16진수·8진수 IP 정규화 후 SSRF 검증** |
| 3 | `blacklist_service.check_blacklist()` | url_hash → domain → registered_domain 3단계 매칭 → DANGER. **단축URL 서비스 도메인은 hash 매칭만 적용** (DC-46 / P0-1 수정) |
| 4 | `whitelist_service.is_whitelisted()` | 히트 + 스푸핑 없음 → SAFE / Open Redirect → SUSPICIOUS |
| 5 | `reputation_cache_service.get_cached_reputation()` | 캐시 lookup (TTL 7일) |
| 6 | `domain_reputation_service.analyze_domain_reputation()` | 캐시 미스 시 WHOIS/SSL 조회. `asyncio.Lock` + double-check 패턴 (DC-41) |
| 7 | `heuristic_scorer.score_url()` | 다신호 가중합. **score ≥ 70 → DANGER**, ≥ 30 → SUSPICIOUS, < 30 → DC-06 강제 SUSPICIOUS. 음수는 0 클램프. |
| 8 | `explanation_service.build_explanation_cards()` | 카드 리스트 생성 |

### 4-1. 휴리스틱 시그널 25종 가중치 (v0527 확정, 2026-06-21 카운트 정정: 23→25)

```
─ 직접 위협 (+35) ────────────────────────────────────────────────
  ip_in_url              35   |  dangerous_extension   35
  userinfo_injection*    35   |  typosquat_levenshtein* 35
  prior_danger_vote_high 35

─ 강신호 (+30~+40) ──────────────────────────────────────────────
  subdomain_spoofing     30   |  homograph_idn  30 (25→30 상향)
  sandbox_danger_score   40 (30→40 상향)

─ 중신호 (+20) ──────────────────────────────────────────────────
  brand_keyword_mismatch 20   |  new_domain          20
  whois_no_record        20   |  prior_danger_vote_low 20
  suspicious_keywords*   20

─ 약신호 (+5~+15) ───────────────────────────────────────────────
  double_encoding        15   |  excessive_subdomains 15
  fresh_infrastructure   15   |  punycode_in_url*    15
  many_hyphens*          10   |  suspicious_tld     10
  port_in_url            10   |  prior_spam_vote_high 10
  url_too_long            5   |  prior_spam_vote_low   5

─ 음의 시그널 (합산 후 0 클램프) ──────────────────────────────
  prior_safe_vote_high  -15   |  prior_safe_vote_low  -5
```
\* = v0527 신규 시그널 (5종)

### 4-2. 임계값

```
score ≥ 70 → DANGER       (단독 시그널 불가 — 최대 +40, 조합 필요)
score ≥ 30 → SUSPICIOUS
score < 30 → SAFE 반환되지만 DC-06으로 analysis_service가 SUSPICIOUS 강제
score < 0  → 0 으로 클램프 (DC-06 + DC-40 보호)
```

---

## 5. DB 스키마

### 5-1. 운영 중

| 테이블 | 키 | TTL |
|--------|-----|-----|
| `blacklist` | url_hash, domain, registered_domain | 영구 |
| `whitelist` | domain (exact/suffix) | 영구 |
| `domain_reputation_cache` | registered_domain | 7일 |

### 5-2. v0513 도입 + v0527 갱신

#### `url_votes` (DC-30 + DC-39)

```sql
id, session_id UNIQUE, device_uuid, url, domain, registered_domain,
vote CHECK(IN 'safe','danger','spam','unsure'), voted_at

UNIQUE INDEX (device_uuid, registered_domain) WHERE vote IN ('safe','danger','spam')
```

`unsure`는 DB INSERT 안 함. 부분 UNIQUE로 의미 있는 투표만 슬롯 점유.

#### `sandbox_results` / `analysis_history` / `users` (DC-45)

v0531과 동일. 변경 없음.

---

## 6. 가상 샌드박스

v0531과 동일. 변경 없음.

DC-34 (7-A CDP 자동 위협 차단) — **구현 완료로 정정 (2026-06-20)**. 백엔드
`browse_service.py`의 CDP watchdog가 `Page.frameNavigated`/`Page.downloadWillBegin`을
감지해 `_threat_cache`에 기록하고 `terminate_browse_session()`으로 세션을 즉시
종료하며, `routers/sandbox.py`의 `GET /sandbox/browse/{id}/status`가 이를 노출한다.
프론트엔드 `sandbox_browse_screen.dart`가 2초 간격으로 이 엔드포인트를 폴링
(`_pollStatus`/`_startStatusPolling`)해 `_buildThreatOverlay()`로 차단 화면(스크린샷
포함)을 띄운다. 코드 확인 결과 엔드투엔드로 이미 동작하며, 이전 "미구현 확정"
기록은 stale이었다.

---

## 7. 핵심 정책 결정

### 7-1. 1종/2종 오류 정책

| | 우선순위 |
|--|---------|
| 1종 오류 (위험→SAFE) | 최우선 회피. SAFE는 화이트리스트 단독 경로 + 0 클램프 |
| 2종 오류 (안전→DANGER) | 차순위. DANGER 임계값 70, 샌드박스 체험 권유 |

### 7-2. 어그로 방어 5중 (NF-29)

```
Layer 1 (DB)    : (device_uuid, registered_domain) 부분 UNIQUE
Layer 2 (Logic) : 우세 방향성만 시그널 발동
Layer 3 (UX)    : VNC 안정화 30 초 대기
Layer 4 (Score) : 단독 시그널로 DANGER 불가
Layer 5 (Auth)  : 카카오 가입 = 자연인 1 명 = 가중치 부스트 (DC-45)
```

### 7-3. NF-24 Rate Limiting

| 엔드포인트 | 현재 코드 |
|---|---|
| `/analyze` | IP 기반 10/min |
| `/sandbox/browse` | IP 기반 5/min |
| `/sandbox/auto-test` | IP 기반 5/min |
| `/sandbox/votes` | IP 기반 20/min |
| `/auth/kakao` | IP 기반 5/min |

미해소 항목: IP / device_uuid / 하이브리드 키 결정 (Q-19, 보류).

### 7-4. UUID + 카카오 가입 공존 (AUTH-01, DC-45)

device_uuid는 모든 요청 필수 (NF-30). 그 위에 선택적 카카오 가입 레이어.

가입자/익명 표 분리 임계값:
```
prior_*_vote_high : anon_X >= 10  OR  user_X >= 3
prior_*_vote_low  : anon_X >= 3   OR  user_X >= 1
```

---

## 8. 시스템 실측 성능 (2026-06-10 홀드아웃 독립 평가)

### 8-1. 평가 방법론

**중요: 이 섹션에서는 기존 `performance_test_set.json`이 아닌 독립 홀드아웃 셋으로 측정한 수치만을 기준으로 한다.**

기존 테스트셋은 화이트리스트 튜닝에 사용된 도메인이 포함되어 과대적합(Overfitting) 상태였다. 따라서 2026-06-10부로 다음 두 가지 독립 홀드아웃 셋을 구축하여 평가 기준을 대체한다.

| 홀드아웃 셋 | 파일 | 건수 | 설명 |
|---|---|---|---|
| C-TAS Holdout | `backend/tests/ctas_holdout.json` | 200건 | 실제 DB 블랙리스트에서 기존 테스트셋 제외 후 층화 추출 |
| Safe Holdout | `backend/tests/safe_holdout.json` | 50건 | 화이트리스트 등록 10개 도메인 기반 안전 SMS |

WHOIS/SSL은 mock 처리 (기존 eval 스크립트 동일 조건). URL 해제도 mock.

### 8-2. 홀드아웃 실측 지표 (2026-06-10 기준)

| 지표 | 값 | 비고 |
|---|---|---|
| **C-TAS Recall** (위협 탐지율, suspicious+danger) | **100.0%** (200/200) | SRS 목표 ≥95% **PASS** |
| C-TAS Recall (danger 정확 탐지) | 99.5% (199/200) | 1건은 suspicious 판정 |
| 미탐 (danger→safe) | 0건 | |
| Safe 정확 탐지율 | 100.0% (50/50) | |
| **FPR** (safe→위협 오탐) | **0.0%** (0/50) | |
| 평가 오류 | 0건 | |

### 8-3. 평가 한계 명시 ★ 필독 ★

> **`safe_holdout`은 완전한 홀드아웃이 아니다.**
>
> `safe_holdout.json`에 사용된 10개 도메인(`moe.go.kr`, `korea.kr`, `nts.go.kr`, `safekorea.go.kr`, `koroad.or.kr`, `lh.or.kr`, `hi.or.kr`, `kfcc.co.kr`, `lottecard.com`, `chunilps.com`)은 화이트리스트 구축에 참고된 도메인과 동일한 집합이다.
>
> 따라서 Safe Holdout 평가 결과(FPR 0.0%)는 **"화이트리스트 커버리지 및 오탐 방지 안정성 검증"**으로 해석해야 한다. 미지의 정상 도메인에 대한 시스템의 진짜 일반화 성능(오탐 방지력)은 이 수치로 단정할 수 없다.
>
> **시스템의 진짜 일반화 성능(미지 위협 탐지력)은 C-TAS holdout recall 수치(100.0%)로만 판단한다.**

---

## 9. 보안 감사 요약 (2026-06-10 기준)

상세 내용: `docs/security_audit.md`

### 9-1. 수정 완료 (3건)

| 구분 | 내용 | 파일 |
|------|------|------|
| P0-1 수정 (DC-46) | 단축URL 도메인 블랙리스트 FP — `_SHORT_URL_PROVIDERS` frozenset, hash_only 매칭 분리 | `blacklist_service.py` |
| P1-1 수정 (DC-49) | SSRF 10진수·16진수·8진수 IP 우회 — `_normalize_ip_host()` 함수 추가 | `url_expander.py` |
| P1-3 수정 (DC-50) | userinfo injection `%40` 인코딩 우회 — `urlparse(unquote(url))` 전처리 | `url_validator.py` |

### 9-2. 남은 미수정 이슈

**P0 (즉시 대응 필요)**

| 위치 | 내용 |
|------|------|
| `url_validator.py:50~64` | `check_dangerous_scheme()`에 `url.strip()` + `unquote()` 미수행. `j%61vascript:` 또는 앞에 공백/개행 삽입 시 Stage 1 완전 우회 → Stage 7 15점(SUSPICIOUS)만 발화. |

**P1 (단기 내 대응)**

| 위치 | 내용 |
|------|------|
| `url_expander.py:48` | `_MAX_HOPS=3` 제한. 4단계 이상 리다이렉트 체인으로 피싱 최종 목적지 미분석. |
| `main.py:255~261` | `_client_ip()`가 `X-Forwarded-For` 헤더를 신뢰. Cloudflare Tunnel 없이 직접 노출 시 IP 위조로 Rate Limit 완전 우회. |

**P2 (중기 대응)**

| 위치 | 내용 |
|------|------|
| `url_validator.py:104~129` | IDN→Punycode 변환 없어 블랙리스트 매칭 불일치. Stage 7 30점 SUSPICIOUS만 가능. |
| `heuristic_scorer.py:494` | `_COMMON_TLDS_IN_SUBDOMAINS`에 `go`, `or`, `ac`, `re` 미포함 — 서브도메인 스푸핑 탐지 누락. |
| `domain_similarity.py` | 16자+ 도메인 임계값 차등 미적용 (Q-20 보류). |
| 이중 인코딩 | 3중 인코딩 패턴 미탐지. 실질적 영향 제한적. |
| `analysis_service.py:13` | "13 시그널" 주석 오기. 기능 영향 없음. |

**신규 관찰**

| 위치 | 내용 |
|------|------|
| `main.py:103` | `/test-phishing` 경로 DeviceUUID 예외. 외부 노출 시 P1 상향. |
| `main.py:217~223` | `unsafe-inline` CSP 완화. 외부 노출 시 검토 필요. |

---

## 10. 일정·진행 상태 (2026-06-10 기준)

### 10-1. 완료

- DB 스키마 재설계 마이그레이션 (DAT-04/05/06) ✅
- 보안 미들웨어 체인 (NF-12/25/30) ✅
- 어그로 방어 5중 (NF-29 + Layer 5) ✅
- 휴리스틱 시그널 25종 + 가중치 (v0527, 카운트 25로 정정) ✅
- domain_similarity.py Levenshtein 타이포스쿼팅 (ANL-06) ✅
- /sandbox/votes rate limit 20/min ✅
- asyncio.Lock WHOIS 중복 방지 (DC-41) ✅
- asyncio.to_thread URL 해제 비동기화 (DC-42) ✅
- INP-04 SMS 직접 읽기 ✅
- INP-05 문자 수신 알림 ✅
- 투표 모달 4지선다 (safe/danger/spam/unsure) ✅
- AUTH-01~03 카카오 소셜 로그인 + JWT (DC-45~48) ✅
- **단축URL FP 수정 (DC-46 / P0-1)** ✅ (2026-06-10)
- **SSRF 10진수·16진수·8진수 IP 우회 수정 (DC-49 / P1-1)** ✅ (2026-06-10)
- **userinfo injection %40 인코딩 우회 수정 (DC-50 / P1-3)** ✅ (2026-06-10)
- **홀드아웃 독립 평가 구축 (ctas_holdout.json 200건, safe_holdout.json 50건)** ✅ (2026-06-10)
- **샌드박스 컨테이너 격리 강화 (DC-51) — 7-A mem/cpu/pids 제한·127.0.0.1 바인딩, 7-A/7-B cap_drop=ALL+no-new-privileges, 탈출시도 11/11 차단 검증** ✅ (2026-06-21)

### 10-2. 남은 P0 (6월 심사 전)

| 항목 |
|---|
| `url_validator.py` 위험 스킴 검사 인코딩 우회 수정 (P0-2) |
| KISA 자가진단표 (`docs/KISA_SELF_ASSESSMENT.md`) 작성 |
| SRS v11 → v12 갱신 (`SRS_v11_to_v12_diff.md` 반영) |

### 10-3. P1 (가능 시)

| 항목 |
|---|
| X-Forwarded-For 신뢰 제한 (CF Tunnel 없는 환경 Rate Limit 우회) |
| 4-hop 이상 리다이렉트 체인 처리 |
| ACT-01: 발신번호 차단 — UI만 있고 기능 미연결 |
| Rate limit 하이브리드 키 (Q-19) |
| domain_similarity 임계값 길이별 차등 (Q-20) |

---

## 11. DC 로그 전체 (DC-49 ~ DC-51 신규)

| DC | 결정 | 영향 |
|----|------|------|
| **DC-49** *(v0610)* | `url_expander.py` `_normalize_ip_host()` 함수 추가. `2130706433`(10진수), `0x7f000001`(16진수), `0177.0.0.1`(8진수 옥텟)을 표준 dotted-decimal로 정규화 후 `is_private_ip()` 호출. | SSRF P1-1 수정. 우회 벡터 차단. |
| **DC-50** *(v0610)* | `url_validator.py` `check_userinfo_injection()`에서 `urlparse(unquote(url))` 전처리 추가. `%40` → `@` 디코딩 후 userinfo 검사. | userinfo injection P1-3 수정. `https://naver.com%40evil.kr/login` 정상 탐지. |
| **DC-51** *(v0610)* | 샌드박스 컨테이너 격리 강화. `browse_service.py`(7-A)에 `_browse_container_kwargs()` 헬퍼 신설 — `mem_limit="512m"`, `nano_cpus=0.5코어`, `pids_limit=256` 추가(기존 미설정, CLAUDE.md의 "RAM 512MB×4" 문서화와 실제 코드를 일치시킴), VNC 포트를 `ports={BROWSE_PORT: None}`(전체 인터페이스 노출)에서 `("127.0.0.1", None)`로 변경. 두 컨테이너(7-A/7-B) 모두 `cap_drop=["ALL"]` + `security_opt=["no-new-privileges"]` 추가. kasmweb/chromium 1.14.0·Browserless 둘 다 `cap_add` 예외 없이 정상 동작 확인(noVNC 렌더링·CDP 원격디버깅·Playwright 분석 스모크 테스트 통과). `backend/tests/run_sandbox_escape_test.py` 신규 — 호스트 파일시스템/Docker소켓/SSRF/프로세스폭탄/권한상승/컨테이너간통신 6종 탈출시도 실제 실행, 11/11 차단 확인(`docs/sandbox_hardening.md`). | 7-A가 7-B 대비 격리 수준이 낮았던 갭 해소("가상서버가 뚫리면 실제 서버가 위험해지는가" 심사 지적 대응). |

이전 DC 로그(DC-001 ~ DC-48)는 `docs/CLAUDE_CONTEXT_v0531.md` §10 참조.

---

## 12. 알려진 코드 인스펙션 이슈 (v0610 기준)

| 위치 | 이슈 | 심각도 |
|------|------|--------|
| `url_validator.py:50~64` | 위험 스킴 검사 인코딩/공백 우회 | **P0** |
| `analysis_service.py` 7단계 주석 | "13 시그널"로 구버전 숫자 잔존 | 낮음 (주석만) |
| `routers/sandbox.py:62, 154` | Semaphore `_value` 사전 검사 경합 | 낮음 |
| `domain_similarity.py` | 16자+ 도메인 max_distance=2 단일 적용 (Q-20 보류) | 낮음 |

---

## 13. Open Questions

### 미해소

| ID | 질문 |
|----|------|
| Q-19 | NF-24 rate limit 키를 IP / device_uuid / 하이브리드 중 무엇으로? |
| Q-20 | domain_similarity 16자+ 도메인 임계값 ≤3 차등 vs 현 단일값(≤2) |
| Q-21 | sandbox_danger_score +40 단독 + 약신호 1개 = 55점 — DANGER 70 도달 불가. 시연 시나리오 검증 필요 |

---

## 14. 산출물 위치

| 파일 | 역할 |
|------|------|
| `docs/security_hub_srs_v11.xlsx` | 요구사항 명세 (구버전) |
| `docs/SRS_v11_to_v12_diff.md` | v0527 코드와의 SRS 셀별 변경 사항 |
| `docs/CLAUDE_CONTEXT_v0610.md` | **본 문서** — 새 대화 시작 시 첨부 |
| `docs/CLAUDE_CONTEXT_v0531.md` | 봉인 (v0610 승계) |
| `docs/security_audit.md` | 보안 감사 상세 (2026-06-10 갱신) |
| `backend/tests/ctas_holdout.json` | C-TAS 홀드아웃 200건 |
| `backend/tests/safe_holdout.json` | Safe 홀드아웃 50건 |
| `backend/tests/run_holdout_eval.py` | 홀드아웃 평가 스크립트 |
| `CLAUDE.md` (루트) | 코드 작업 즉시 참조용 빠른 가이드 |
| `backend/security_hub.db` | SQLite (Git 제외) |
