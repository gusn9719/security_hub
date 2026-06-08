# Security Audit Report — security_hub

**감사 일시**: 2026-06-08
**감사 범위**: 파이프라인 Stage 0~8 공격 벡터 7종 + 미들웨어 우회 + SSRF 방어 충분성
**감사자**: smishing-security-auditor
**결론 요약**: P0 2건, P1 4건, P2 5건

---

## P0 — 즉시 대응 필요

### P0-1. 단축 URL 도메인 블랙리스트 등록 시 서비스 전체 차단 FP (False Positive)

**파일**: `backend/database/blacklist_service.py:208~228`
**심각도**: P0 (서비스 가용성 파괴 + 사용자 신뢰 붕괴)

**문제 설명**

`check_blacklist()`의 2순위 매칭(domain 일치)과 3순위 매칭(registered_domain 일치)은 입력 URL에서 추출한 도메인/등록도메인을 블랙리스트 전체에 대해 조회한다. C-TAS 블랙리스트에 단축 서비스 경유 피싱 URL(예: `bit.ly/XxXxXx`)이 등록될 때, C-TAS CSV 적재 스크립트가 해당 URL의 `domain`을 `bit.ly`로, `registered_domain`을 `bit.ly`로 저장하는 경우, 이후 어떤 `bit.ly/YyYyYy` URL을 분석해도 2순위 매칭에서 즉시 DANGER가 반환된다.

**재현 시나리오**

1. C-TAS CSV에 `http://bit.ly/malicious123`가 피싱 URL로 존재한다.
2. `load_ctas_csv.py`가 해당 URL의 domain=`bit.ly`, registered_domain=`bit.ly`로 INSERT한다.
3. 사용자가 합법적인 `http://bit.ly/govnotice`를 분석 요청한다.
4. Stage 2(단축 URL 해제)에서 최종 목적지 URL로 변환되기 전, `check_blacklist`는 `expanded_urls` 기준으로 실행된다.
5. 만약 expand 실패(타임아웃 등) 시 원본 `bit.ly/govnotice`로 조회 → 2순위 domain 매칭에서 `bit.ly` DANGER 히트.
6. 정상 bit.ly 링크가 DANGER로 오판된다.

**추가 관찰**: `SHORT_URL_DOMAINS` 집합(`url_expander.py:21~36`)에는 `bit.ly`, `tinyurl.com`, `han.gl` 등 14개 단축 서비스가 있다. 이 중 하나라도 블랙리스트에 domain 수준으로 등록되면 해당 단축 서비스 전체가 차단된다. `forms.gle`(Google Forms)의 경우 `registered_domain`이 `google.com` → `google.com`이 블랙리스트에 등록되면 Google 전체 서비스 차단.

**수정 방향**
- 2순위/3순위 매칭 대상에서 알려진 단축 서비스 도메인(`SHORT_URL_DOMAINS`와 그 등록 도메인)을 사전 배제한다.
- 또는 Stage 2에서 expand 성공한 URL에 한해서만 domain/registered_domain 매칭을 수행하고, expand 실패 시 url_hash 매칭만 허용한다.
- C-TAS CSV 적재 시 단축 서비스 경유 URL은 expand 후 저장하도록 `load_ctas_csv.py`를 보완한다.

---

### P0-2. 위험 스킴 검사 우회 — 인코딩·대소문자·공백 변형

**파일**: `backend/services/url_validator.py:50~64`, `backend/services/analysis_service.py:121~137`
**심각도**: P0 (Stage 1 완전 우회 → Stage 7 휴리스틱 의존)

**문제 설명**

`check_dangerous_scheme(url)`은 `urlparse(url).scheme.lower()`를 사용해 스킴을 추출한다. 이 방식은 다음 변형을 탐지하지 못한다.

**패턴 A: URL 인코딩된 스킴 구분자**
```
j%61vascript:alert(1)
```
`urlparse`는 `j%61vascript`를 scheme으로 인식하지 못한다. scheme 추출 결과가 빈 문자열이 되어 `DANGEROUS_SCHEMES` 검사를 통과한다. 이후 Stage 3 블랙리스트 hash 매칭도 미스, Stage 7에서 `double_encoding`(+15) 시그널만 발화 → 15점 → SUSPICIOUS 폴백.

**패턴 B: 앞에 공백/탭/개행 삽입**
```
 javascript:alert(1)
 	data:text/html,<script>
```
`urlparse`의 scheme 추출은 앞에 공백이 있으면 scheme을 인식 못한다. `url.strip()`이 `check_dangerous_scheme` 내부에서 호출되지 않으므로 화이트스페이스 프리픽스가 있는 경우 탐지 실패.
단, `extract_urls()`의 `_PROTO_URL_RE` 정규식은 `re.ASCII`이고 시작 앵커가 없어서 공백 뒤의 `https?://` 패턴은 잡지만, `javascript:` 같은 비-http 스킴은 1단계 정규식에서 아예 추출되지 않을 수 있다. 그 경우 URL이 없음으로 처리되어 SUSPICIOUS 반환.

**패턴 C: 대소문자 혼합**
`urlparse(url).scheme.lower()`로 소문자 처리하므로 `Javascript:`, `DATA:`, `JaVaScRiPt:`는 정상 탐지된다. — 이 패턴은 방어됨.

**재현 시나리오 (패턴 A)**
1. 공격자가 `j%61vascript:evil()` 형태 URL을 문자 메시지에 삽입.
2. `extract_urls()`에서 프로토콜 없는 도메인 정규식(`_BARE_DOMAIN_RE`)으로 추출 시도 → 미추출(도메인 형식이 아님) → URL 없음 → SUSPICIOUS.
3. 단, `https://safe.com?redirect=j%61vascript:evil()` 형태로 쿼리스트링에 포함하면 `extract_urls()`는 `safe.com` 도메인을 추출하고, Stage 4 화이트리스트 조회에서 `safe.com`이 히트 시 SAFE 반환 → 인코딩된 스킴이 payload로 활용.

**수정 방향**
- `check_dangerous_scheme()` 진입 전에 `url = unquote(url.strip())`을 수행해 인코딩·공백 정규화.
- 또는 `extract_urls()` 단계에서 비-http(s) 스킴으로 시작하는 토큰도 추출해 Stage 1로 전달.

---

## P1 — 단기 내 대응 권고

### P1-1. SSRF 방어 불완전 — IPv6 루프백·IPv4-mapped 미처리

**파일**: `backend/services/url_validator.py:168~182`, `backend/services/url_expander.py:69~83`
**심각도**: P1

**문제 설명**

`is_private_ip(hostname)`은 `ipaddress.ip_address(hostname)`으로 파싱한 뒤 `addr.is_private or addr.is_loopback or addr.is_link_local`을 반환한다.

Python의 `ipaddress` 모듈에서 `is_private`는 IPv4-mapped IPv6 주소(`::ffff:127.0.0.1`)에 대해 버전별로 동작이 다르다. Python 3.11 미만에서는 `IPv6Address('::ffff:127.0.0.1').is_private`가 `False`를 반환한 이력이 있다(CPython 이슈 #85043).

다음 형태가 `is_private_ip`를 통과할 수 있다:
```
http://[::ffff:127.0.0.1]/admin          # IPv4-mapped 루프백
http://[0:0:0:0:0:ffff:c0a8:101]/        # ::ffff:192.168.1.1
http://[::1]/                             # IPv6 loopback (is_loopback=True → 차단됨, 정상)
http://2130706433/                        # 10진수 표기 127.0.0.1
http://0x7f000001/                        # 16진수 표기 127.0.0.1
```

`ipaddress.ip_address("2130706433")` — Python은 10진수 정수 표기법 IP를 파싱하지 않으므로 `ValueError` → `False` → SSRF 차단 없이 통과.

실제 HTTP 라이브러리(requests)가 `requests.head("http://2130706433/")` 요청을 발송하면 OS 레벨에서 127.0.0.1로 연결될 수 있다.

**재현 시나리오**
1. 공격자가 내부망 접근 단축 URL을 등록: `bit.ly/ssrf-test` → `http://2130706433:8000/admin` redirect.
2. Stage 2: `expand_url` 호출, `_is_safe_to_request("http://bit.ly/ssrf-test")` → `hostname=bit.ly` → `is_private_ip("bit.ly")` → `ValueError` → False(안전) → HEAD 요청 진행.
3. 첫 hop 응답에 `Location: http://2130706433:8000/admin`.
4. `_is_safe_to_request("http://2130706433:8000/admin")` → `hostname="2130706433"` → `ipaddress.ip_address("2130706433")` → `ValueError` → False(안전으로 오판) → HEAD 요청 발송 → 내부망 접근.

**수정 방향**
- `is_private_ip()` 내에서 10진수·16진수 IP 표기법을 정규화하는 전처리 추가.
- `ipaddress.ip_address()` 실패 시 hostname이 순수 숫자인 경우 위험으로 처리.
- Python 버전 고정 시 IPv4-mapped 처리 동작을 확인하고 명시적 `is_private` 체크 보완.

---

### P1-2. 3-hop 초과 단축 URL 체인 우회

**파일**: `backend/services/url_expander.py:86~150`
**심각도**: P1

**문제 설명**

`expand_url()`은 최대 `_MAX_HOPS=3`회만 리다이렉트를 추적한다. 공격자가 4단계 이상 체인 리다이렉트를 구성하면, 3번째 hop에서 중간 경유지 URL이 반환된다. 이 중간 URL이 블랙리스트에 없고 휴리스틱 시그널도 적으면 파이프라인을 통과한다.

또한 `_is_safe_to_request` 검사는 hop 시작 시점의 `current` URL에만 적용된다. 리다이렉트 응답의 `Location` 헤더가 상대 경로(`/admin`)인 경우, `urlparse(current).netloc`에서 원래 호스트를 유지한 채 경로만 교체하므로(`location = f"{scheme}://{netloc}{location}"`) 문제없다. 그러나 절대 URL `Location`이 사설 IP인 경우는 다음 반복의 `_is_safe_to_request`에서 체크된다 — 이 부분은 정상 작동.

**재현 시나리오**
1. 공격자 체인: `bit.ly/a` → `tinyurl.com/b` → `is.gd/c` → `evil-phishing.xyz/login`
2. 3-hop 후 `is.gd/c` (중간 단축 서비스)가 반환됨.
3. `is.gd`가 블랙리스트에 없고 휴리스틱도 낮으면 SUSPICIOUS로 폴백.
4. 실제 피싱 최종 목적지 `evil-phishing.xyz`는 분석되지 않는다.

**수정 방향**
- `_MAX_HOPS`를 5로 상향 검토 (타임아웃 총량은 `_MAX_HOPS × timeout`이므로 성능 트레이드오프 필요).
- 3-hop 초과 시 "단축 URL 체인 과다" 자체를 SUSPICIOUS 상향 시그널로 처리.
- 현재 `url_too_long`(+5)과 유사하게 `excessive_redirect_hops` 시그널 추가 검토.

---

### P1-3. userinfo injection — 인코딩된 `@`(`%40`) 미탐지

**파일**: `backend/services/url_validator.py:136~161`
**심각도**: P1

**문제 설명**

`check_userinfo_injection(url)`은 `urlparse(url).username`이 비어 있지 않은지 확인한다. 그러나 `@`가 `%40`으로 인코딩된 경우 `urlparse`는 userinfo를 분리하지 않는다.

```
https://naver.com%40evil.kr/login
```

`urlparse`는 `%40`을 `@`의 인코딩으로 해석하지 않고 netloc 전체를 `naver.com%40evil.kr`로 처리한다. 결과: `username=None`, `hostname='naver.com%40evil.kr'` → `check_userinfo_injection`이 False 반환.

그러나 일부 구버전 브라우저/앱은 `%40`을 `@`로 디코딩해 `evil.kr`에 접속할 수 있다.

`heuristic_scorer`의 `userinfo_injection` 시그널(+35)도 동일한 `check_userinfo_injection(url)`을 호출하므로 마찬가지로 미발화.

단, `blacklist_service.normalize_url()`에서 `unquote(unquote(url))`(이중 디코딩)을 거친 후 블랙리스트 hash 매칭이 이루어지므로, 정규화 URL로 hash를 계산하면 `%40`이 `@`로 변환된다. 하지만 이는 블랙리스트 hash 매칭에만 영향이 있고, Stage 1 스킴 체크와 Stage 7 userinfo 시그널에는 원본 URL이 전달된다.

**재현 시나리오**
1. `https://naver.com%40phishing.kr/auth` 입력.
2. Stage 1: `check_dangerous_scheme` → scheme=https → 통과.
3. Stage 7: `check_userinfo_injection(url)` → `urlparse.username=None` → 미발화.
4. `_signal_brand_keyword_mismatch`에서 `naver` 키워드 탐지 가능하나, hostname이 `naver.com%40phishing.kr`이고 등록도메인이 `phishing.kr`이면 `naver` 키워드 단어 경계 정규식에서 `naver.com%40phishing` 문자열에 `naver` 매칭 → `brand_keyword_mismatch`(+20) 발화 가능성 있음.
5. 그러나 `userinfo_injection`(+35)은 미발화 → 점수가 35점 낮게 산출.

**수정 방향**
- `check_userinfo_injection()` 호출 전 `unquote(url)`을 1회 수행해 `%40` → `@` 정규화 후 체크.
- 또는 `%40`을 직접 탐지하는 추가 패턴 검사 추가.

---

### P1-4. RateLimitMiddleware IP 스푸핑 — 신뢰할 수 없는 헤더 우선 추출

**파일**: `backend/main.py:240~246`
**심각도**: P1

**문제 설명**

`_client_ip()`는 `cf-connecting-ip` → `x-real-ip` → `x-forwarded-for` 순으로 클라이언트 IP를 추출한다. Cloudflare Tunnel 없이 직접 운용하거나 리버스 프록시 없이 인터넷에 노출된 경우, 공격자가 임의 `X-Forwarded-For: 1.2.3.4` 헤더를 위조하면 IP를 `1.2.3.4`로 속일 수 있다. 결과적으로 IP 기반 Rate Limit을 완전히 우회할 수 있다.

```http
POST /analyze HTTP/1.1
X-Forwarded-For: 1.2.3.4
X-Device-UUID: <valid-uuid>
...
```

이 요청을 동일 클라이언트가 초당 수백 회 발송해도 RateLimit이 `1.2.3.4`로 카운트하므로 실제 클라이언트 IP(`request.client.host`)는 제한받지 않는다.

또한 `x-forwarded-for`는 콤마 구분 체인이 올 수 있고(`client, proxy1, proxy2`), 현재 코드는 `val.split(",")[0].strip()`으로 가장 왼쪽 값(클라이언트가 위조 가능)을 사용한다.

**수정 방향**
- Cloudflare Tunnel 운용 시: `cf-connecting-ip`만 신뢰, 나머지 헤더 무시.
- 직접 노출 시: `request.client.host`만 신뢰 (프록시 없는 환경).
- `FORCE_TRUSTED_PROXY` 환경변수로 신뢰 헤더 모드를 설정 가능하게 구성.
- `x-forwarded-for` 체인 처리 시 마지막 값(신뢰 프록시가 붙인 값)을 사용하는 것이 권고.

---

## P2 — 중기 대응 권고

### P2-1. IDN 동형문자 — Stage 1 미차단, Stage 7 의존

**파일**: `backend/services/url_validator.py:104~129`, `backend/services/heuristic_scorer.py:528~531`
**심각도**: P2

**문제 설명**

키릴 `а`(U+0430) 등 동형문자를 포함한 IDN 도메인(`nаver.com`)은 Stage 1의 `check_dangerous_scheme()`에서 차단되지 않는다. Stage 7의 `homograph_idn` 시그널(+30)이 발화되어야 탐지된다.

`_signal_homograph(hostname)`은 `normalize_idn_hostname(hostname)`을 호출하고, 호스트명에 비ASCII 문자가 있으면 `is_idn=True`를 반환한다. `hostname.isascii()`가 False이면 탐지 가능.

**Punycode 변환 후 블랙리스트 매칭 미수행**: `blacklist_service.normalize_url()`은 IDN→Punycode 변환 없이 소문자 변환+디코딩만 수행한다. 따라서 `nаver.com`(키릴)의 Punycode 표현 `xn--nver-qqa.com`과의 블랙리스트 매칭이 이루어지지 않는다.

**점수 검증 (Stage 7 단독 탐지 시)**:
- `homograph_idn`: +30
- `punycode_in_url`: `hostname.split(".")`에서 `xn--` 접두 → +15
- 주의: `xn--` 탐지는 브라우저가 Punycode로 변환 후 전송한 경우에만 해당. 원본 키릴 문자 그대로 전달 시 `punycode_in_url`은 미발화.
- `brand_keyword_mismatch`: `nаver` 호스트명에서 `naver` 키워드 단어 경계 정규식 미매칭 가능 (키릴 `а`가 포함되어 `[a-z0-9]` 외 문자 → 경계 조건 불명확).

단독 발화 시 최대 30점 → SUSPICIOUS. DANGER 도달 불가 (임계값 70). 신생 도메인(+20) + WHOIS 없음(+20) 조합 시 70점 → DANGER 도달 가능.

**수정 방향**
- `normalize_url()`에서 IDN→ASCII(Punycode) 변환을 추가해 블랙리스트 매칭 일관성 확보.
- CLAUDE.md의 알려진 이슈와 연계 없음(이 이슈는 별도).

---

### P2-2. 서브도메인 스푸핑 — `_COMMON_TLDS_IN_SUBDOMAINS` 범위 제한

**파일**: `backend/services/heuristic_scorer.py:490~507`
**심각도**: P2

**문제 설명**

`_signal_subdomain_spoofing()`은 서브도메인 파트에 `_COMMON_TLDS_IN_SUBDOMAINS`(`com`, `net`, `org`, `co`, `kr`, `jp`, `us`) 중 하나가 포함되는지 검사한다.

다음 패턴은 탐지되지 않는다:
```
kakao.com.phishing.xyz     → registered=phishing.xyz, subdomain_part=kakao.com → "com" 포함 → 탐지됨 (정상)
naver.co.kr.phishing.top   → registered=phishing.top, subdomain_part=naver.co.kr → "co", "kr" 포함 → 탐지됨 (정상)
hometax.go.kr.phishing.xyz → registered=phishing.xyz, subdomain_part=hometax.go.kr → "kr" 포함 → 탐지됨 (정상)
naver.net.phishing.site    → registered=phishing.site, subdomain_part=naver.net → "net" 포함 → 탐지됨 (정상)
```

단, `nhis.or.kr.phishing.xyz`에서 `or`은 `_COMMON_TLDS_IN_SUBDOMAINS`에 없으므로 서브도메인 파트 `nhis.or.kr`에서 `kr`이 있으면 탐지된다.

실제 미탐 패턴:
```
www-naver-com.phishing.xyz → registered=phishing.xyz, subdomain_part 없음 (하이픈 도메인) → 미탐
                              → brand_keyword_mismatch(+20)으로 보완 가능
```

**수정 방향**
- `_COMMON_TLDS_IN_SUBDOMAINS`에 `go`, `or`, `ac`, `re` 등 한국 2단계 TLD 추가.
- 하이픈 연결형 브랜드 위장(`www-naver-com.xyz`)은 `brand_keyword_mismatch`와 `many_hyphens` 조합으로 탐지 보완.

---

### P2-3. 타이포스쿼팅 — 16자 이상 도메인 임계값 차등 미적용 (알려진 이슈)

**파일**: `backend/services/domain_similarity.py:158~214`
**심각도**: P2

**문제 설명**

CLAUDE.md 「알려진 코드 인스펙션 이슈」에 명시된 이슈. `detect_typosquat()`은 도메인 길이에 관계없이 `max_distance=2`를 단일 적용한다.

SRS Q-20에서 16자+ 도메인은 편집 거리 ≤3을 허용하는 정밀화가 보류 중이다.

역방향 문제: 짧은 도메인에 대해서는 `_MIN_TARGET_LENGTH=6` 보호가 있으나, 표적 도메인이 긴 경우(예: `shinhancard.com` 14자) 편집 거리 2 범위가 너무 넓어져 무관 도메인이 타이포스쿼팅으로 오탐될 수 있다.

```
shinhancard.com (14자) vs shinhan-card.com: 거리 1 → 탐지 (실제 위장 가능성 높음, 정상)
shinhancard.com (14자) vs shinhancare.com : 거리 1 → 탐지 (타이포, 정상)
shinhancard.com (14자) vs shinhantar.com  : 거리 2 (d와 r 치환, a 삭제) → 탐지 여부는 실제 계산 필요
```

현행 max_distance=2 단일 적용은 보수적 측면에서 FP 증가보다 FN 감소 쪽으로 설계 의도가 있으나, 문서화된 이슈로 명시.

**수정 방향**
- 표적 도메인 길이 16자 초과 시 `max_distance=3` 허용 (SRS Q-20 정밀화).
- 표적 도메인 길이 8자 미만 시 `max_distance=1`로 제한하는 하향 조정도 검토.

---

### P2-4. 이중 인코딩 시그널 — 정규식 패턴 범위 제한

**파일**: `backend/services/url_validator.py:72~88`
**심각도**: P2

**문제 설명**

`_DOUBLE_ENCODING_RE = re.compile(r"%25[0-9a-fA-F]{2}")`는 `%25XX` 형태만 탐지한다. 이는 가장 일반적인 이중 인코딩(`%252F` = `%2F` = `/`)을 탐지하기에 충분하다.

그러나 다음 변형은 탐지되지 않는다:
```
%2500    → %00 (null byte) — 정규식 불일치 아님, %25 뒤 "00" → 탐지됨 (정상)
%25252F  → 3중 인코딩 → %252F → %2F → /  → 1회 탐지 후 디코딩하면 여전히 %252F
```

`normalize_url()`에서 `unquote(unquote(url))`로 2회 디코딩하므로, 3중 인코딩된 URL은 2회 디코딩 후에도 `%2F`가 남는다. 이 상태로 블랙리스트 hash 계산 시 정규화 부족으로 미스 가능.

`has_double_encoding(url)` 체크는 원본 URL에 적용되고 `double_encoding` 시그널(+15)을 발화시킨다. 실제 공격에서 3중 이상 인코딩 사용 사례는 드물고, `double_encoding`이 단독 DANGER 도달 불가(+15)이므로 실질적 영향은 제한적.

**수정 방향**
- 3중 인코딩 탐지: 디코딩 후 재검사 루프 추가 또는 `%25{2,}XX` 패턴으로 정규식 확장.
- `normalize_url()`의 디코딩 횟수를 늘리거나 루프 기반 완전 디코딩으로 교체.

---

### P2-5. `analysis_service.py` Stage 7 주석 오류 — 알려진 이슈

**파일**: `backend/services/analysis_service.py:13`
**심각도**: P2 (문서 오류, 기능 영향 없음)

**문제 설명**

CLAUDE.md 「알려진 코드 인스펙션 이슈」에 명시된 이슈.

```python
#   7. 휴리스틱 스코어링   (13 시그널 + 투표 + sandbox 시그널, 가중합)
```

실제 시그널은 23종이나 주석에 구버전 숫자 "13"이 잔존한다.

**수정 방향**: 주석을 "23 시그널"로 수정. 기능 영향 없음.

---

## 종합 위험도 평가

| 공격 벡터 | 판정 | 탐지 Stage | 미탐 패턴 | 심각도 |
|-----------|------|-----------|----------|--------|
| 단축 URL 서비스 블랙리스트 FP | 판정 오류(DANGER 오판) | Stage 3 (2순위 domain 매칭) | bit.ly 등 도메인이 블랙리스트에 등록된 경우 | P0 |
| 위험 스킴 인코딩 우회 | 미탐 → SUSPICIOUS | Stage 1 우회, Stage 7 15점 | `j%61vascript:`, 앞 공백+`javascript:` | P0 |
| SSRF — 10진수/IPv4-mapped IP | 미탐 → 내부망 접근 | Stage 2 SSRF 방어 우회 | `http://2130706433/`, `::ffff:127.0.0.1` | P1 |
| 3-hop 초과 단축 URL 체인 | SUSPICIOUS 폴백 | Stage 2 (hop 한계 초과) | 4단계 이상 리다이렉트 체인 | P1 |
| userinfo injection %40 | 미탐(+35 미발화) | Stage 7 우회 | `naver.com%40evil.kr` | P1 |
| Rate Limit IP 헤더 위조 | Rate Limit 완전 우회 | 미들웨어 단계 | `X-Forwarded-For` 위조 | P1 |
| IDN 동형문자 | SUSPICIOUS (30점) | Stage 7 (homograph_idn) | 추가 시그널 없으면 DANGER 불가 | P2 |
| 서브도메인 스푸핑 | 탐지됨(일부 미탐) | Stage 7 (subdomain_spoofing) | 하이픈형 브랜드 위장 | P2 |
| 타이포스쿼팅 임계값 | 미정밀(알려진 이슈) | Stage 7 (typosquat) | 16자+ 도메인 max_distance 단일 적용 | P2 |
| 이중 인코딩 3중 변형 | SUSPICIOUS(15점) | Stage 7 (double_encoding) | 3중 인코딩 | P2 |
| 주석 오류 | 무기능 | - | "13 시그널" 오기 | P2 |

---

## 알려진 코드 인스펙션 이슈 연계

| CLAUDE.md 이슈 | 본 감사 연계 | 보안 영향 |
|----------------|------------|----------|
| Semaphore `_value` 경합 (`sandbox.py:62,154`) | 감사 범위 외 (샌드박스 세션 관리) | DoS 가능성 — 슬롯 소진 시 503 즉시 거부 의도와 어긋나 대기 큐 형성, 결과적으로 과부하 상태에서 부분 서비스 제공. 보안보다 가용성 이슈. |
| `analysis_service.py` 주석 "13 시그널" 오류 | P2-5로 문서화 | 기능 영향 없음. 코드 유지보수자 혼란 가능성. |
| `domain_similarity.py` 임계값 차등 미적용 | P2-3으로 문서화 | 긴 도메인 FP 증가 가능성. 실제 피해는 SUSPICIOUS 오판 수준 (FN보다 낮음). |

---

## 파이프라인 단계별 방어 커버리지 요약

| Stage | 담당 | 방어 강도 | 주요 취약점 |
|-------|------|----------|-----------|
| 0 | extract_urls | 보통 | 비-http 스킴 URL 미추출 가능 |
| 1 | check_dangerous_scheme | 보통 | 인코딩/공백 변형 우회 가능 (P0-2) |
| 2 | expand_url | 보통 | 3-hop 초과 우회(P1-2), 10진수 IP SSRF(P1-1) |
| 3 | check_blacklist | 보통 | 단축 서비스 FP(P0-1), 정규화 불일치 |
| 4 | is_whitelisted | 양호 | Open Redirect 패턴 탐지, 다중 URL 처리 개선됨 |
| 5~6 | domain_reputation | 양호 | 외부 의존성, 실패 시 graceful 처리 |
| 7 | score_url (23 시그널) | 양호 | 단독 DANGER 불가 원칙 준수, %40 userinfo 미탐(P1-3) |
| 8 | explanation_service | 양호 | EXPLANATION_DICT 기반, LLM 미사용 |
| MW | RateLimitMiddleware | 취약 | IP 헤더 위조 우회(P1-4) |

---

## 변경 이력

- 2026-06-08: 최초 작성. 소스 코드 정적 분석 기반. 서비스 코드 미수정.
