# 7-B 샌드박스 실데이터 신뢰성 평가 결과

실행 일시: 2026-06-21 15:51:56
측정 대상: `backend/services/sandbox_service.run_auto_test()` 직접 호출
(실제 Docker 컨테이너 + Playwright로 실제 URL 방문, HTTP 계층 우회)

## 왜 이 평가가 필요한가

`backend/tests/test_sandbox.py`의 `TestCalcScore`는 `_calc_score()`를 mock indicator dict로만 단위테스트한다 — 실제 사이트를 한 번도 띄워본 적이 없다. "자동 모드로 리포트된 게 실제로 믿을만 하냐"는 질문에 답하려면 진짜 위험 URL(C-TAS 등재, `ctas_holdout.json`)과 진짜 안전 URL(화이트리스트 공식 도메인, `performance_test_set.json`의 `whitelisted_safe`)을 실제로 방문시켜봐야 한다.

## 1. 죽은 링크 비율

C-TAS에 등재된 피싱 URL은 신고·차단 이후 인프라가 자주 폐기되므로, 이 평가에서는 "죽은 링크"(접속 자체 실패: DNS 오류·타임아웃·연결거부)와 "살아있는 링크"(페이지 로드 성공, 분석 가능)를 분리해서 본다. 죽은 링크는 sandbox_score를 측정할 수 없으므로 정확도 계산에서 제외.

| 그룹 | 전체 | 죽은 링크 | 살아있는 링크 |
|---|---|---|---|
| danger (C-TAS 등재) | 10 | 9 | 1 |
| safe (화이트리스트 공식도메인) | 10 | 1 | 9 |

## 2. sandbox_score 정확도 (살아있는 링크 기준)

- **danger 탐지율**: 살아있는 1건 중 `sandbox_score>=70`(휴리스틱 `sandbox_danger_score` 시그널 발동 임계값과 동일) 0건 — **0.0%**
- **safe 오탐률**: 살아있는 9건 중 `sandbox_score>0` 2건 — **22.2%**

## 3. 5가지 판정 기준 발화 빈도

| 기준 | danger군 발화 | safe군 발화 |
|---|---|---|
| `form_with_password` | 0/1 | 0/9 |
| `external_form_action` | 0/1 | 1/9 |
| `auto_download` | 0/1 | 0/9 |
| `redirect_count>=3` | 0/1 | 1/9 |
| `clipboard_access` | 0/1 | 0/9 |

## 4. 개별 결과

| 라벨 | URL | score | 죽은링크 | findings | error |
|---|---|---|---|---|---|
| danger | `https://tny.kr/h72fw` | 0 | N | - | - |
| danger | `http://yx.bsdf.homse` | 0 | Y | - | Page.goto: net::ERR_NAME_NOT_RESOLVED at http://yx.bsdf.homs |
| danger | `http://y02.o4ys.pw` | 0 | Y | - | Page.goto: net::ERR_NAME_NOT_RESOLVED at http://y02.o4ys.pw/ |
| danger | `http://gov.pn4g.fit` | 0 | Y | - | Page.goto: net::ERR_NAME_NOT_RESOLVED at http://gov.pn4g.fit |
| danger | `https://moz.asuo.my` | 0 | Y | - | Page.goto: net::ERR_NAME_NOT_RESOLVED at https://moz.asuo.my |
| danger | `http://114.41.229.162` | 0 | Y | - | Page.goto: Timeout 20000ms exceeded.
Call log:
  - navigatin |
| danger | `http://gov.i9pn.icu` | 0 | Y | - | Page.goto: net::ERR_NAME_NOT_RESOLVED at http://gov.i9pn.icu |
| danger | `http://yii.g7nk.bar` | 0 | Y | - | Page.goto: net::ERR_NAME_NOT_RESOLVED at http://yii.g7nk.bar |
| danger | `http://x.aetu.beer` | 0 | Y | - | Page.goto: net::ERR_NAME_NOT_RESOLVED at http://x.aetu.beer/ |
| danger | `http://ibn.i9cy.mom` | 0 | Y | - | Page.goto: net::ERR_NAME_NOT_RESOLVED at http://ibn.i9cy.mom |
| safe | `https://naver.com/security` | 40 | N | 외부 도메인 폼 전송 감지 | - |
| safe | `https://kbstar.com/personal/account` | 0 | N | - | - |
| safe | `https://ibk.co.kr/loan/detail` | 0 | N | - | - |
| safe | `https://cjlogistics.com/ko/tool/parcel/tracking` | 20 | N | 과도한 리다이렉트 감지 (14회) | - |
| safe | `https://coupang.com/np/orderhistory` | 0 | N | - | - |
| safe | `https://samsunghospital.com/appointment` | 0 | N | - | - |
| safe | `https://pay.kakao.com/history` | 0 | N | - | - |
| safe | `https://gov.kr/documents/issued` | 0 | Y | - | Page.goto: net::ERR_NAME_NOT_RESOLVED at https://gov.kr/docu |
| safe | `https://hanabank.com` | 0 | N | - | - |
| safe | `https://mois.go.kr/emergency-drill` | 0 | N | - | - |

## 5. 자체 테스트 하네스(`/test-phishing`)와 SSRF 방어의 상호작용

이 라이브 평가를 준비하며 발견한 사실: 프로젝트에 이미 5가지 판정 기준을
각각 정확히 하나씩 발화시키도록 만든 통제된 테스트 페이지가 있다
(`backend/static/test_phishing/`):

| 페이지 | 기준 |
|---|---|
| `1_password.html` | `form_with_password` (+30) |
| `2_ext_form.html` | `external_form_action` (+40) |
| `3_download.html` | `auto_download` (+50) |
| `/test-phishing/redirect/start` (302×3) | `redirect_count>=3` (+20) |
| `5_clipboard.html` | `clipboard_access` (+25) |

**이번 라이브 평가에서는 이 페이지들을 쓸 수 없었다** — 7-B 컨테이너가
로컬 백엔드(`localhost:8000`)에 접근하려면 `host.docker.internal`을
거쳐야 하는데, `sandbox_service.py`가 컨테이너 생성 시
`extra_hosts={"host.docker.internal": "0.0.0.0"}`로 그 호스트명을 의도적으로
존재하지 않는 주소에 매핑해 막아둔다. Docker 표준 관용구는
`"host-gateway"`(특수 문자열, 런타임에 실제 호스트 IP로 치환됨)인데 여기선
리터럴 `"0.0.0.0"`을 박아넣었다 — **이건 버그가 아니라 SSRF 방어 의도로
보인다**: 악성 페이지가 `host.docker.internal`을 통해 호스트 머신을 공격하는
경로를 원천 차단한다. 격리 네트워크(`internal=False`로 인터넷은 열려있되
호스트 루프백은 막힘)와 일치하는 설계.

**결과적으로 자체 테스트 하네스를 쓰려면** 백엔드를 Cloudflare Tunnel 등으로
외부에 노출한 뒤(`BASE_URL` 환경변수, CLAUDE.md 참조) 그 공개 URL로
`/test-phishing/`을 7-B에 입력해야 한다 — 로컬 평가 환경에선 보안상 의도적으로
막혀 있어 이번 라운드에서는 시도하지 않았다(범위 밖, 별도 확인 필요).

**그래도 실데이터로 2/5 기준은 이미 실증됐다**: 이번 라이브 평가에서
`external_form_action`(naver.com/security)과 `redirect_count>=3`
(cjlogistics.com, 14회)이 **실제 공개 사이트에서 자연스럽게 발화**했다 —
mock 데이터가 아니라 진짜 DOM에서 작동을 확인한 것. 나머지 3개
(`form_with_password`/`auto_download`/`clipboard_access`)는 이번 20개
샘플에 해당 패턴이 없어서 못 봤을 뿐 — `test_sandbox.py::TestCalcScore`가
mock 기준으로는 5개 전부 검증해둔 상태다.

## 한계

- 표본 10+10건으로 매우 작다 — 통계적 신뢰구간을 낼 만큼 충분하지 않고, 방향성 확인 목적의 파일럿 평가다.
- C-TAS 등재 URL은 시간이 지나면 죽는 경우가 흔해 죽은 링크 비율이 높게 나올 수 있다 — 이는 휴리스틱/sandbox 자체의 결함이 아니라 위협 인텔리전스 데이터의 자연적 노화(decay)다.
- `GEMINI_API_KEY`가 `.env`에 설정되지 않아 Gemini 자연어 요약은 폴백 텍스트로 대체됐다 — `sandbox_score`/`findings` 자체(이번 평가의 측정 대상)에는 영향 없음.
- 동시성 3(시스템 자체 `_AUTO_SEM` 한계와 동일)으로 제한해 실행 — 실제 운영 부하와 같은 조건.
- **발견(경미)**: 20건 실행 후 격리 네트워크 1개(`sandbox_net_*`)가 정리되지 않고 남아 있었다(컨테이너는 0개로 정상 정리됨). `run_auto_test()`의 `finally`에서 `container.stop()` 직후 곧바로 `network.remove()`를 호출하는데, Docker가 컨테이너의 네트워크 엔드포인트 분리를 완료하기 전에 호출되면 가끔 실패하는 경합으로 보인다(예외는 잡혀서 경고 로그만 남고 진행은 막지 않음). 직접 `docker network rm`으로 정리함. 기능 영향은 없으나(다음 요청에 새 네트워크를 또 만들 뿐) 누적되면 네트워크 리소스가 천천히 쌓일 수 있음 — 이번 작업 범위 밖이라 수정하지 않고 기록만 남김.

## 6. 투표 피드백 루프 엔드투엔드 실증 (2026-06-21)

"넘어간 게 의심이면 어떻게 처리되나"를 코드 설명이 아니라 실제
`analysis_service.analyze()` + `database.vote_service.save_vote()` 호출로
직접 보여준 실증 테스트(`backend/tests/run_vote_escalation_test.py`).

- **테스트 URL**: `http://8.8.8.8/promo` (`ip_in_url` 단일 시그널, baseline 35점 — 단독으론
  DANGER(70) 미달, 설계상 SUSPICIOUS여야 함)
- **1단계(투표 전)**: `analyze()` 호출 → status=**suspicious**, 설명카드 1개
- **2단계**: 서로 다른 `device_uuid` 10개로 danger 투표 적재 — 10/10건 저장 성공
- **3단계(투표 후 재분석)**: 같은 URL을 다시 `analyze()` 호출 → status=**danger**,
  설명카드 2개
- **결론**: **SUSPICIOUS → DANGER 승급 성공.** 
  `prior_danger_vote_high`(+35) 시그널이 실제 DB 투표를 거쳐 살아있는
  파이프라인에서 정확히 반영됨을 직접 확인 — 단위테스트(`test_heuristic_scorer.py`)
  는 `score_url()`에 합성 `vote_counts`를 직접 주입해서 시그널 로직만
  봤지, "투표 저장 → DB 반영 → 재분석 시 실제로 읽힘"이라는 전체 경로는
  이번에 처음 실데이터로 검증됐다.
- 테스트가 추가한 투표 행은 종료 후 자동 삭제해 운영 DB에 영향을 남기지 않음.

**관찰**: `AnalyzeResponse`는 `status`/`title`/`description`/`cards`만
반환하고 휴리스틱 점수 숫자(35→70)나 `triggered` 딕셔너리는 노출하지
않는다 — 사용자가 "왜 35점에서 70점으로 올랐는지"를 점수 단위로는 볼 수
없고 카드 텍스트로만 추론해야 한다. 이건 이전에 논의된 "설명카드 투명성
공백"(보류 항목)과 같은 지점이다.

## 7. 투표 기반 '안전 톤완화' 엔드투엔드 실증 (2026-06-21, SAFE 승격 아님)

섹션 6("투표→위험 승급")의 대칭 버전. `prior_safe_vote_high`(-15)가
실제로 점수를 낮추지만, **DC-06 때문에 화이트리스트 없이는 절대 SAFE로
승격되지 않는다**는 것을 직접 보여준다(`backend/tests/
run_safe_tone_down_test.py`).

- **테스트 URL**: `http://8.8.4.4/info` (`ip_in_url` 단일 시그널, baseline 35점)
- **1단계(투표 전)**: `analyze()` status=**suspicious**, `score_url()`
  score=**35** (triggered: ['ip_in_url'])
- **2단계**: 서로 다른 `device_uuid` 10개로 safe 투표 적재 — 10/10건 저장 성공
- **3단계(투표 후)**: `analyze()` status=**suspicious**, `score_url()`
  score=**20** (triggered: ['ip_in_url', 'prior_safe_vote_high'])
- **결론**:
  - 점수 톤완화 성공 — 35점 →
    20점 (`prior_safe_vote_high` -15 실제 반영됨)
  - SAFE 미승격 확인 — 투표
    전후 모두 `analyze()` 최종 판정은 **suspicious**로 유지. 투표가 아무리
    쌓여도 화이트리스트가 없으면 SAFE에 도달하지 못한다(DC-06, 절대
    바뀌지 않는 아키텍처 불변 원칙).
- 테스트가 추가한 투표 행은 종료 후 자동 삭제해 운영 DB에 영향을 남기지 않음.

**왜 이게 "보수적으로 안전 쪽에도 반영"이라는 설계의 정확한 의미인가**:
투표가 안전 쪽으로 쌓이면 경고 강도(점수)는 실제로 줄어든다 — 정상
신생 사이트가 영원히 같은 강도로 경고받는 UX 문제를 푼다. 하지만 "안전
승격"(화이트리스트 자동 추가 같은)은 절대 일어나지 않는다 — 1종 오류
(위험을 안전으로 오판)는 구조적으로 봉인돼 있고, 화이트리스트는 수동
검증된 도메인만 들어가는 별도 경로로 남는다. 이게 "왜 안전 승급을 더
적극적으로 안 했나"는 질문에 대한 정확한 답이다 — 적극적으로 안 한 게
아니라, 안전 오판의 비용이 위험 오판의 비용보다 훨씬 크기 때문에
의도적으로 막아둔 것.

## 8. 투표 단계별([0,1,3,5,10]건) 점수 추이 — 다중 URL 실증 (2026-06-21)

섹션 6/7(URL 1개·투표 전후 2-포인트 비교)의 일반화 버전
(`backend/tests/run_vote_calibration_sweep.py`). 투표량을
0→1→3→5→10건으로 단계적으로 누적하며 매 단계 `heuristic_scorer.score_url()`
점수를 기록 — `prior_danger_vote_low`(3~9건,+20) → `prior_danger_vote_high`
(≥10건,+35) 구간 전환이 계단형으로 나타나는지 확인한다(선형이 아니라
임계값 구간 설계이므로 1건→3건 사이에는 변화가 없는 것이 정상).

### 합성 URL danger 방향 (`http://1.1.1.1/verify`, `analyze()` 전체 경로)

| 투표 수 | score | triggered | analyze() status |
|---|---|---|---|
| 0 | 35 | ip_in_url | suspicious |
| 1 | 35 | ip_in_url | suspicious |
| 3 | 55 | ip_in_url, prior_danger_vote_low | suspicious |
| 5 | 55 | ip_in_url, prior_danger_vote_low | suspicious |
| 10 | 70 | ip_in_url, prior_danger_vote_high | danger |

단조 증가: **성공**.

### 합성 URL safe 방향 (`http://9.9.9.9/secure`, `analyze()` 전체 경로)

| 투표 수 | score | triggered | analyze() status |
|---|---|---|---|
| 0 | 35 | ip_in_url | suspicious |
| 1 | 35 | ip_in_url | suspicious |
| 3 | 30 | ip_in_url, prior_safe_vote_low | suspicious |
| 5 | 30 | ip_in_url, prior_safe_vote_low | suspicious |
| 10 | 20 | ip_in_url, prior_safe_vote_high | suspicious |

단조 감소: **성공**. 투표가 10건까지
쌓여도 `analyze()` 최종 판정은 끝까지 `suspicious` 유지 — 화이트리스트 없이는
SAFE로 승격되지 않음(DC-06) 재확인.

### 실데이터 C-TAS URL (`http://y02.o4ys.pw`, 블랙리스트 우회 — `score_url()` 단독 호출)

| 투표 수 | score | triggered |
|---|---|---|
| 0 | 10 | suspicious_tld |
| 1 | 10 | suspicious_tld |
| 3 | 30 | suspicious_tld, prior_danger_vote_low |
| 5 | 30 | suspicious_tld, prior_danger_vote_low |
| 10 | 45 | suspicious_tld, prior_danger_vote_high |

단조 증가: **성공**. 이 URL은 실제 C-TAS에
등재돼 `analyze()` 전체 경로에서는 투표와 무관하게 항상 DANGER다(블랙리스트
Early Return) — 여기서는 그 사실을 의도적으로 우회해 "블랙리스트가 없다고
가정해도 휴리스틱+투표만으로 실제 위험 URL을 향해 점수가 올라가는가"를
분리해서 검증했다.

**관찰**: 계단형 곡선은 버그가 아니라 설계다 — `prior_danger_vote_low`/`_high`가
연속값이 아니라 3~9건/≥10건 두 구간으로 나뉘어 있어서, 투표가 1건 늘어난다고
점수가 매번 조금씩 오르지 않는다. 이는 투표 1~2건 같은 소규모 어그로가
즉시 점수에 반영되지 않도록 막는 NF-29 어그로 방어 설계와 일치한다.
