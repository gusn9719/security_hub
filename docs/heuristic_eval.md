# 휴리스틱 스코어러 컴포넌트 단위 분석

실행 일시: 2026-06-21 16:35:24
측정 대상: `backend/services/heuristic_scorer.score_url()` 단독 호출
(블랙리스트/화이트리스트 우회, `domain_evidence=vote_counts=sandbox_score=None`)

> **이 문서는 시스템 정확도가 아니다.** "안전/의심/위험을 시스템이 얼마나 잘 맞히는가"는 [`docs/system_accuracy_eval.md`](system_accuracy_eval.md)를 봐야 한다 — `AnalysisService.analyze()` 전체 파이프라인(블랙리스트+화이트리스트+휴리스틱+DC-06)을 실제로 호출해서 낸 수치다(508건 100%, 독립 holdout 250건 danger recall 100%/safe FPR 0%). 이 문서는 그중 **7단계 휴리스틱 컴포넌트 하나만** 떼어서 내부 동작(점수 분포, threshold 민감도, 시그널별 발화 빈도)을 본다.

**왜 따로 보는가**: `run_performance_eval.py`는 블랙/화이트리스트가 먼저 가로채는 구조라 휴리스틱이 508건 중 80건에서만 호출되고, `domain_evidence`를 빈 값으로 넘겨서 25종 시그널 중 10개(WHOIS 3종+투표 6종+샌드박스 1종)는 그 80건에서도 구조적으로 발화하지 않는다. 이 문서는 그 컴포넌트 내부를 직접 들여다본다. 10개 사각지대 시그널은 `backend/tests/test_heuristic_scorer.py`(58개 단위테스트 전부 PASS)가 합성 입력으로 따로 검증한다.

## 1. raw 점수 분포

| 데이터셋(라벨) | min | median | mean | max |
|---|---|---|---|---|
| heuristic_danger(danger) | 70 | 77.5 | 80.7 | 130 |
| boundary_suspicious(suspicious) | 0 | 0.0 | 0 | 0 |
| whitelisted_safe(safe) | 0 | 0.0 | 1.9 | 35 |

danger군은 70점 이상에 몰려 있고(70~130), suspicious/safe군은 거의 0점에 몰려 있다 — 휴리스틱 점수가 **이산적/이중모드(bimodal)**다. 30~69점(SUSPICIOUS 내부 구간)에 실제로 떨어지는 케이스가 이 정적 신호만으로는 거의 없다는 뜻 — 그 중간 영역을 메우는 건 WHOIS/투표/샌드박스 같은 사각지대 시그널들의 역할로 설계돼 있다(섹션 3 참조).

## 2. DANGER_THRESHOLD 민감도

현재 `DANGER_THRESHOLD=70`. heuristic_danger군 점수가 ≥T인 비율과 whitelisted_safe군 점수가 ≥T인 비율을 40~90 사이에서 스윕(시스템 recall/FPR이 아니라 이 컴포넌트의 점수가 threshold 근처에서 얼마나 여유가 있는지를 보는 것).

| Threshold | danger군 ≥T 비율 | safe군 ≥T 비율 | |
|---|---|---|---|
| 40 | 1.000 | 0.000 | |
| 45 | 1.000 | 0.000 | |
| 50 | 1.000 | 0.000 | |
| 55 | 1.000 | 0.000 | |
| 60 | 1.000 | 0.000 | |
| 65 | 1.000 | 0.000 | |
| 70 | 1.000 | 0.000 | **← 현재값** |
| 75 | 0.580 | 0.000 | |
| 80 | 0.500 | 0.000 | |
| 85 | 0.240 | 0.000 | |
| 90 | 0.200 | 0.000 | |

40~70 구간은 동일하고 75부터 급락한다 — 현재 70 설정이 "더 낮춰도 이 데이터셋 안에서는 손해 없고, 75 이상은 위험"한 지점에 걸쳐 있음을 보여준다. (이게 시스템 recall이 아니라는 점에 유의 —  시스템 recall은 `system_accuracy_eval.md`의 holdout 결과 참조.)

## 3. 시그널별 발화 통계

danger군 n=50, safe군 n=180. `signal_precision` = danger군 발화 / (danger군 발화 + safe군 발화).

| 시그널 | 가중치 | danger 발화 | safe 발화 | signal_precision |
|---|---|---|---|---|
| `dangerous_extension` | +35 | 50 | 0 | 1.00 |
| `suspicious_tld` | +10 | 30 | 0 | 1.00 |
| `suspicious_keywords` | +20 | 12 | 1 | 0.92 |
| `ip_in_url` | +35 | 10 | 0 | 1.00 |
| `userinfo_injection` | +35 | 10 | 0 | 1.00 |
| `typosquat_levenshtein` | +35 | 10 | 9 | 0.53 |
| `subdomain_spoofing` | +30 | 10 | 0 | 1.00 |
| `brand_keyword_mismatch` | +20 | 10 | 0 | 1.00 |
| `excessive_subdomains` | +15 | 6 | 0 | 1.00 |
| `homograph_idn` | +30 | 2 | 0 | 1.00 |
| `port_in_url` | +10 | 2 | 0 | 1.00 |
| `punycode_in_url` | +15 | 1 | 0 | 1.00 |
| `many_hyphens` | +10 | 1 | 0 | 1.00 |

**미발화 12개** — 구조적 사각지대 10개(domain_evidence/vote_counts/sandbox_score=None이라 원천 불가):
  - `prior_danger_vote_high` (weight=+35)
  - `sandbox_danger_score` (weight=+40)
  - `new_domain` (weight=+20)
  - `whois_no_record` (weight=+20)
  - `prior_danger_vote_low` (weight=+20)
  - `fresh_infrastructure` (weight=+15)
  - `prior_spam_vote_high` (weight=+10)
  - `prior_spam_vote_low` (weight=+5)
  - `prior_safe_vote_high` (weight=-15)
  - `prior_safe_vote_low` (weight=-5)
우연한 데이터 공백 2개(정적 시그널이지만 패턴이 데이터셋에 없었음):
  - `double_encoding` (weight=+15)
  - `url_too_long` (weight=+5)

위 12개 전부 `backend/tests/test_heuristic_scorer.py`에서 합성 입력으로 양성/음성 둘 다 검증됨(58개 단위테스트 전부 PASS).

## 관련 문서

- **시스템 레벨 3분류 정확도**: [`docs/system_accuracy_eval.md`](system_accuracy_eval.md)
- **휴리스틱 25종 시그널 단위테스트**: `backend/tests/test_heuristic_scorer.py`
- **투표→위험 승급 / 투표→안전 톤완화 실증**: [`docs/sandbox_eval.md`](sandbox_eval.md)
- **7-B 샌드박스 실데이터 평가**: [`docs/sandbox_eval.md`](sandbox_eval.md)

## 한계

- 표본 30/50/180건은 작은 편.
- `domain_evidence=None` 가정은 "첫 등장 URL" 시나리오라 실제보다 보수적인(시그널이 적게 발화하는) 하한선에 가깝다.
- `whitelisted_safe` 180건은 실제 운영에서는 화이트리스트로 SAFE 처리되며 휴리스틱을 거치지 않는다 — 여기서는 "화이트리스트가 없다고 가정해도 휴리스틱 단독으로 안전한가"라는 defense-in-depth 질문에 답한 것이다.
