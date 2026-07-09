# 시스템 레벨 3분류(안전/의심/위험) 정확도 실측 결과

실행 일시: 2026-06-21
측정 대상: `backend/services/analysis_service.py`의 `AnalysisService.analyze()`
**전체 파이프라인**(0~8단계: 위험스킴→단축URL해제→블랙리스트→화이트리스트
→도메인평판→휴리스틱→DC-06 판정)을 실제로 호출.
`url_expander.expand_url`/`domain_reputation_service.analyze_domain_reputation`
만 mock(외부 네트워크 제거), 블랙리스트/화이트리스트는 **실제 DB** 사용.

## 왜 이 문서가 필요한가

`docs/heuristic_eval.md`는 `heuristic_scorer.score_url()` **단독**(파이프라인
7단계만)을 떼서 본 컴포넌트 단위 분석이다. 실제 사용자가 받는 안전/의심/
위험 판정은 휴리스틱 혼자 정하지 않는다 — 블랙리스트(3a/3b)·화이트리스트
(4단계)·휴리스틱(7단계)·DC-06 정책이 합쳐진 `analyze()` 전체의 결과다.
이 문서는 그 **전체 파이프라인의 진짜 정확도**를 측정한다. 두 문서를
혼동하지 않는 것이 중요하다 — "휴리스틱이 몇 점 맞췄나"와 "시스템이 안전/
의심/위험을 몇 번 맞췄나"는 다른 질문이다.

실제 판정 트리(`analysis_service.py` 1~365줄):
```
1단계 위험 스킴                              → DANGER
3a단계 url_hash 블랙리스트                    → DANGER
4단계 화이트리스트 히트 (Open Redirect 없음)   → SAFE   ← SAFE 가능한 유일한 경로
4단계 화이트리스트 히트 + Open Redirect       → SUSPICIOUS
3b단계 domain/registered_domain 블랙리스트     → DANGER  (화이트리스트 통과 후)
7단계 휴리스틱 score ≥ 70                     → DANGER
그 외 전부                                    → SUSPICIOUS  (DC-06)
```

## 1. 기존 테스트셋(`performance_test_set.json`, 508건) — `run_performance_eval.py`

이 테스트셋은 시스템 튜닝 과정에서 같이 써온 데이터다 — "한 번도 안 본
데이터에 대한 일반화 성능"이 아니라 "회귀(regression) 없이 의도대로
동작하는가"를 보는 것에 더 가깝다. 진짜 일반화 성능은 2번(독립 holdout)을
봐야 한다.

| 지표 | 값 |
|---|---|
| 정확도 (Accuracy) | **100.0%** |
| 정밀도 (Precision) | 100.0% |
| 재현율 (Recall) | 100.0% |
| FPR | 0.0% |
| FNR | 0.0% |

### 3분류 Confusion Matrix

| True \ Pred | safe | suspicious | danger |
|---|---|---|---|
| safe (182) | 182 | 0 | 0 |
| suspicious (75) | 0 | 75 | 0 |
| danger (251) | 0 | 0 | 251 |

(safe=whitelisted_safe 180+real_world_messages 2, suspicious=
boundary_suspicious 30+short_url_fp 45, danger=blacklisted_danger 201+
heuristic_danger 50)

### 카테고리별 정확도

| 카테고리 | 건수 | 정확도 |
|---|---|---|
| blacklisted_danger | 201 | 100.0% |
| boundary_suspicious | 30 | 100.0% |
| heuristic_danger | 50 | 100.0% |
| real_world_messages | 2 | 100.0% |
| short_url_fp | 45 | 100.0% |
| whitelisted_safe | 180 | 100.0% |

`short_url_fp`(DC-46/P0-1로 고친 단축URL 오탐 케이스 45건)가 100%인 것이
특히 의미있다 — 최근 수정한 버그가 회귀 없이 고정됐음을 확인.

## 2. 독립 홀드아웃(`ctas_holdout.json` + `safe_holdout.json`, 250건) — `run_holdout_eval.py`

튜닝에 한 번도 쓰이지 않은 데이터셋 — **이게 진짜 일반화 성능 지표**다.

| 지표 | 값 |
|---|---|
| Danger 탐지율 (위협으로 탐지 = suspicious+danger, n=200) | **100.0%** (200/200) |
| Danger 정확 탐지율 (정확히 danger, n=200) | 99.5% (199/200) — 1건은 suspicious로 다소 약하게 탐지(미탐 아님) |
| Safe 정확 탐지율 (n=50) | 100.0% (50/50) |
| Safe FPR | 0.0% (0/50) |
| **SRS 목표 (C-TAS Recall ≥ 95%)** | **실측 100.0% — PASS** |

## 3. 알려진 이슈: `run_combined_eval.py`의 holdout 미로딩

`run_combined_eval.py`(508+holdout 통합 버전)를 실행하면 "holdout_danger 0
+ holdout_safe 0"으로 표시되며 holdout 파일을 못 찾는다 — `run_holdout_eval.py`
는 같은 파일들을 정상적으로 로드하므로, `run_combined_eval.py`의 경로
탐색 로직에 버그가 있는 것으로 보인다(이번 작업 범위 밖, 수정 안 함).
이 평가에서는 `run_performance_eval.py`(508건)와 `run_holdout_eval.py`
(250건)를 각각 실행해 우회했다.

## 한계

- 1번(508건)은 튜닝에 쓰인 데이터라 100%가 "일반화"의 증거는 약하다 —
  "의도대로 회귀 없이 동작한다"는 증거로 읽어야 한다.
- 2번(250건)이 더 신뢰할 수 있는 일반화 성능 지표지만, 표본 200/50건도
  절대적으로 크진 않다.
- `expand_url`/WHOIS를 mock해서 외부 네트워크 의존 없이 빠르게 돌렸다 —
  실제 운영 중 단축 URL 해제나 WHOIS 실패가 결과에 미치는 영향은 이
  평가 범위 밖(`docs/qa_benchmark.md`의 응답시간 측정이 그 경로를
  실측했음).
