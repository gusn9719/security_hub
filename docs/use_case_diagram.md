# 유즈케이스 다이어그램 (2026-07-01 기준)

> 이전 `유즈케이스 다이어그램.png`(2026-05-17 작성)는 "의심/위험 사유 생성"을
> **Gemini API가 수행하는 시스템 처리**로 그리고 있었다. `시스템구성도.png`와
> 동일한 이유로 현재 코드(DC-25, `explanation_service.py`)와 모순되어
> `docs/legacy/유즈케이스 다이어그램.png`로 이동했다. 카카오 로그인(AUTH-01~03)과
> 투표(url_votes 피드백 순환) 유즈케이스도 없어서 이번에 추가했다.

```mermaid
flowchart LR
    User(("사용자"))
    Kakao(("카카오 API\n외부 서비스"))

    subgraph System["Security Hub 시스템 처리"]
        UC0["카카오 로그인 / 비회원 시작"]
        UC1["문자·URL 분석 요청"]
        UC2["분석 결과 확인\n안전/의심/위험 + 설명카드"]
        UC3["링크 열기"]
        UC4["발신번호 차단"]
        UC5["가상 샌드박스 실행"]
        UC6["7-A 직접 탐방 모드"]
        UC7["7-B AI 자동 테스트 모드"]
        UC8["탐지 결과 리포트 확인"]
        UC9["안전/위험/스팸 투표"]
        UC10["설명카드 생성\nEXPLANATION_DICT 조회 (LLM 미사용)"]
    end

    User --> UC0 -->|include| Kakao
    User --> UC1 -->|include| UC2
    UC2 -->|extend: 안전| UC3
    UC2 -->|extend: 위험| UC4
    UC2 -->|extend: 의심·위험| UC5
    UC2 -->|include| UC10
    UC5 -->|extend| UC6
    UC5 -->|extend| UC7
    UC7 -->|include| UC8
    UC6 -->|include| UC9
    UC9 -.->|url_votes 누적 → prior_*_vote_* 시그널로 다음 분석 반영| UC1
```

## 이전 버전과의 핵심 차이

| 항목 | `유즈케이스 다이어그램.png` (legacy) | 현재 |
|---|---|---|
| 의심/위험 사유 생성 주체 | Gemini API (외부 액터) | 시스템 내부 `EXPLANATION_DICT` 조회 — 외부 LLM 호출 없음 |
| 로그인 | 유즈케이스 없음 | 카카오 로그인/비회원 시작 추가 (AUTH-01~03) |
| 투표 | 유즈케이스 없음 | 안전/위험/스팸 투표 + 분석 파이프라인 피드백 순환 추가 |
