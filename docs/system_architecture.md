# 시스템 구성도 (2026-07-02 기준, 최종보고서 채택본)

![시스템 구성도](system_architecture.png)

> 위 다이어그램이 최종보고서(`FINAL_REPORT.md`/`.docx`) 4.1절에 실제로 채택된
> 버전이다. UI(파랑) → 서비스 로직(초록) → DB(노랑) 3계층 구조로, 로그인/회원가입,
> 문자 전처리~휴리스틱 스코어링~의심사유 생성까지의 분석 파이프라인, 7-A/7-B
> 샌드박스와 사용자 투표까지 한 화면에 담았다. **"의심사유 생성"은 이 다이어그램에서도
> Gemini가 아니라 서비스 로직 계층(초록)에 위치** — `explanation_service.py`의
> `EXPLANATION_DICT` 딕셔너리 기반이며 LLM을 호출하지 않는다(DC-25). Gemini는
> 이 그림에는 등장하지 않는 7-B 샌드박스 findings 자연어 요약 전용 외부 서비스다.
>
> 아래 Mermaid 소스는 미들웨어 체인·DB 스키마·외부 서비스까지 포함한 더 상세한
> 기술 버전이다(개발자 참고용, 위 채택본과 내용은 동일하되 세분화 수준이 다름).
>
> 이전 `시스템구성도.png`(2026-05-17 작성, `docs/legacy/`로 이동)는 "의심사유 생성"을
> **Gemini 호출**로 표기하고 있었다. DC-25 확정 전 초기 설계도로 현재 코드와 모순돼
> 이 문서로 대체했다.

```mermaid
flowchart TB
    subgraph Flutter["Flutter 앱 (Android)"]
        UI_Input["문자 입력\n직접입력 · 붙여넣기 · 공유하기\n클립보드감지 · 알림읽기 · 문자함불러오기"]
        UI_Login["로그인 UI\n카카오 로그인 / 비회원"]
        UI_Result["분석 결과 UI\n신호등 3단계(안전/의심/위험) + 설명카드"]
        UI_Action["액션 UI\n발신번호 차단 이동 · URL 열기"]
        UI_Sandbox["샌드박스 UI\n7-A 직접조작 / 7-B AI자동조작"]
    end

    subgraph MW["보안 미들웨어 체인 (main.py)"]
        direction LR
        M1["CORS"] --> M2["SecurityHeaders"] --> M3["RateLimit(IP)"] --> M4["DeviceUUID 강제"] --> M5["OptionalAuth(JWT)"] --> M6["BlockDangerousMethods"]
    end

    subgraph Pipeline["분석 파이프라인 (analysis_service.py, Early Return)"]
        Pre["0. URL 추출 + 1. 위험스킴 체크"]
        Expand["2. 단축URL 해제(SSRF 방어, 최대 3-hop)"]
        BL["3. 블랙리스트 매칭\nurl_hash→domain→registered_domain"]
        WL["4. 화이트리스트 매칭\nexact/suffix/pattern"]
        Rep["5~6. 도메인 평판\nWHOIS/SSL, 캐시 TTL 7일"]
        Heur["7. 휴리스틱 스코어링\n25종 시그널 가중합, DANGER≥70 / SUSPICIOUS≥30"]
        Expl["8. 설명카드 생성\nEXPLANATION_DICT (LLM 미사용, 할루시네이션 방지)"]
    end

    subgraph Auth["인증 (AUTH-01~03)"]
        AuthSvc["jwt_service / kakao_service\nHS256, 32자 미만 시크릿 거부"]
    end

    subgraph DB["데이터베이스 (SQLite WAL)"]
        BLDB[("blacklist\nC-TAS")]
        WLDB[("whitelist\n수동 등록")]
        RepDB[("domain_reputation_cache\nTTL 7일")]
        VoteDB[("url_votes\n(device_uuid, registered_domain) 부분UNIQUE")]
        SandboxDB[("sandbox_results\nTTL 24h")]
        HistDB[("analysis_history")]
        UserDB[("users\n카카오 가입자")]
    end

    subgraph Sandbox["가상 샌드박스 서버 (Docker)"]
        A7["7-A 직접탐방\nkasmweb/chromium + noVNC\nCDP 실시간 위협차단(DC-34)"]
        B7["7-B AI 자동테스트\nBrowserless + Playwright\n가짜정보 자동입력"]
    end

    subgraph External["외부 서비스"]
        Gemini["Gemini 2.5 Flash\n7-B findings 자연어 요약 전용\n(⚠ 분석 파이프라인에는 관여하지 않음)"]
        KakaoAPI["kapi.kakao.com\n/v2/user/me"]
    end

    UI_Input --> MW
    UI_Login --> AuthSvc --> KakaoAPI
    AuthSvc --> UserDB
    MW --> Pre --> Expand --> BL
    BL -->|hit| UI_Result
    BL --- BLDB
    BL -->|miss| WL
    WL -->|hit, 스푸핑없음| UI_Result
    WL --- WLDB
    WL -->|miss / Open Redirect| Rep
    Rep --- RepDB
    Rep --> Heur
    VoteDB -.->|prior_danger/safe/spam_vote_*| Heur
    Heur --> Expl --> UI_Result
    Heur -.-> HistDB
    UI_Result --> UI_Action
    UI_Result --> UI_Sandbox
    UI_Sandbox --> A7 & B7
    A7 --> SandboxDB
    B7 --> SandboxDB
    B7 -.->|findings 요약 요청| Gemini
    SandboxDB -.->|사용자 투표 safe/danger/spam| VoteDB
    SandboxDB -.->|sandbox_danger_score≥70| Heur
```

## 이전 버전과의 핵심 차이

| 항목 | `시스템구성도.png` (legacy) | 현재 |
|---|---|---|
| 의심/위험 사유 생성 | "Gemini 호출 · 설명 전담" | `EXPLANATION_DICT` 딕셔너리 조회 (LLM 미사용, DC-25) |
| Gemini 역할 | 파이프라인 핵심 로직 | 7-B 샌드박스 findings 자연어 요약 전용 |
| 인증 | 없음 | 카카오 로그인 + JWT (AUTH-01~03), `users` 테이블 |
| 휴리스틱 | 없음(암묵적으로 도메인평판만 표기) | 25종 시그널 가중합, DANGER_THRESHOLD=70 |
| 투표 피드백 순환 | 없음 | `url_votes` → `prior_*_vote_*` 시그널 → 다음 분석 반영 |
| 보안 미들웨어 | 없음 | CORS→SecurityHeaders→RateLimit→DeviceUUID→OptionalAuth→BlockDangerousMethods |
