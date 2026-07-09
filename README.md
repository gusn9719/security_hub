# Security Hub

**AI기반 피싱 탐지 및 가상 환경 테스트 앱** — 한이음 ICT 드림업 2026

의심스러운 문자·URL을 다신호 스코어링 파이프라인으로 분석해 **안전 / 의심 / 위험** 3단계로 판정하고, 판정이 애매한 경우 격리된 가상 샌드박스(직접 탐방 또는 AI 자동 테스트)에서 사용자가 직접 확인해볼 수 있게 하는 Flutter(Android) + FastAPI 앱입니다.

> 팀원: 고윤혁(Backend) · 임현우(Frontend·통합) · 배성민(Data·Sandbox)

## 목차

- [프로젝트 소개](#프로젝트-소개)
- [핵심 기능](#핵심-기능)
- [시스템 아키텍처](#시스템-아키텍처)
- [기술 스택](#기술-스택)
- [문서](#문서)
- [환경설정방법](#환경설정방법)
  - [1. 사전 준비물](#1-사전-준비물)
  - [2. 저장소 다운로드](#2-저장소-다운로드)
  - [3. 백엔드 설치 및 가동](#3-백엔드-설치-및-가동)
  - [4. 에뮬레이터 ↔ 로컬 백엔드 연결 (adb reverse)](#4-에뮬레이터--로컬-백엔드-연결-adb-reverse)
- [실행방법](#실행방법)

---

## 프로젝트 소개

문자를 통한 스미싱 피해 경험에서 출발한 프로젝트입니다. "링크를 안전하게 눌러볼 수 있게 하면 되지 않을까?"라는 질문에서, 의심스러운 링크를 실제로 클릭하기 전에 **다신호 휴리스틱 스코어링**으로 위험도를 먼저 판정하고, 판단이 애매하면 기기 밖 **격리된 가상 브라우저**에서 안전하게 직접 확인할 수 있는 앱을 만들었습니다.

**핵심 판정 로직은 AI/LLM이 아니라 규칙 기반 다신호 스코어링입니다.** 블랙리스트·화이트리스트 대조, WHOIS/SSL 기반 도메인 평판, 타이포스쿼팅·동형문자·서브도메인 스푸핑 등 25종 휴리스틱 시그널을 가중합해 판정하며, 시그널 하나만으로는 위험 판정이 나오지 않도록(2개 이상 조합 필수) 설계했습니다. 생성형 AI(Gemini)는 이 판정 과정에는 전혀 관여하지 않고, **AI 자동 테스트 샌드박스(7-B)가 수집한 결과를 사람이 읽기 쉬운 자연어로 요약하는 보조 역할**에만 선택적으로 사용됩니다 — 없어도 탐지 기능은 정상 동작합니다.

또 하나의 핵심은 **피드백 순환 구조**입니다. 사용자가 가상 샌드박스에서 직접 확인한 뒤 남긴 안전/위험/스팸 투표가 누적되어 다음 분석의 휴리스틱 시그널로 즉시 반영됩니다 — 한 번 판정하고 끝나는 도구가 아니라, C-TAS가 아직 못 잡은 신규 위협을 사용자 참여로 발견하고 학습하는 구조입니다.

## 핵심 기능

| 기능 | 설명 |
|---|---|
| 문자 입력 5경로 | 직접 입력, 공유하기, 클립보드 자동 감지, 문자함 불러오기, SMS 수신 알림 — 전부 동일 분석 파이프라인으로 수렴 |
| 3단계 위험도 판정 | 블랙리스트 → 화이트리스트 → 도메인 평판 → 휴리스틱 25종 시그널을 거쳐 안전/의심/위험 판정, 근거를 설명카드로 제시 |
| 7-A 직접 탐방 샌드박스 | Docker 격리 Chromium을 noVNC로 조작해 실제 기기 밖에서 위험 사이트 확인, CDP 기반 실시간 위협(피싱 이동·악성 다운로드) 자동 차단 |
| 7-B AI 자동 테스트 샌드박스 | Browserless + Playwright가 가짜 개인정보를 자동 입력해 피싱 폼 여부를 기계적으로 탐지, Gemini가 결과만 자연어로 요약 |
| 사용자 투표 피드백 | 샌드박스 체험 후 안전/위험/스팸 투표 → 다음 분석의 휴리스틱 점수에 즉시 반영 |
| 카카오 소셜 로그인 | 비회원(익명 device_uuid)도 전 기능 사용 가능하되, 로그인 시 투표 신뢰도 가중치 상승(어뷰징 방지) |
| 보안 하드닝 | TRACE/CONNECT/TRACK 등 위험 HTTP 메서드 차단, 보안 응답 헤더, 전역 예외 처리로 스택트레이스 미노출, 만료 캐시 자동 정리 |

## 시스템 아키텍처

![시스템 구성도](docs/system_architecture.png)

UI(파랑) → 서비스 로직(초록) → DB(노랑) 3계층 구조입니다. "의심사유 생성"은 사전 정의된 설명 카드 딕셔너리에서만 만들어지며(LLM 미사용, 할루시네이션 방지), 샌드박스 투표 결과가 다시 휴리스틱 스코어링에 피드백되는 순환 구조가 핵심입니다. 더 상세한 기술 버전은 [docs/system_architecture.md](docs/system_architecture.md)를, DB 스키마는 [docs/ERD.md](docs/ERD.md)를 참고하세요.

## 기술 스택

| 영역 | 기술 |
|---|---|
| 백엔드 | Python 3.11+, FastAPI, Uvicorn, SQLite (WAL) |
| 프론트엔드 | Flutter (Dart), Android only |
| 가상 샌드박스 | Docker (`kasmweb/chromium`, `ghcr.io/browserless/chromium`), Playwright, Chrome DevTools Protocol |
| 도메인 분석 | python-whois, tldextract, Levenshtein 거리(타이포스쿼팅) |
| 인증 | 카카오 로그인 API, JWT(HS256) |
| 외부 API | Google Gemini 2.5 Flash — 7-B 샌드박스 결과 자연어 요약 전용, 판정 로직에는 미관여 |

## 문서

| 문서 | 내용 |
|---|---|
| [docs/system_architecture.md](docs/system_architecture.md) | 시스템 구성도 (Mermaid 상세 버전) |
| [docs/ERD.md](docs/ERD.md) | DB ERD |
| [docs/SRS.xlsx](docs/SRS.xlsx) | 요구사항 명세서 |
| [docs/use_case_diagram.md](docs/use_case_diagram.md) | 유즈케이스 다이어그램 |
| [docs/FINAL_REPORT.md](docs/FINAL_REPORT.md) | 최종 결과보고서 |
| [docs/guide/](docs/guide/00_인덱스.md) | 기능별 상세 가이드 (분석 파이프라인, 샌드박스, 투표/인증 등) |
| [docs/SETUP.md](docs/SETUP.md) | 개발자용 소스 빌드 셋업 가이드 |
| [docs/REVIEWER_SETUP.md](docs/REVIEWER_SETUP.md) | 심사자용 빠른 시작 가이드 |

---

# 환경설정방법   

## 1. 사전 준비물

| 준비물 | 용도 | 설치 |
|---|---|---|
| Python 3.11+ | 백엔드 실행 | [python.org](https://www.python.org/downloads/) — 설치 시 "Add to PATH" 체크 |
| Docker Desktop | 7-A/7-B 가상 샌드박스 (없어도 분석 기능 정상 작동) | [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/) 설치 후 실행 |
| Android 에뮬레이터 | APK 실행 | BlueStacks, MUMU 등 아무거나 |
| ADB | APK 설치 + `adb reverse` 로 로컬 백엔드 연결 | [Android Platform-Tools](https://developer.android.com/tools/releases/platform-tools) 설치 |

---

## 2. 저장소 다운로드

GitHub에서 clone 하거나 zip으로 다운로드합니다.

```powershell
git clone https://github.com/gusn9719/security_hub.git
cd security_hub
```

---

## 3. 백엔드 설치 및 가동
[setup.ps1 다운](https://github.com/gusn9719/security_hub/releases/download/dev-v260701/setup.ps1)
[start_server.ps1 다운](https://github.com/gusn9719/security_hub/releases/download/dev-v260701/start_server.ps1)

저장소 루트에서:

```powershell
.\setup.ps1          # 최초 1회 — venv, 패키지, .env, C-TAS/화이트리스트 데이터, DB 마이그레이션
.\start_server.ps1   # 매번 — 백엔드 기동 (http://localhost:8000)
```

- 샌드박스 자동탐방 위험 요약을 보려면 [Google AI Studio](https://aistudio.google.com/apikey)에서 키 발급 후 `backend\.env`의 `GEMINI_API_KEY`에 입력 필요. (선택 사항 — 없어도 분석 목록은 그대로 표시됨)

---

## 4. 에뮬레이터 ↔ 로컬 백엔드 연결 (adb reverse)

배포된 APK는 `http://127.0.0.1:8000`으로 빌드되어 있습니다. 에뮬레이터의 가상 네트워크를 거치지 않고 ADB 터널로 직접 연결합니다:

```powershell
adb connect 127.0.0.1:(포트번호)      # 에뮬레이터가 ADB를 TCP로 노출하는 경우 (BlueStacks 기본 포트 — 설정 > 고급 > Android Debug Bridge 에서 확인)
adb reverse tcp:8000 tcp:8000   # 기기의 127.0.0.1:8000 → 호스트의 127.0.0.1:8000
```

이미 `adb devices`에 잡혀 있는 경우 `adb connect` 없이 `adb reverse`만 실행하면 됩니다.

---

   
# 실행방법  
APK 다운로드 : https://github.com/gusn9719/security_hub/releases/download/dev-v260701/app-release.apk
설치 후 실행  
다만 현재 앱이 과도한 권한요청(READ SMS 등)으로 인해 사용자 직접 설치시 Google Play Protect로 설치가 불가능할 시 ADB방식 강제설치 필요  
1. PC에 ADB(Android SDK 플랫폼 도구) 설치(https://developer.android.com/tools/releases/platform-tools?hl=ko)  
2. 에뮬레이터에서 USB 디버깅 활성화
3. PC 터미널 실행 후 ADB 설치 폴더로 이동  
4. adb install app-release.apk 입력
