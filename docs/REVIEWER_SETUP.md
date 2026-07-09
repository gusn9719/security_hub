# 심사자용 빠른 시작 가이드

Flutter/Android SDK, 소스 빌드 없이 **미리 빌드된 APK + 스크립트 2개**만으로 앱 전체 기능(피싱 탐지, 가상 샌드박스, 카카오 로그인)을 직접 테스트하는 절차입니다.

> 소스를 직접 빌드하거나 개발을 이어가려면 [SETUP.md](SETUP.md) 참조.

---

## 1. 사전 준비물

| 준비물 | 용도 | 설치 |
|---|---|---|
| Python 3.11+ | 백엔드 실행 | [python.org](https://www.python.org/downloads/) — 설치 시 "Add to PATH" 체크 |
| Docker Desktop | 7-A/7-B 가상 샌드박스 (없어도 `/analyze` 탐지 기능은 정상 동작) | [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/) 설치 후 실행만 해두면 됨. 이미지(`kasmweb/chromium`, `browserless/chromium`)는 최초 샌드박스 요청 시 자동 다운로드됨 |
| Android 에뮬레이터 | APK 실행 | BlueStacks, Android Studio AVD 등 아무거나 |
| ADB | APK 설치 + `adb reverse` 로 로컬 백엔드 연결 | 에뮬레이터에 내장된 ADB 사용 가능, 또는 [Android Platform-Tools](https://developer.android.com/tools/releases/platform-tools) 설치 |

---

## 2. 저장소 다운로드

GitHub에서 clone 하거나 zip으로 다운로드합니다.

```powershell
git clone https://github.com/gusn9719/security_hub.git
cd security_hub
```

---

## 3. 백엔드 셋업 + 기동

저장소 폴더에서 `setup.bat`(최초 1회) → `start_server.bat`(매번)을 **더블클릭**하면 됩니다.
(`.ps1`을 직접 더블클릭하면 실행 대신 편집기로 열립니다 — Windows가 스크립트 오남용을 막기 위해 기본 설정해둔 동작이라, `.bat`이 그 대신 `powershell -ExecutionPolicy Bypass`로 실행해줍니다.)

터미널에서 직접 실행하고 싶다면 저장소 루트에서:

```powershell
.\setup.ps1          # 최초 1회 — venv, 패키지, .env, C-TAS/화이트리스트 데이터, DB 마이그레이션
.\start_server.ps1   # 매번 — 백엔드 기동 (http://localhost:8000)
```

`start_server.ps1` 실행 후 터미널에 `Uvicorn running on http://0.0.0.0:8000` 이 뜨면 서버가 정상 기동된 것입니다.

`setup.ps1`은 API 키 없이도 동작하도록 `JWT_SECRET`을 자동 생성합니다.
- **카카오 로그인**: 별도 키 입력 없이 APK 그대로 테스트 가능 (네이티브 키가 APK에 이미 포함되어 있고, 백엔드는 카카오 키를 사용하지 않음)
- **Gemini 7-B 요약**: 보고 싶으면 [Google AI Studio](https://aistudio.google.com/apikey)에서 무료 키 발급 후 `backend\.env`의 `GEMINI_API_KEY`에 채워넣기 (선택 사항 — 없어도 findings 목록은 그대로 표시됨)

---

## 4. 에뮬레이터 ↔ 로컬 백엔드 연결 (adb reverse)

배포된 APK는 `http://127.0.0.1:8000`으로 빌드되어 있습니다. 에뮬레이터 종류(Android Studio AVD, BlueStacks 등)에 따라 호스트 접근 IP 관례가 다르고 일부는 아예 안 통하기 때문에 (`10.0.2.2`는 QEMU/SLIRP 고유 관례라 다른 엔진에선 보장 안 됨), 에뮬레이터의 가상 네트워크를 거치지 않고 ADB 터널로 직접 연결합니다:

```powershell
adb connect 127.0.0.1:5555      # 에뮬레이터가 ADB를 TCP로 노출하는 경우 (BlueStacks 기본 포트 — 설정 > 고급 > Android Debug Bridge 에서 확인)
adb reverse tcp:8000 tcp:8000   # 기기의 127.0.0.1:8000 → 호스트의 127.0.0.1:8000
```

Android Studio AVD처럼 이미 `adb devices`에 잡혀 있는 경우 `adb connect` 없이 `adb reverse`만 실행하면 됩니다.

---

## 5. APK 설치 + 실행

[README.md](../README.md)의 다운로드 링크에서 APK를 받아 설치합니다. 과도한 권한요청(READ SMS 등)으로 Google Play Protect가 직접 설치를 막을 수 있어 ADB 강제 설치가 필요할 수 있습니다:

```powershell
adb install app-release.apk
```

---

## 6. 테스트 체크리스트

| 기능 | 확인 방법 |
|---|---|
| 피싱 탐지 (`/analyze`) | 홈 화면에서 URL/문자 붙여넣기 → 안전/의심/위험 판정 확인 |
| 7-A 직접 탐방 샌드박스 | 분석 결과에서 샌드박스 진입 → KasmVNC 화면 로딩 확인 (Docker Desktop 필요) |
| 7-B AI 자동 테스트 | 분석 결과에서 자동 테스트 진입 → findings 목록 확인 |
| 카카오 로그인 | 앱 내 로그인 화면 → 카카오 계정으로 로그인 → 프로필 표시 확인 |

문제가 있으면 `start_server.ps1`을 실행 중인 터미널 창의 로그를 먼저 확인하세요 — 대부분의 오류(포트 충돌, DB 미적재 등)가 여기 출력됩니다.
