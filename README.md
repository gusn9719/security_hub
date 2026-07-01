# Security Hub
AI기반 피싱 탐지 및 가상 환경 테스트 앱 | 한이음 ICT 드림업 2026  

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
