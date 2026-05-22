# Security Hub
AI기반 피싱 탐지 및 가상 환경 테스트 앱 | 한이음 ICT 드림업 2026  

# 실행방법  
APK 다운로드 : https://github.com/gusn9719/security_hub/releases/download/dev-v260518/securityhub_v260518.apk  
설치 후 실행  
다만 현재 앱이 과도한 권한요청(READ SMS 등)으로 인해 사용자 직접 설치시 Google Play Protect로 설치가 불가능해 ADB방식 강제설치 필요  
1. PC에 ADB(Android SDK 플랫폼 도구) 설치(https://developer.android.com/tools/releases/platform-tools?hl=ko)  
2. 핸드폰 설정 - 개발자 도구 - USB 디버깅 활성화  
3. PC - 핸드폰 연결 후 핸드폰에서 이 PC에서 디버깅 허용  
4. PC 터미널 실행 후 ADB 설치 폴더로 이동  
5. adb install app-release.apk 입력  
