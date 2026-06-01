# 셋업 가이드

신규 PC에서 처음 빌드할 때만 1회 수행. 셋업이 끝나면 이후엔 `flutter run` 한 줄로 동작.

---

## 1. 백엔드 (`backend/.env`)

`backend/.env.example` 을 복사해 `backend/.env` 로 사용:

```powershell
Copy-Item backend\.env.example backend\.env
```

필수 항목을 채운다:

| 변수 | 값 | 비고 |
|---|---|---|
| `GEMINI_API_KEY` | Google AI Studio 의 API 키 | 7-B 자연어 요약용 |
| `KAKAO_REST_API_KEY` | 카카오 디벨로퍼스 콘솔 → 앱 → "REST API 키" | 백엔드 access_token 검증용. 네이티브 키 아님 |
| `JWT_SECRET` | 32 자 이상 hex 문자열 | `openssl rand -hex 32` 결과. 32 자 미만이면 서버 기동 거부 (RFC 7518 §3.2) |

선택 항목 (`BASE_URL`, `FORCE_HTTPS`, `DISABLE_DOCS` 등) 은 `.env.example` 의 주석 참조.

---

## 2. 프론트엔드 — 카카오 키

카카오 네이티브 키는 **두 곳**에 같은 값을 주입해야 한다.

1. **Flutter 측** (`KakaoSdk.init` 용) — Dart `String.fromEnvironment`
2. **Android 측** (`AndroidManifest.xml` 의 redirect scheme `kakao{키}://oauth`) — Gradle `manifestPlaceholder`

한 쪽만 빠지면 카카오 Accept 화면에서 우리 앱으로 redirect 가 안 돌아온다.

### 2-1. Flutter 측 — `.kakao.env` 한 번 만들기

프로젝트 루트의 `.kakao.env.example` 을 복사:

```powershell
Copy-Item .kakao.env.example .kakao.env
```

`.kakao.env` 를 열어 실제 값으로 채운다:

```json
{
  "KAKAO_NATIVE_KEY": "카카오 디벨로퍼스 콘솔의 '네이티브 앱 키'",
  "API_BASE_URL": "http://10.0.2.2:8000"
}
```

> `.kakao.env` 는 `.gitignore` 처리되어 있다. 저장소에 올라가지 않는다.

### 2-2. Android 측 — `~/.gradle/gradle.properties` 한 번 추가

Windows 의 경우 파일 경로:
```
C:\Users\<사용자>\.gradle\gradle.properties
```

파일이 없으면 새로 만들고 한 줄 추가:

```
kakaoNativeKey=<위와 같은 네이티브 키>
```

> 이 파일은 사용자 홈에 있고 본 저장소와 무관하다.
> 따라서 다른 프로젝트에도 영향 없고, git 노출 위험도 없다.

키가 비어 있는 상태로 빌드를 시도하면 `build.gradle.kts` 가 의도적으로 `GradleException` 을 던져 빌드가 즉시 중단된다.

---

## 3. 실행

### 백엔드

```powershell
cd C:\dev\security_hub\backend
venv\Scripts\Activate.ps1
uvicorn main:app --reload --port 8000
```

### 프론트엔드

```powershell
cd C:\dev\security_hub\frontend
flutter run --dart-define-from-file=.kakao.env
```

> 매번 인자가 귀찮으면 `--dart-define-from-file=.kakao.env` 를 IDE 의 launch configuration 에 한 번만 등록해 두면 된다.

---

## 4. 다른 PC 에서 빌드할 때

위 1·2 단계를 동일하게 반복.
`.env`, `.kakao.env`, `~/.gradle/gradle.properties` 셋 다 사용자 로컬 전용.

---

## 5. 키를 다른 값으로 바꿔야 할 때 (배포 빌드 등)

```powershell
# 일회성 오버라이드
flutter build apk `
    --dart-define=KAKAO_NATIVE_KEY=<배포용 키> `
    --dart-define=API_BASE_URL=<배포용 URL> `
    -- -PkakaoNativeKey=<배포용 키>
```

`--dart-define` 가 `.kakao.env` 보다, `-PkakaoNativeKey` 가 `gradle.properties` 보다 우선 적용된다.
