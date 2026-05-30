plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.example.security_hub"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "com.example.security_hub"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName

        // AUTH-01: 카카오 SDK redirect 스킴은 'kakao{NATIVE_APP_KEY}://oauth' 다.
        // 키를 manifest 에 직접 박지 않고 -PkakaoNativeKey=... 빌드 인자로 주입.
        // 사용 예:
        //   flutter build apk --dart-define=KAKAO_NATIVE_KEY=xxxxx \
        //                     -- -PkakaoNativeKey=xxxxx
        // 미지정 시 빈 문자열 — 빌드는 통과하지만 카카오 로그인 시 스킴 매칭
        // 실패. CI / 로컬 빌드 모두 같은 키를 두 군데 (Dart side / Android side)
        // 에 넘겨야 하는 것은 카카오 SDK 의 본질적 제약.
        manifestPlaceholders["kakaoNativeKey"] =
            (project.findProperty("kakaoNativeKey") as String? ?: "")
    }

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

flutter {
    source = "../.."
}
