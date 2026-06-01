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
        // 키는 저장소에 두지 않는다 — public github 노출 방지.
        //
        // 주입 방법 (택 1):
        //   1. ~/.gradle/gradle.properties 에 한 줄 (권장, 1회 셋업):
        //        kakaoNativeKey=<카카오 네이티브 키>
        //   2. 빌드 시 인자:
        //        flutter run -- -PkakaoNativeKey=<키>
        //   3. 환경변수:
        //        ORG_GRADLE_PROJECT_kakaoNativeKey=<키>
        //
        // 셋업 전체 절차는 docs/SETUP.md 참조.
        // 키가 비어 있으면 의도적으로 빌드를 중단해 사고를 빌드 시점에 차단한다.
        val kakaoKey = project.findProperty("kakaoNativeKey") as String? ?: ""
        if (kakaoKey.isEmpty()) {
            throw GradleException(
                "kakaoNativeKey 가 설정되지 않았습니다. " +
                "docs/SETUP.md 의 카카오 셋업 절차를 따르세요. " +
                "(예: ~/.gradle/gradle.properties 에 kakaoNativeKey=<키> 추가)"
            )
        }
        manifestPlaceholders["kakaoNativeKey"] = kakaoKey
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
