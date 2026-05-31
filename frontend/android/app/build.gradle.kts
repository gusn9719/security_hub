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
        // 졸업작품 시연 단순화를 위해 default 키를 직접 박는다.
        //
        // 노출 위험은 실질 0 — Android native key 는 APK 디컴파일 시 반드시
        // 노출되는 값이고, 카카오 SDK 의 보안 모델은 '콘솔 등록 키해시 검증'
        // 으로 강제된다. 키 자체 노출만으로 악용 불가.
        // public git 푸시만 주의하면 된다.
        //
        // 운영/배포 시 다른 키로 바꾸려면 -PkakaoNativeKey=... 또는
        // ORG_GRADLE_PROJECT_kakaoNativeKey 환경변수로 오버라이드 가능.
        manifestPlaceholders["kakaoNativeKey"] =
            (project.findProperty("kakaoNativeKey") as String?
                ?: "50f09a9edb8273c2690a09f0f5d18c65")
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
