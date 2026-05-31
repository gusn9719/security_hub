import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show SystemChrome, SystemUiOverlayStyle;
import 'package:kakao_flutter_sdk_user/kakao_flutter_sdk_user.dart';

import 'screens/home_screen.dart';
import 'screens/login_screen.dart';
import 'services/auth_service.dart';

// AUTH-01: 카카오 네이티브 앱 키.
// 졸업작품 시연 단순화를 위해 default 에 키를 박는다. build.gradle.kts 의
// manifestPlaceholder 와 동일 가치 — APK 디컴파일하면 어차피 노출되는 값.
// public git 푸시만 주의. 다른 키로 빌드하려면 --dart-define=KAKAO_NATIVE_KEY=...
// 로 오버라이드.
const String _kakaoNativeKey = String.fromEnvironment(
  'KAKAO_NATIVE_KEY',
  defaultValue: '50f09a9edb8273c2690a09f0f5d18c65',
);

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // 카카오 SDK 초기화. 키가 비어있어도 init 자체는 통과하지만 로그인 시점에
  // SDK 가 에러를 낸다 — 운영자가 빌드 시 키를 빼먹은 사실을 즉시 알게 된다.
  KakaoSdk.init(nativeAppKey: _kakaoNativeKey);

  // SharedPreferences 에 저장된 JWT/프로필 복원. runApp 이전에 동기 캐시
  // 채우는 게 목적 — currentJwt()/currentUser() 가 첫 빌드부터 정확한 값.
  await AuthService.bootstrap();

  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: Brightness.dark,
    ),
  );
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: '보안 검증 시스템',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1A56DB),
          brightness: Brightness.light,
        ),
        useMaterial3: true,
        fontFamily: 'sans-serif',
      ),
      // 첫 실행이면 LoginScreen, 가입자 또는 익명 선택 사용자면 HomeScreen.
      home: AuthService.shouldShowLogin()
          ? const LoginScreen()
          : const HomeScreen(),
    );
  }
}
