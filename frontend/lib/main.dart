import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show SystemChrome, SystemUiOverlayStyle;
import 'package:kakao_flutter_sdk_user/kakao_flutter_sdk_user.dart';

import 'screens/home_screen.dart';
import 'screens/login_screen.dart';
import 'services/auth_service.dart';

// AUTH-01: 카카오 네이티브 앱 키. 외부 주입 전용 (저장소 미포함).
// 셋업 절차는 docs/SETUP.md 참조.
//   flutter run --dart-define-from-file=.kakao.env
// 또는 인자 직접 지정:
//   flutter run --dart-define=KAKAO_NATIVE_KEY=<키>
const String _kakaoNativeKey = String.fromEnvironment(
  'KAKAO_NATIVE_KEY',
  defaultValue: '',
);

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // 키 미주입 시 즉시 실패시켜 카카오 redirect 깨짐을 빌드 시점에 발견하게 한다.
  // (default 가 비어있으면 manifest scheme 가 'kakao://oauth' 가 되어 redirect 가
  // 안 돌아온다 — 런타임에 원인 추적이 어려움. 빌드 직후 throw 가 가장 명확.)
  assert(
    _kakaoNativeKey.isNotEmpty,
    'KAKAO_NATIVE_KEY 가 비어 있습니다. docs/SETUP.md 의 카카오 셋업을 따르세요.\n'
    '예: flutter run --dart-define-from-file=.kakao.env',
  );

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
