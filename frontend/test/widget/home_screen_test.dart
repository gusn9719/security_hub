import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:security_hub/screens/home_screen.dart';

// MethodChannel + EventChannel을 테스트 환경에서 mock으로 처리
void _setupMockChannels() {
  TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
      .setMockMethodCallHandler(
    const MethodChannel('com.security_hub/platform'),
    (call) async => null, // getSharedText → null 반환 (공유 텍스트 없음)
  );

  // EventChannel은 stream handler가 없으면 아무것도 안 보내도 됨
  TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
      .setMockStreamHandler(
    const EventChannel('com.security_hub/sms_stream'),
    null,
  );
}

Widget _buildTestApp() => const MaterialApp(home: HomeScreen());

void main() {
  setUp(_setupMockChannels);

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
      const MethodChannel('com.security_hub/platform'),
      null,
    );
  });

  group('HomeScreen - 기본 UI 렌더링', () {
    testWidgets('앱바에 "보안 검증 시스템" 타이틀이 표시된다', (tester) async {
      await tester.pumpWidget(_buildTestApp());
      await tester.pump();
      expect(find.text('보안 검증 시스템'), findsOneWidget);
    });

    testWidgets('"문자 내용 입력" 섹션 레이블이 있다', (tester) async {
      await tester.pumpWidget(_buildTestApp());
      await tester.pump();
      expect(find.text('문자 내용 입력'), findsOneWidget);
    });

    testWidgets('"분석하기" 버튼이 있다', (tester) async {
      await tester.pumpWidget(_buildTestApp());
      await tester.pump();
      expect(find.text('분석하기'), findsOneWidget);
    });

    testWidgets('"클립보드" 퀵칩이 있다', (tester) async {
      await tester.pumpWidget(_buildTestApp());
      await tester.pump();
      expect(find.text('클립보드'), findsOneWidget);
    });

    testWidgets('"문자 불러오기" 퀵칩이 있다', (tester) async {
      await tester.pumpWidget(_buildTestApp());
      await tester.pump();
      expect(find.text('문자 불러오기'), findsOneWidget);
    });

    testWidgets('초기 상태에서 결과 플레이스홀더가 표시된다', (tester) async {
      await tester.pumpWidget(_buildTestApp());
      await tester.pump();
      expect(find.text('분석 결과가 여기에 표시됩니다'), findsOneWidget);
    });
  });

  group('HomeScreen - 입력 유효성 검사', () {
    testWidgets('빈 입력으로 분석하기 누르면 SnackBar가 표시된다', (tester) async {
      await tester.pumpWidget(_buildTestApp());
      await tester.pump();

      await tester.tap(find.text('분석하기'));
      await tester.pump();

      expect(find.text('분석할 문자 내용을 먼저 입력해주세요.'), findsOneWidget);
    });

    testWidgets('TextField에 텍스트 입력이 가능하다', (tester) async {
      await tester.pumpWidget(_buildTestApp());
      await tester.pump();

      await tester.enterText(find.byType(TextField), 'https://evil.com/phishing');
      expect(find.text('https://evil.com/phishing'), findsOneWidget);
    });
  });

  group('HomeScreen - 클립보드 퀵칩', () {
    testWidgets('클립보드 퀵칩 탭 시 클립보드를 읽으려 시도한다', (tester) async {
      // 클립보드에 텍스트 설정
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        SystemChannels.platform,
        (call) async {
          if (call.method == 'Clipboard.getData') {
            return {'text': 'https://test.com'};
          }
          return null;
        },
      );

      await tester.pumpWidget(_buildTestApp());
      await tester.pump();

      await tester.tap(find.text('클립보드'));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 100));

      // 클립보드에서 내용이 텍스트 필드에 채워졌는지 확인
      expect(find.text('https://test.com'), findsOneWidget);

      // 복구
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        SystemChannels.platform,
        null,
      );
    });
  });
}
