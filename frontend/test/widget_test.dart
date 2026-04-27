// 앱 전체 smoke test — HomeScreen이 오류 없이 렌더링되는지 확인
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:security_hub/main.dart';

void main() {
  setUp(() {
    // 네이티브 MethodChannel / EventChannel mock
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
      const MethodChannel('com.security_hub/platform'),
      (_) async => null,
    );
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockStreamHandler(
      const EventChannel('com.security_hub/sms_stream'),
      null,
    );
  });

  testWidgets('앱 smoke test — HomeScreen이 예외 없이 렌더링된다', (tester) async {
    await tester.pumpWidget(const MyApp());
    await tester.pump();

    expect(find.text('보안 검증 시스템'), findsOneWidget);
    expect(find.text('분석하기'), findsOneWidget);
  });
}
