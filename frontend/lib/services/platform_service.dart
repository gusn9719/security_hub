import 'package:flutter/services.dart';

/// Android 네이티브 ↔ Flutter 채널 추상화.
///
/// HomeScreen과 SmsPickerSheet가 MethodChannel / EventChannel 이름 문자열을
/// 직접 알 필요 없도록 정적 메서드로 감싼다.
class PlatformService {
  static const _methodChannel = MethodChannel('com.security_hub/platform');
  static const _eventChannel  = EventChannel('com.security_hub/sms_stream');

  // INP-02: 앱이 공유 인텐트로 시작된 경우 첫 번째 텍스트를 가져온다.
  static Future<String?> getSharedText() async {
    try {
      return await _methodChannel.invokeMethod<String>('getSharedText');
    } catch (_) {
      return null;
    }
  }

  // INP-02: 앱 실행 중 onNewIntent로 들어오는 공유 텍스트 핸들러를 등록한다.
  static void setMethodCallHandler(
    Future<dynamic> Function(MethodCall) handler,
  ) {
    _methodChannel.setMethodCallHandler(handler);
  }

  // INP-04: SMS 받은 문자함에서 최근 메시지 목록을 읽는다. (READ_SMS 필요)
  static Future<List<Map<String, String>>> getSmsMessages() async {
    final raw = await _methodChannel.invokeMethod<List>('getSmsMessages');
    return raw
            ?.map((e) => Map<String, String>.from(e as Map))
            .toList() ??
        [];
  }

  // INP-05: 수신 SMS 실시간 스트림. (RECEIVE_SMS 필요)
  static Stream<Map<String, String>> get incomingSmsStream =>
      _eventChannel
          .receiveBroadcastStream()
          .map((event) => Map<String, String>.from(event as Map));
}
