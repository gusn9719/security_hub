// =============================================================================
// lib/services/api_service.dart
// 역할: FastAPI 백엔드와의 HTTP 통신을 담당하는 서비스 레이어.
// 책임 분리 원칙: 네트워크 통신 로직을 UI(HomeScreen)로부터 완전히 분리한다.
// =============================================================================

import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import '../models/analysis_result.dart';

class ApiService {
  // -------------------------------------------------------------------------
  // 서버 주소 상수
  // Android 에뮬레이터에서 호스트 PC localhost는 10.0.2.2로 접근한다.
  // 실기기 테스트 시: 같은 와이파이의 PC IP로 변경 (예: http://192.168.0.x:8000)
  // TODO: 배포 시 실제 서버 URL로 교체
  // -------------------------------------------------------------------------
  static const String _baseUrl = 'http://10.0.2.2:8000';

  /// 피싱 의심 텍스트를 백엔드로 전송하고 분석 결과를 반환한다.
  ///
  /// [text]: 사용자가 입력한 의심 문자/URL 원문
  /// 반환값: [AnalysisResult] — 위험 상태, 제목, 설명, 액션 레이블
  /// 예외: 네트워크 오류 또는 서버 오류 시 [Exception] throw
  static Future<AnalysisResult> analyzeText(String text) async {
    final uri = Uri.parse('$_baseUrl/analyze');

    try {
      final response = await http.post(
        uri,
        headers: {'Content-Type': 'application/json; charset=utf-8'},
        body: jsonEncode({'text': text}),
      ).timeout(
        const Duration(seconds: 30),
        onTimeout: () => throw Exception('서버 응답 시간이 초과되었습니다. 잠시 후 다시 시도해 주세요.'),
      );

      if (response.statusCode == 200) {
        final data = jsonDecode(utf8.decode(response.bodyBytes));
        return AnalysisResult.fromJson(data);
      } else {
        throw Exception('분석 서버 오류 (${response.statusCode})');
      }
    } on SocketException {
      throw Exception('서버에 연결할 수 없습니다. 네트워크 연결을 확인해 주세요.');
    }
  }

  /// URL을 백엔드 Browserless 샌드박스에서 분석하고 결과를 반환한다.
  ///
  /// [url]: 샌드박스에서 실행할 대상 URL
  /// 반환값: findings, screenshot_initial, screenshot_after3s 등을 담은 Map
  /// 예외: 네트워크 오류 또는 서버 오류 시 [Exception] throw
  static Future<Map<String, dynamic>> startSandbox(String url) async {
    final uri = Uri.parse('$_baseUrl/sandbox/run');

    try {
      final response = await http.post(
        uri,
        headers: {'Content-Type': 'application/json; charset=utf-8'},
        body: jsonEncode({'url': url}),
      ).timeout(
        const Duration(seconds: 60),
        onTimeout: () => throw Exception('샌드박스 응답 시간이 초과되었습니다. (컨테이너 생성 포함 60초)'),
      );

      if (response.statusCode == 200) {
        return jsonDecode(utf8.decode(response.bodyBytes)) as Map<String, dynamic>;
      } else {
        throw Exception('샌드박스 서버 오류 (${response.statusCode})');
      }
    } on SocketException {
      throw Exception('서버에 연결할 수 없습니다. 네트워크 연결을 확인해 주세요.');
    }
  }
}
