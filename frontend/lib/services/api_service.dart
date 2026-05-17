// =============================================================================
// lib/services/api_service.dart
// 역할: FastAPI 백엔드와의 HTTP 통신을 담당하는 서비스 레이어.
// 책임 분리 원칙: 네트워크 통신 로직을 UI(HomeScreen)로부터 완전히 분리한다.
// =============================================================================

import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import '../models/analysis_result.dart';

class ApiService {
  // -------------------------------------------------------------------------
  // 서버 주소 상수
  // Android 에뮬레이터에서 호스트 PC localhost는 10.0.2.2로 접근한다.
  // 실기기 테스트 시: 같은 와이파이의 PC IP로 변경 (예: http://192.168.0.x:8000)
  // TODO: 배포 시 실제 서버 URL로 교체
  // -------------------------------------------------------------------------
  // static const String _baseUrl = 'http://172.31.57.14:8000';
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

  // ---------------------------------------------------------------------------
  // Sprint 7-B: AI 자동탐지 API (/sandbox/auto-test)
  // ---------------------------------------------------------------------------

  /// URL을 격리 컨테이너에서 AI가 자동 분석하고 결과를 반환한다.
  ///
  /// 가짜 개인정보를 폼에 주입해 피싱 폼 여부를 탐지한다.
  /// 결과는 24시간 캐시된다.
  ///
  /// [url]: 분석할 대상 URL
  /// 반환값: session_id, sandbox_score, findings, summary, screenshots,
  ///         final_url, redirect_count, error, cached 등을 담은 Map
  /// 예외: 네트워크 오류 또는 서버 오류 시 [Exception] throw
  static Future<Map<String, dynamic>> startAutoTest(String url) async {
    final uri = Uri.parse('$_baseUrl/sandbox/auto-test');

    try {
      final response = await http.post(
        uri,
        headers: {'Content-Type': 'application/json; charset=utf-8'},
        body: jsonEncode({'url': url}),
      ).timeout(
        const Duration(seconds: 120),
        onTimeout: () => throw Exception(
          'AI 자동 분석 응답 시간이 초과되었습니다. '
          '(컨테이너 기동 포함 최대 120초)',
        ),
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

  // ---------------------------------------------------------------------------
  // Sprint 7-A: kasmweb/chromium 직접 탐방 API
  // ---------------------------------------------------------------------------

  /// kasmweb/chromium 컨테이너를 생성하고 noVNC 세션 정보를 반환한다.
  ///
  /// [url]: Chromium이 처음 열 대상 URL
  /// 반환값: {"container_id": str, "novnc_url": str, "network_name": str}
  /// 예외: 네트워크 오류, 서버 오류(4xx/5xx), Docker 미실행(503) 시 [Exception] throw
  static Future<Map<String, dynamic>> startBrowseSessionV2(
    String url, {
    int screenWidth = 1080,
    int screenHeight = 1920,
  }) async {
    final uri = Uri.parse('$_baseUrl/sandbox/browse');

    try {
      final response = await http.post(
        uri,
        headers: {'Content-Type': 'application/json; charset=utf-8'},
        body: jsonEncode({
          'url': url,
          'screen_width': screenWidth,
          'screen_height': screenHeight,
        }),
      ).timeout(
        const Duration(seconds: 90),
        onTimeout: () => throw Exception('컨테이너 시작 응답 시간이 초과되었습니다. (최대 90초)'),
      );

      if (response.statusCode == 200) {
        return jsonDecode(utf8.decode(response.bodyBytes)) as Map<String, dynamic>;
      } else if (response.statusCode == 503) {
        throw Exception('Docker가 실행 중이지 않습니다. Docker Desktop을 시작한 후 다시 시도해 주세요.');
      } else {
        throw Exception('서버 오류 (${response.statusCode}): ${response.body}');
      }
    } on SocketException {
      throw Exception('서버에 연결할 수 없습니다. 네트워크 연결을 확인해 주세요.');
    }
  }

  /// container_id의 kasmweb/chromium 컨테이너를 종료하고 네트워크를 삭제한다.
  ///
  /// [containerId]: startBrowseSessionV2()가 반환한 컨테이너 ID
  /// [networkName]: startBrowseSessionV2()가 반환한 네트워크 이름
  /// 실패해도 예외를 throw하지 않는다 (dispose fire-and-forget 용도).
  static Future<void> terminateBrowseSession(
    String containerId,
    String networkName,
  ) async {
    final uri = Uri.parse(
      '$_baseUrl/sandbox/browse/$containerId?network_name=${Uri.encodeComponent(networkName)}',
    );

    try {
      await http.delete(uri).timeout(const Duration(seconds: 10));
    } catch (e) {
      // 5분 타임아웃으로 자동 정리되므로 dispose 실패는 조용히 무시
      debugPrint('[ApiService] terminateBrowseSession 실패 (무시): $e');
    }
  }
}
