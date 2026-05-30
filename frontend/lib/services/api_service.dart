// =============================================================================
// lib/services/api_service.dart
// 역할: FastAPI 백엔드와의 HTTP 통신을 담당하는 서비스 레이어.
// 책임 분리 원칙: 네트워크 통신 로직을 UI(HomeScreen)로부터 완전히 분리한다.
// NF-30: 모든 요청에 X-Device-UUID 헤더를 포함한다.
// =============================================================================

import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:uuid/uuid.dart';
import '../models/analysis_result.dart';

class ApiService {
  // -------------------------------------------------------------------------
  // 서버 주소 상수
  // 빌드/실행 시 --dart-define=API_BASE_URL=https://... 로 주입한다.
  //
  // 로컬 에뮬레이터 (기본값):
  //   flutter run
  // 프로덕션 APK:
  //   flutter build apk --dart-define=API_BASE_URL=https://api.securityhubserver.cloud
  // -------------------------------------------------------------------------
  static const String _baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'http://10.0.2.2:8000',
  );

  static const String _uuidKey = 'device_uuid';
  static String? _cachedUuid;

  /// SharedPreferences에 저장된 device_uuid를 반환한다.
  /// 없으면 UUID v4를 생성 후 저장한다. 앱 재설치 전까지 동일 UUID 유지.
  static Future<String> _getOrCreateDeviceUUID() async {
    if (_cachedUuid != null) return _cachedUuid!;
    final prefs = await SharedPreferences.getInstance();
    var id = prefs.getString(_uuidKey);
    if (id == null) {
      id = const Uuid().v4();
      await prefs.setString(_uuidKey, id);
    }
    _cachedUuid = id;
    return id;
  }

  /// 모든 요청에 공통으로 주입되는 헤더를 반환한다.
  static Future<Map<String, String>> _headers({bool json = true}) async {
    final uuid = await _getOrCreateDeviceUUID();
    return {
      if (json) 'Content-Type': 'application/json; charset=utf-8',
      'X-Device-UUID': uuid,
    };
  }

  /// 피싱 의심 텍스트를 백엔드로 전송하고 분석 결과를 반환한다.
  ///
  /// [text]: 사용자가 입력한 의심 문자/URL 원문
  /// 반환값: [AnalysisResult] — 위험 상태, 제목, 설명, 액션 레이블
  /// 예외: 네트워크 오류 또는 서버 오류 시 [Exception] throw
  static Future<AnalysisResult> analyzeText(String text) async {
    final uri = Uri.parse('$_baseUrl/analyze');
    debugPrint('[ApiService] POST $uri');

    try {
      final response = await http.post(
        uri,
        headers: await _headers(),
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
    } on SocketException catch (e) {
      debugPrint('[ApiService] SocketException: $e');
      throw Exception('서버에 연결할 수 없습니다. 네트워크 연결을 확인해 주세요.');
    } on HandshakeException catch (e) {
      debugPrint('[ApiService] SSL HandshakeException: $e');
      throw Exception('SSL 연결 오류가 발생했습니다. ($e)');
    } catch (e) {
      debugPrint('[ApiService] 알 수 없는 오류: ${e.runtimeType} $e');
      rethrow;
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
        headers: await _headers(),
        body: jsonEncode({'url': url}),
      ).timeout(
        const Duration(seconds: 60),
        onTimeout: () => throw Exception('분석이 너무 오래 걸려요. 잠시 후 다시 시도해 주세요.'),
      );

      if (response.statusCode == 200) {
        return jsonDecode(utf8.decode(response.bodyBytes)) as Map<String, dynamic>;
      } else {
        throw Exception('분석 서버에 일시적인 문제가 생겼어요 (${response.statusCode})');
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
        headers: await _headers(),
        body: jsonEncode({'url': url}),
      ).timeout(
        const Duration(seconds: 120),
        onTimeout: () => throw Exception(
          'AI 분석이 너무 오래 걸려요. 잠시 후 다시 시도해 주세요.',
        ),
      );

      if (response.statusCode == 200) {
        return jsonDecode(utf8.decode(response.bodyBytes)) as Map<String, dynamic>;
      } else {
        throw Exception('분석 서버에 일시적인 문제가 생겼어요 (${response.statusCode})');
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
        headers: await _headers(),
        body: jsonEncode({
          'url': url,
          'screen_width': screenWidth,
          'screen_height': screenHeight,
        }),
      ).timeout(
        const Duration(seconds: 90),
        onTimeout: () => throw Exception('화면 준비가 너무 오래 걸려요. 잠시 후 다시 시도해 주세요.'),
      );

      if (response.statusCode == 200) {
        return jsonDecode(utf8.decode(response.bodyBytes)) as Map<String, dynamic>;
      } else if (response.statusCode == 503) {
        throw Exception('서버가 잠시 점검 중이에요. 잠시 후 다시 시도해 주세요.');
      } else {
        throw Exception('서버 오류 (${response.statusCode}): ${response.body}');
      }
    } on SocketException {
      throw Exception('서버에 연결할 수 없습니다. 네트워크 연결을 확인해 주세요.');
    }
  }

  // ---------------------------------------------------------------------------
  // Sprint 7-A: 투표 API (/sandbox/votes)
  // ---------------------------------------------------------------------------

  /// 7-A 직접 탐방 세션 종료 후 사용자 피드백 투표를 제출한다.
  ///
  /// [url]:       투표 대상 URL
  /// [sessionId]: 탐방 세션 ID (container_id) — 세션당 1회만 허용
  /// [vote]:      "safe" | "danger" | "spam" | "unsure"
  /// 반환값: {"success": bool, "message": str}
  /// 실패 시 예외를 throw하지 않고 success=false를 반환한다.
  static Future<Map<String, dynamic>> submitVote(
    String url,
    String sessionId,
    String vote,
  ) async {
    final uri = Uri.parse('$_baseUrl/sandbox/votes');
    try {
      final response = await http.post(
        uri,
        headers: await _headers(),
        body: jsonEncode({'url': url, 'session_id': sessionId, 'vote': vote}),
      ).timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        return jsonDecode(utf8.decode(response.bodyBytes)) as Map<String, dynamic>;
      }
      return {'success': false, 'message': '서버 오류 (${response.statusCode})'};
    } catch (e) {
      debugPrint('[ApiService] submitVote 실패 (무시): $e');
      return {'success': false, 'message': e.toString()};
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
      final h = await _headers(json: false);
      await http.delete(uri, headers: h).timeout(const Duration(seconds: 10));
    } catch (e) {
      // 5분 타임아웃으로 자동 정리되므로 dispose 실패는 조용히 무시
      debugPrint('[ApiService] terminateBrowseSession 실패 (무시): $e');
    }
  }
}
