// =============================================================================
// lib/services/auth_service.dart
// 역할: 카카오 소셜 로그인 + 백엔드 JWT 교환 + 토큰/프로필 영속화.
//
// AUTH-01 (v0530 신설):
//   - 흐름:
//     1. loginWithKakao() → 카카오 SDK 가 talk/web login 자동 분기
//        → kakao OAuthToken 획득
//     2. 백엔드 POST /auth/kakao 로 access_token 교환
//     3. 응답의 JWT + 프로필을 SharedPreferences 에 영속화
//   - currentUser() 는 캐시된 프로필 반환 (네트워크 호출 없음).
//   - logout() 은 카카오 SDK logout + 로컬 토큰 폐기. 백엔드 호출은 선택적
//     (서버 stateless 라 의미 없음).
// =============================================================================

import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:kakao_flutter_sdk_user/kakao_flutter_sdk_user.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// 가입자 프로필 — 백엔드 /auth/me 응답과 1:1.
@immutable
class AuthUser {
  final int id;
  final String kakaoId;
  final String? nickname;
  final String? email;

  const AuthUser({
    required this.id,
    required this.kakaoId,
    this.nickname,
    this.email,
  });

  factory AuthUser.fromJson(Map<String, dynamic> json) => AuthUser(
        id: json['id'] as int,
        kakaoId: json['kakao_id'] as String,
        nickname: json['nickname'] as String?,
        email: json['email'] as String?,
      );

  Map<String, dynamic> toJson() => {
        'id': id,
        'kakao_id': kakaoId,
        'nickname': nickname,
        'email': email,
      };

  /// 화면 표시용 — 닉네임이 없으면 카카오ID 일부로 폴백.
  String displayName() {
    if (nickname != null && nickname!.isNotEmpty) return nickname!;
    if (kakaoId.length > 4) return '카카오${kakaoId.substring(0, 4)}';
    return '카카오 사용자';
  }
}

class AuthService {
  // ───────────────────────────────────────────────────────────────────────────
  // 서버 주소 — api_service.dart 와 동일 환경변수 사용.
  // ───────────────────────────────────────────────────────────────────────────
  static const String _baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'http://10.0.2.2:8000',
  );

  static const String _jwtKey = 'auth_jwt';
  static const String _userKey = 'auth_user';

  // SharedPreferences 접근 비용을 줄이기 위한 메모리 캐시.
  static String? _cachedJwt;
  static AuthUser? _cachedUser;
  static bool _loadedFromDisk = false;

  // ───────────────────────────────────────────────────────────────────────────
  // 초기 부팅 — SharedPreferences 에서 JWT/프로필 복원.
  // main.dart 에서 runApp 전에 1회 호출.
  // ───────────────────────────────────────────────────────────────────────────
  static Future<void> bootstrap() async {
    if (_loadedFromDisk) return;
    final prefs = await SharedPreferences.getInstance();
    _cachedJwt = prefs.getString(_jwtKey);
    final userJson = prefs.getString(_userKey);
    if (userJson != null) {
      try {
        _cachedUser = AuthUser.fromJson(
          jsonDecode(userJson) as Map<String, dynamic>,
        );
      } catch (e) {
        // 직렬화 형식이 바뀌어 깨진 경우 — 조용히 폐기 후 익명 상태로 시작.
        debugPrint('[AuthService] 캐시된 user 디코딩 실패: $e');
        await prefs.remove(_userKey);
        _cachedUser = null;
      }
    }
    _loadedFromDisk = true;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 동기 getter — UI 가 별도 await 없이 현재 상태를 즉시 읽을 수 있도록.
  // bootstrap() 이후에만 정확한 값. 그 전엔 null.
  // ───────────────────────────────────────────────────────────────────────────
  static String? currentJwt() => _cachedJwt;
  static AuthUser? currentUser() => _cachedUser;
  static bool get isLoggedIn => _cachedJwt != null && _cachedUser != null;

  // ───────────────────────────────────────────────────────────────────────────
  // 로그인 — 카카오 SDK 호출 → 백엔드 교환 → 영속화.
  // ───────────────────────────────────────────────────────────────────────────

  /// 카카오 로그인을 수행하고 백엔드 JWT 를 받는다.
  ///
  /// 카카오톡 앱이 설치돼 있으면 talk login (앱 전환), 없으면 web login
  /// (Custom Tab). SDK 가 자동 분기한다.
  ///
  /// 예외:
  ///   - PlatformException(code=CANCELED): 사용자가 로그인 화면 닫음.
  ///   - Exception: 카카오 SDK 또는 백엔드 통신 실패.
  static Future<AuthUser> loginWithKakao({String? deviceUuid}) async {
    // 1. 카카오 OAuthToken 획득. talk → web 폴백.
    OAuthToken token;
    if (await isKakaoTalkInstalled()) {
      try {
        token = await UserApi.instance.loginWithKakaoTalk();
      } catch (e) {
        debugPrint('[AuthService] talk login 실패, web 폴백: $e');
        token = await UserApi.instance.loginWithKakaoAccount();
      }
    } else {
      token = await UserApi.instance.loginWithKakaoAccount();
    }

    // 2. 백엔드와 교환 — kakao access_token 을 서버가 직접 검증해야 신뢰됨.
    final uri = Uri.parse('$_baseUrl/auth/kakao');
    final headers = <String, String>{
      'Content-Type': 'application/json; charset=utf-8',
      if (deviceUuid != null) 'X-Device-UUID': deviceUuid,
    };
    final body = jsonEncode({'access_token': token.accessToken});

    final http.Response resp;
    try {
      resp = await http
          .post(uri, headers: headers, body: body)
          .timeout(const Duration(seconds: 15));
    } on SocketException {
      throw Exception('서버에 연결할 수 없습니다. 네트워크 연결을 확인해 주세요.');
    }

    if (resp.statusCode != 200) {
      throw Exception('로그인 서버 오류 (${resp.statusCode})');
    }

    final data = jsonDecode(utf8.decode(resp.bodyBytes)) as Map<String, dynamic>;
    final jwt = data['access_token'] as String;
    final user = AuthUser.fromJson(data['user'] as Map<String, dynamic>);

    // 3. 영속화 + 메모리 캐시 갱신.
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_jwtKey, jwt);
    await prefs.setString(_userKey, jsonEncode(user.toJson()));
    _cachedJwt = jwt;
    _cachedUser = user;
    _loadedFromDisk = true;

    return user;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 로그아웃 — 로컬 폐기 + 카카오 SDK logout.
  // ───────────────────────────────────────────────────────────────────────────

  /// 클라이언트 측 로그아웃. 백엔드는 stateless JWT 라 별도 호출 의미 없음.
  ///
  /// 카카오 SDK logout 은 실패해도 무시한다 (이미 만료된 카카오 토큰일 수
  /// 있음). 로컬 JWT/프로필 폐기가 본질.
  static Future<void> logout() async {
    try {
      await UserApi.instance.logout();
    } catch (e) {
      debugPrint('[AuthService] 카카오 logout 실패 (무시): $e');
    }
    await clearLocalAuth();
  }

  /// 백엔드가 401 을 돌려보낸 경우 (만료·무효 토큰) UI 에서 호출.
  /// 카카오 SDK 호출 없이 로컬 토큰만 비운다.
  static Future<void> clearLocalAuth() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_jwtKey);
    await prefs.remove(_userKey);
    _cachedJwt = null;
    _cachedUser = null;
  }
}
