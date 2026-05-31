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
import 'package:flutter/services.dart' show PlatformException;
import 'package:http/http.dart' as http;
import 'package:kakao_flutter_sdk_user/kakao_flutter_sdk_user.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'api_service.dart';

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
  static const String _anonChosenKey = 'auth_anon_chosen';

  // SharedPreferences 접근 비용을 줄이기 위한 메모리 캐시.
  static String? _cachedJwt;
  static AuthUser? _cachedUser;
  static bool _anonymousChosen = false;
  static bool _loadedFromDisk = false;

  // ───────────────────────────────────────────────────────────────────────────
  // 초기 부팅 — SharedPreferences 에서 JWT/프로필 복원.
  // main.dart 에서 runApp 전에 1회 호출.
  // ───────────────────────────────────────────────────────────────────────────
  static Future<void> bootstrap() async {
    if (_loadedFromDisk) return;
    final prefs = await SharedPreferences.getInstance();
    _cachedJwt = prefs.getString(_jwtKey);
    _anonymousChosen = prefs.getBool(_anonChosenKey) ?? false;
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

  /// 로그인 화면을 띄울지 결정. 가입자거나 사용자가 익명 선택을 영구적으로
  /// 표시한 경우 false.
  static bool shouldShowLogin() {
    if (isLoggedIn) return false;
    if (_anonymousChosen) return false;
    return true;
  }

  /// 사용자가 '지금은 익명으로 사용' 을 누른 경우 호출. 다음 실행에 또
  /// 묻지 않도록 영속화. 로그인 메뉴에서 '카카오로 로그인' 을 누르면
  /// 자연스럽게 가입자로 전환되므로 비가역 선택이 아님.
  static Future<void> markAnonymous() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_anonChosenKey, true);
    _anonymousChosen = true;
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
  /// device_uuid 는 본 메서드가 직접 ApiService.deviceUuid() 로 조달한다.
  /// 호출자가 인자로 넘기는 책임을 분산시키면 누락 시 백엔드의
  /// DeviceUUIDMiddleware 가 401 로 잘라내는데, 원인 추적이 어렵다.
  /// (Phase 4 까지는 호출자 책임이었으나 P0 코드 인스펙션에서 내부화)
  ///
  /// 예외:
  ///   - PlatformException(code=CANCELED): 사용자가 로그인 화면 닫음.
  ///   - Exception: 카카오 SDK 또는 백엔드 통신 실패.
  static Future<AuthUser> loginWithKakao() async {
    // 1. 카카오 OAuthToken 획득. talk → web 폴백.
    //
    // 사용자가 talk login 화면에서 '취소' 를 누른 경우 PlatformException
    // (code=CANCELED) 가 발생한다. 이걸 catch 로 잡아 web login 으로 자동
    // 폴백하면 사용자가 명시적으로 취소했는데 카카오 로그인 화면이 또 떠
    // UX 가 어긋난다. CANCELED 는 rethrow 해서 호출자(login_screen)의 catch
    // 가 silent 처리하도록 한다. talk 실패가 진짜 오류(앱 미설치·통신 실패
    // 등) 일 때만 web 폴백.
    OAuthToken token;
    if (await isKakaoTalkInstalled()) {
      try {
        token = await UserApi.instance.loginWithKakaoTalk();
      } on PlatformException catch (e) {
        if (e.code == 'CANCELED' || e.code == 'CANCELLED') {
          rethrow;
        }
        debugPrint('[AuthService] talk login 실패, web 폴백: $e');
        token = await UserApi.instance.loginWithKakaoAccount();
      } catch (e) {
        debugPrint('[AuthService] talk login 실패, web 폴백: $e');
        token = await UserApi.instance.loginWithKakaoAccount();
      }
    } else {
      token = await UserApi.instance.loginWithKakaoAccount();
    }

    // 2. 백엔드와 교환 — kakao access_token 을 서버가 직접 검증해야 신뢰됨.
    //    device_uuid 는 ApiService 가 발급/캐시하므로 직접 조달.
    //    DeviceUUIDMiddleware (NF-30) 가 헤더 누락 시 401 차단.
    final deviceUuid = await ApiService.deviceUuid();
    final uri = Uri.parse('$_baseUrl/auth/kakao');
    final headers = <String, String>{
      'Content-Type': 'application/json; charset=utf-8',
      'X-Device-UUID': deviceUuid,
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
  /// 있음). 로컬 JWT/프로필 폐기 + 익명 선택 플래그도 함께 초기화 — 명시적
  /// 로그아웃은 '익명 사용 의사' 까지 철회한 것으로 본다. 다음 앱 재시작
  /// 시 LoginScreen 이 다시 나타나 명확한 재선택 흐름 제공.
  static Future<void> logout() async {
    try {
      await UserApi.instance.logout();
    } catch (e) {
      debugPrint('[AuthService] 카카오 logout 실패 (무시): $e');
    }
    await clearLocalAuth();
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_anonChosenKey);
    _anonymousChosen = false;
  }

  /// 백엔드가 401 을 돌려보낸 경우 (만료·무효 토큰) UI 에서 호출.
  /// 카카오 SDK 호출 없이 로컬 토큰만 비운다.
  ///
  /// 익명 선택 플래그(anonymous_chosen) 는 의도적으로 유지한다. 만료 토큰
  /// 으로 익명 모드 전환되었을 때 다시 LoginScreen 으로 강제 이동하면
  /// 사용자가 작업 중인 흐름이 끊긴다. 가입자 기능을 다시 쓰고 싶을 때
  /// 명시적으로 로그인 메뉴를 누르도록 안내.
  static Future<void> clearLocalAuth() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_jwtKey);
    await prefs.remove(_userKey);
    _cachedJwt = null;
    _cachedUser = null;
  }
}
