// =============================================================================
// lib/screens/login_screen.dart
// 역할: 카카오 소셜 로그인 선택 화면.
//
// AUTH-01:
//   - 익명 사용도 동등하게 가능 — '지금은 익명으로 사용' 버튼을 카카오 버튼과
//     같은 시각 비중으로 둔다 (Nielsen #3 사용자 제어 / 자유).
//   - 카카오 SDK 에러는 사용자가 의도적으로 취소했을 수 있어 toast 만, 화면
//     전환 없음. 다른 실패는 안내.
// =============================================================================

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show PlatformException;

import '../services/api_service.dart';
import '../services/auth_service.dart';
import 'home_screen.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  bool _isLoading = false;

  Future<void> _loginWithKakao() async {
    if (_isLoading) return;
    setState(() => _isLoading = true);
    try {
      final deviceUuid = await ApiService.deviceUuid();
      await AuthService.loginWithKakao(deviceUuid: deviceUuid);
      if (!mounted) return;
      _goToHome();
    } on PlatformException catch (e) {
      // 사용자가 카카오 로그인 화면을 닫음 — 조용히 무시.
      if (e.code == 'CANCELED' || e.code == 'CANCELLED') return;
      _showError('카카오 로그인 실패: ${e.message ?? e.code}');
    } catch (e) {
      _showError('로그인에 실패했습니다. 잠시 후 다시 시도해 주세요.');
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  Future<void> _continueAsAnonymous() async {
    // 다음 실행에 또 묻지 않도록 영속화. 사용자가 나중에 우상단 메뉴에서
    // '카카오로 로그인' 을 누르면 자연스럽게 가입자로 전환 — 비가역 아님.
    await AuthService.markAnonymous();
    if (!mounted) return;
    _goToHome();
  }

  void _goToHome() {
    Navigator.of(context).pushReplacement(
      MaterialPageRoute(builder: (_) => const HomeScreen()),
    );
  }

  void _showError(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(msg)),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF8F9FC),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24),
          child: Column(
            children: [
              const Spacer(flex: 2),
              _buildLogo(),
              const SizedBox(height: 24),
              const Text(
                '보안 검증 시스템',
                style: TextStyle(
                  fontSize: 22,
                  fontWeight: FontWeight.w700,
                  color: Color(0xFF111827),
                  letterSpacing: -0.3,
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                '의심스러운 문자를 안전하게 검증해 보세요',
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontSize: 14,
                  color: Color(0xFF6B7280),
                ),
              ),
              const Spacer(flex: 3),
              _buildKakaoButton(),
              const SizedBox(height: 12),
              _buildAnonymousButton(),
              const Spacer(),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildLogo() {
    return Container(
      width: 72,
      height: 72,
      decoration: BoxDecoration(
        color: const Color(0xFF1A56DB),
        borderRadius: BorderRadius.circular(20),
      ),
      child: const Icon(Icons.security_rounded, color: Colors.white, size: 36),
    );
  }

  Widget _buildKakaoButton() {
    return SizedBox(
      width: double.infinity,
      height: 52,
      child: ElevatedButton(
        onPressed: _isLoading ? null : _loginWithKakao,
        style: ElevatedButton.styleFrom(
          backgroundColor: const Color(0xFFFEE500),  // 카카오 공식 노랑
          foregroundColor: const Color(0xFF191919),  // 카카오 공식 글자
          elevation: 0,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
        child: _isLoading
            ? const SizedBox(
                width: 22,
                height: 22,
                child: CircularProgressIndicator(
                  strokeWidth: 2,
                  color: Color(0xFF191919),
                ),
              )
            : const Text(
                '카카오로 시작하기',
                style: TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.w600,
                ),
              ),
      ),
    );
  }

  Widget _buildAnonymousButton() {
    return SizedBox(
      width: double.infinity,
      height: 52,
      child: OutlinedButton(
        onPressed: _isLoading ? null : _continueAsAnonymous,
        style: OutlinedButton.styleFrom(
          foregroundColor: const Color(0xFF374151),
          side: const BorderSide(color: Color(0xFFE5E7EB)),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
        child: const Text(
          '비회원으로 시작',
          style: TextStyle(
            fontSize: 15,
            fontWeight: FontWeight.w500,
          ),
        ),
      ),
    );
  }
}
