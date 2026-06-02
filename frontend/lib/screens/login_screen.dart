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
      await AuthService.loginWithKakao();
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
    // LoginScreen 이 HomeScreen 우상단 뱃지에서 push 된 경우 → pop 으로 복귀해야
    // 스택에 옛 HomeScreen 이 남아 ← 백 버튼이 생기는 현상을 방지한다.
    // 앱 첫 진입(root)에서 보여진 경우에만 HomeScreen 으로 교체.
    final nav = Navigator.of(context);
    if (nav.canPop()) {
      nav.pop();
    } else {
      nav.pushReplacement(
        MaterialPageRoute(builder: (_) => const HomeScreen()),
      );
    }
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
          padding: const EdgeInsets.fromLTRB(24, 24, 24, 20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const SizedBox(height: 32),
              Center(child: _buildLogo()),
              const SizedBox(height: 20),
              const Text(
                '보안 검증 시스템',
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.w800,
                  color: Color(0xFF111827),
                  letterSpacing: -0.5,
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                '의심스러운 문자를 안전하게 검증해 보세요',
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontSize: 14,
                  color: Color(0xFF6B7280),
                  height: 1.5,
                ),
              ),
              const SizedBox(height: 36),
              _buildBenefitList(),
              const Spacer(),
              _buildKakaoButton(),
              const SizedBox(height: 10),
              _buildAnonymousButton(),
              const SizedBox(height: 14),
              _buildFooterNote(),
            ],
          ),
        ),
      ),
    );
  }

  // 첫 진입에서 앱이 무엇을 해 주는지 즉시 보여 준다 (H1 / H6 / H10).
  // 빈 가운데 공간을 의미 있는 콘텐츠로 채워 레이아웃 균형도 회복.
  Widget _buildBenefitList() {
    return Column(
      children: const [
        _BenefitRow(
          icon: Icons.verified_user_outlined,
          text: '문자·URL 을 다신호로 분석해 위협 판정',
        ),
        SizedBox(height: 14),
        _BenefitRow(
          icon: Icons.shield_moon_outlined,
          text: '의심 사이트는 격리된 가상 환경에서 안전하게 체험',
        ),
        SizedBox(height: 14),
        _BenefitRow(
          icon: Icons.how_to_vote_outlined,
          text: '체험 결과를 다른 사용자와 공유해 신규 위협 발견',
        ),
      ],
    );
  }

  // H3 사용자 제어 / 자유: 비회원 선택이 비가역이 아님을 명시.
  Widget _buildFooterNote() {
    return const Text(
      '비회원으로도 모든 기능을 사용할 수 있어요.\n나중에 언제든 로그인할 수 있습니다.',
      textAlign: TextAlign.center,
      style: TextStyle(
        fontSize: 11.5,
        color: Color(0xFF9CA3AF),
        height: 1.5,
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
      height: 54,
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
            : Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: const [
                  Icon(Icons.chat_bubble_rounded, size: 18),
                  SizedBox(width: 8),
                  Text(
                    '카카오로 시작하기',
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ],
              ),
      ),
    );
  }

  Widget _buildAnonymousButton() {
    return SizedBox(
      width: double.infinity,
      height: 54,
      child: OutlinedButton(
        onPressed: _isLoading ? null : _continueAsAnonymous,
        style: OutlinedButton.styleFrom(
          foregroundColor: const Color(0xFF374151),
          backgroundColor: Colors.white,
          side: const BorderSide(color: Color(0xFFE5E7EB)),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
        child: const Text(
          '비회원으로 시작',
          style: TextStyle(
            fontSize: 15,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
    );
  }
}

// 첫 진입 화면의 가치 제안 한 줄 — 아이콘 + 설명.
class _BenefitRow extends StatelessWidget {
  final IconData icon;
  final String text;
  const _BenefitRow({required this.icon, required this.text});

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Container(
          width: 36,
          height: 36,
          decoration: BoxDecoration(
            color: const Color(0xFFEFF3FE),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(icon, size: 20, color: const Color(0xFF1A56DB)),
        ),
        const SizedBox(width: 14),
        Expanded(
          child: Text(
            text,
            style: const TextStyle(
              fontSize: 13.5,
              color: Color(0xFF374151),
              height: 1.45,
              fontWeight: FontWeight.w500,
            ),
          ),
        ),
      ],
    );
  }
}
