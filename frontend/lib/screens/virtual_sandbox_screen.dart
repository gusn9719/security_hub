// =============================================================================
// lib/screens/virtual_sandbox_screen.dart
// 역할: 7-A 직접 탐방 / 7-B AI 자동탐지 모드 선택 및 결과 표시.
//       AI 자동탐지는 POST /sandbox/auto-test 를 호출하며
//       가짜 개인정보 주입 후 피싱 폼 여부를 탐지한다.
//
// 변경 이력:
//   - Sprint 7:   최초 작성 (/sandbox/run 기반)
//   - Sprint 7-B: /sandbox/auto-test 연동, sandbox_score·summary·screenshots 표시,
//                 스크린샷 탭→전체화면(InteractiveViewer 핀치줌) 추가.
// =============================================================================

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../services/api_service.dart';
import 'sandbox_browse_screen.dart';

class VirtualSandboxScreen extends StatefulWidget {
  final String url;

  const VirtualSandboxScreen({super.key, required this.url});

  @override
  State<VirtualSandboxScreen> createState() => _VirtualSandboxScreenState();
}

class _VirtualSandboxScreenState extends State<VirtualSandboxScreen> {
  bool _isLoading = true;
  bool _modeSelected = false;
  bool _isBrowseStarting = false;
  String? _error;

  // 7-B 자동탐지 결과 상태
  List<String> _findings = [];
  List<Uint8List> _screenshots = []; // 최대 3장
  int _sandboxScore = 0;
  String _summary = '';
  String _finalUrl = '';
  int _redirectCount = 0;
  bool _cached = false;

  // 스크린샷 순서별 레이블 (최대 3장)
  static const _screenshotLabels = [
    '① 접속 직후',
    '② 가짜 정보 주입 후',
    '③ 제출 시도 후',
  ];

  @override
  void initState() {
    super.initState();
    // 모드 선택 UI를 먼저 보여주기 위해 자동 실행하지 않는다.
  }

  // ── 7-A 직접 탐방 ────────────────────────────────────────────────────────

  Future<void> _startDirectBrowse() async {
    setState(() => _isBrowseStarting = true);
    try {
      // WebView DNS 캐시 초기화 — 이전 실패한 조회 결과가 캐시돼
      // ERR_NAME_NOT_RESOLVED를 유발하는 문제 방지
      await InAppWebViewController.clearAllCache();

      final mq = MediaQuery.of(context);
      // 논리 픽셀 사용: 컨테이너 내부는 DPR 없이 1px=1CSS px
      final screenWidth = mq.size.width.toInt();
      final screenHeight = mq.size.height.toInt();
      final result = await ApiService.startBrowseSessionV2(
        widget.url,
        screenWidth: screenWidth,
        screenHeight: screenHeight,
      );
      if (!mounted) return;
      Navigator.push(
        context,
        MaterialPageRoute(
          builder: (_) => SandboxBrowseScreen(
            url: widget.url,
            novncUrl: result['novnc_url'] as String,
            containerId: result['container_id'] as String,
            networkName: result['network_name'] as String,
          ),
        ),
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(e.toString().replaceFirst('Exception: ', '')),
          backgroundColor: const Color(0xFFDC2626),
          behavior: SnackBarBehavior.floating,
        ),
      );
    } finally {
      if (mounted) setState(() => _isBrowseStarting = false);
    }
  }

  // ── 7-B AI 자동탐지 ──────────────────────────────────────────────────────

  Future<void> _runAutoTest() async {
    try {
      final result = await ApiService.startAutoTest(widget.url);
      if (!mounted) return;

      // base64 → Uint8List 디코딩 (디코딩 실패 항목은 건너뜀)
      final rawShots = List<String>.from(result['screenshots'] ?? []);
      final parsedShots = <Uint8List>[];
      for (final s in rawShots) {
        try {
          parsedShots.add(base64Decode(s));
        } catch (_) {}
      }

      setState(() {
        _findings = List<String>.from(result['findings'] ?? []);
        _screenshots = parsedShots;
        _sandboxScore = (result['sandbox_score'] as int?) ?? 0;
        _summary = (result['summary'] as String?) ?? '';
        _finalUrl = (result['final_url'] as String?) ?? widget.url;
        _redirectCount = (result['redirect_count'] as int?) ?? 0;
        _error = result['error'] as String?;
        _cached = (result['cached'] as bool?) ?? false;
        _isLoading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.toString().replaceFirst('Exception: ', '');
        _isLoading = false;
      });
    }
  }

  // ── 전체화면 스크린샷 뷰어 ────────────────────────────────────────────────

  /// 스크린샷을 전체화면으로 열고 InteractiveViewer로 핀치줌을 지원한다.
  void _openFullScreen(Uint8List bytes, String title) {
    Navigator.push(
      context,
      MaterialPageRoute(
        fullscreenDialog: true,
        builder: (_) => Scaffold(
          backgroundColor: Colors.black,
          appBar: AppBar(
            backgroundColor: Colors.black,
            foregroundColor: Colors.white,
            title: Text(
              title,
              style: const TextStyle(fontSize: 14, color: Colors.white),
            ),
            leading: const BackButton(color: Colors.white),
          ),
          body: Center(
            child: InteractiveViewer(
              minScale: 0.5,
              maxScale: 6.0,
              child: Image.memory(
                bytes,
                fit: BoxFit.contain,
                errorBuilder: (_, __, ___) => const Icon(
                  Icons.broken_image_outlined,
                  color: Colors.white38,
                  size: 64,
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  // ── build ─────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF111827),
      appBar: AppBar(
        backgroundColor: const Color(0xFF1F2937),
        foregroundColor: Colors.white,
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              '가상 샌드박스 분석',
              style: TextStyle(
                fontSize: 14,
                fontWeight: FontWeight.w700,
                color: Colors.white,
              ),
            ),
            Text(
              widget.url,
              style: const TextStyle(fontSize: 11, color: Color(0xFF9CA3AF)),
              overflow: TextOverflow.ellipsis,
            ),
          ],
        ),
      ),
      body: Column(
        children: [
          _buildWarningBanner(),
          Expanded(
            child: _modeSelected
                ? (_isLoading ? _buildLoadingView() : _buildResultView())
                : _buildModeSelectionView(),
          ),
        ],
      ),
    );
  }

  // ── 모드 선택 화면 ────────────────────────────────────────────────────────

  Widget _buildModeSelectionView() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(28),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.security_rounded, color: Color(0xFF60A5FA), size: 52),
            const SizedBox(height: 20),
            const Text(
              '분석 모드를 선택하세요',
              style: TextStyle(
                color: Colors.white,
                fontSize: 18,
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              widget.url,
              style: const TextStyle(color: Color(0xFF9CA3AF), fontSize: 12),
              overflow: TextOverflow.ellipsis,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 36),
            // 직접 탐방 버튼
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: _isBrowseStarting ? null : _startDirectBrowse,
                icon: _isBrowseStarting
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(
                          color: Colors.white,
                          strokeWidth: 2,
                        ),
                      )
                    : const Icon(Icons.open_in_browser_rounded),
                label: Padding(
                  padding: const EdgeInsets.symmetric(vertical: 4),
                  child: Column(
                    children: [
                      Text(
                        _isBrowseStarting ? '컨테이너 생성 중...' : '직접 탐방',
                        style: const TextStyle(
                          fontSize: 15,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 2),
                      const Text(
                        '격리 컨테이너 Chromium을 직접 조작',
                        style: TextStyle(fontSize: 11),
                      ),
                    ],
                  ),
                ),
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF2563EB),
                  foregroundColor: Colors.white,
                  disabledBackgroundColor: const Color(0xFF1D4ED8),
                  disabledForegroundColor: Colors.white70,
                  padding: const EdgeInsets.symmetric(vertical: 14, horizontal: 20),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
              ),
            ),
            const SizedBox(height: 14),
            // AI 자동탐지 버튼
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: () {
                  setState(() => _modeSelected = true);
                  _runAutoTest();
                },
                icon: const Icon(Icons.smart_toy_outlined),
                label: const Padding(
                  padding: EdgeInsets.symmetric(vertical: 4),
                  child: Column(
                    children: [
                      Text(
                        'AI 자동 분석',
                        style: TextStyle(fontSize: 15, fontWeight: FontWeight.w700),
                      ),
                      SizedBox(height: 2),
                      Text(
                        '가짜 정보 주입으로 피싱 폼 자동 탐지',
                        style: TextStyle(fontSize: 11),
                      ),
                    ],
                  ),
                ),
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF374151),
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(vertical: 14, horizontal: 20),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ── 공통 위젯 ─────────────────────────────────────────────────────────────

  Widget _buildWarningBanner() {
    return Container(
      width: double.infinity,
      color: const Color(0xFFDC2626),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      child: const Row(
        children: [
          Icon(Icons.security_rounded, color: Colors.white, size: 18),
          SizedBox(width: 8),
          Expanded(
            child: Text(
              '격리된 서버 컨테이너에서 실행 중입니다. 실제 기기에는 영향이 없습니다.',
              style: TextStyle(
                color: Colors.white,
                fontSize: 12,
                fontWeight: FontWeight.w600,
                height: 1.4,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildLoadingView() {
    return const Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          CircularProgressIndicator(color: Color(0xFF60A5FA)),
          SizedBox(height: 20),
          Text(
            'AI 자동 분석 중...',
            style: TextStyle(color: Color(0xFF9CA3AF), fontSize: 14),
          ),
          SizedBox(height: 6),
          Text(
            'Docker 컨테이너 기동 및 피싱 폼 탐지에 최대 2분이 소요됩니다.',
            style: TextStyle(color: Color(0xFF6B7280), fontSize: 12),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  // ── 결과 화면 ─────────────────────────────────────────────────────────────

  Widget _buildResultView() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (_error != null) ...[
            _buildErrorCard(),
            const SizedBox(height: 12),
          ],
          _buildScoreCard(),
          if (_summary.isNotEmpty && _summary != '탐지된 위험 요소 없음') ...[
            const SizedBox(height: 12),
            _buildSummaryCard(),
          ],
          if (_findings.isNotEmpty) ...[
            const SizedBox(height: 12),
            _buildFindingsCard(),
          ],
          // 스크린샷 목록 (최대 3장)
          ..._screenshots.asMap().entries.map((entry) {
            final idx = entry.key;
            final label = idx < _screenshotLabels.length
                ? _screenshotLabels[idx]
                : '스크린샷 ${idx + 1}';
            return Padding(
              padding: const EdgeInsets.only(top: 16),
              child: _buildScreenshotCard(label, entry.value),
            );
          }),
          const SizedBox(height: 8),
        ],
      ),
    );
  }

  // ── 결과 카드 위젯 ────────────────────────────────────────────────────────

  Widget _buildErrorCard() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: const Color(0xFF7F1D1D),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFFDC2626)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Icon(Icons.error_outline, color: Color(0xFFFCA5A5), size: 18),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              _error!,
              style: const TextStyle(
                color: Color(0xFFFCA5A5),
                fontSize: 13,
                height: 1.5,
              ),
            ),
          ),
        ],
      ),
    );
  }

  /// AI 위협 점수 카드 (0~29 이상없음 · 30~59 주의 · 60+ 위험)
  Widget _buildScoreCard() {
    final Color scoreColor;
    final String scoreLabel;
    final IconData scoreIcon;

    if (_sandboxScore >= 60) {
      scoreColor = const Color(0xFFDC2626);
      scoreLabel = '위험';
      scoreIcon = Icons.dangerous_rounded;
    } else if (_sandboxScore >= 30) {
      scoreColor = const Color(0xFFD97706);
      scoreLabel = '주의';
      scoreIcon = Icons.warning_amber_rounded;
    } else {
      scoreColor = const Color(0xFF10B981);
      scoreLabel = '이상없음';
      scoreIcon = Icons.check_circle_rounded;
    }

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF1F2937),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: scoreColor.withOpacity(0.4)),
      ),
      child: Row(
        children: [
          // 점수 원형 뱃지
          Container(
            width: 68,
            height: 68,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: scoreColor.withOpacity(0.15),
              border: Border.all(color: scoreColor, width: 2),
            ),
            child: Center(
              child: Text(
                '$_sandboxScore',
                style: TextStyle(
                  color: scoreColor,
                  fontSize: 24,
                  fontWeight: FontWeight.w900,
                ),
              ),
            ),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(scoreIcon, color: scoreColor, size: 16),
                    const SizedBox(width: 6),
                    Text(
                      'AI 위협 점수: $scoreLabel',
                      style: TextStyle(
                        color: scoreColor,
                        fontSize: 15,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ],
                ),
                if (_redirectCount > 0) ...[
                  const SizedBox(height: 5),
                  Text(
                    '리다이렉트 $_redirectCount회 감지',
                    style: const TextStyle(
                      color: Color(0xFF9CA3AF),
                      fontSize: 12,
                    ),
                  ),
                ],
                if (_finalUrl.isNotEmpty && _finalUrl != widget.url) ...[
                  const SizedBox(height: 5),
                  Text(
                    '최종 URL: $_finalUrl',
                    style: const TextStyle(
                      color: Color(0xFF9CA3AF),
                      fontSize: 11,
                    ),
                    overflow: TextOverflow.ellipsis,
                    maxLines: 2,
                  ),
                ],
                if (_cached) ...[
                  const SizedBox(height: 5),
                  const Row(
                    children: [
                      Icon(Icons.cached_rounded, color: Color(0xFF6B7280), size: 12),
                      SizedBox(width: 4),
                      Text(
                        '24h 캐시된 결과',
                        style: TextStyle(color: Color(0xFF6B7280), fontSize: 11),
                      ),
                    ],
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }

  /// Gemini AI 요약 카드 (summary가 없거나 기본값이면 표시하지 않음)
  Widget _buildSummaryCard() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: const Color(0xFF1E1B4B),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF4338CA).withOpacity(0.45)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.auto_awesome_rounded, color: Color(0xFF818CF8), size: 15),
              SizedBox(width: 6),
              Text(
                'AI 분석 요약',
                style: TextStyle(
                  color: Color(0xFF818CF8),
                  fontSize: 13,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            _summary,
            style: const TextStyle(
              color: Color(0xFFE0E7FF),
              fontSize: 13,
              height: 1.65,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFindingsCard() {
    final hasWarnings = _findings.any(
      (f) => f.startsWith('[경고]') || f.startsWith('[오류]'),
    );
    final headerColor =
        hasWarnings ? const Color(0xFFD97706) : const Color(0xFF10B981);
    final borderColor =
        hasWarnings ? const Color(0xFF92400E) : const Color(0xFF065F46);
    final bgColor =
        hasWarnings ? const Color(0xFF1C1207) : const Color(0xFF052E16);

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: bgColor,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: borderColor),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                hasWarnings
                    ? Icons.warning_amber_rounded
                    : Icons.check_circle_outline,
                color: headerColor,
                size: 18,
              ),
              const SizedBox(width: 8),
              Text(
                '탐지 결과 (${_findings.length}건)',
                style: TextStyle(
                  color: headerColor,
                  fontSize: 14,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          ..._findings.map(
            (f) => Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    '• ',
                    style: TextStyle(color: Color(0xFF9CA3AF), fontSize: 13),
                  ),
                  Expanded(
                    child: Text(
                      f,
                      style: const TextStyle(
                        color: Color(0xFFD1D5DB),
                        fontSize: 13,
                        height: 1.5,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  /// 스크린샷 카드.
  ///
  /// 탭하면 전체화면으로 열리고 [InteractiveViewer]로 핀치줌을 지원한다.
  Widget _buildScreenshotCard(String title, Uint8List bytes) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // 타이틀 + "탭하여 확대" 힌트
        Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: Row(
            children: [
              Text(
                title,
                style: const TextStyle(
                  color: Color(0xFF9CA3AF),
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 0.3,
                ),
              ),
              const Spacer(),
              const Icon(
                Icons.zoom_in_rounded,
                color: Color(0xFF6B7280),
                size: 13,
              ),
              const SizedBox(width: 3),
              const Text(
                '탭하여 확대',
                style: TextStyle(color: Color(0xFF6B7280), fontSize: 11),
              ),
            ],
          ),
        ),
        // 이미지 + 전체화면 오버레이 버튼
        GestureDetector(
          onTap: () => _openFullScreen(bytes, title),
          child: Stack(
            alignment: Alignment.bottomRight,
            children: [
              ClipRRect(
                borderRadius: BorderRadius.circular(12),
                child: Image.memory(
                  bytes,
                  width: double.infinity,
                  fit: BoxFit.fitWidth,
                  errorBuilder: (_, __, ___) => _buildScreenshotPlaceholder(),
                ),
              ),
              // 전체화면 힌트 배지
              Padding(
                padding: const EdgeInsets.all(8),
                child: Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: Colors.black54,
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: const Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        Icons.zoom_out_map_rounded,
                        color: Colors.white,
                        size: 11,
                      ),
                      SizedBox(width: 4),
                      Text(
                        '전체화면',
                        style: TextStyle(color: Colors.white, fontSize: 10),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildScreenshotPlaceholder() {
    return Container(
      height: 120,
      decoration: BoxDecoration(
        color: const Color(0xFF1F2937),
        borderRadius: BorderRadius.circular(12),
      ),
      child: const Center(
        child: Text(
          '스크린샷을 불러올 수 없습니다.',
          style: TextStyle(color: Color(0xFF6B7280), fontSize: 12),
        ),
      ),
    );
  }
}
