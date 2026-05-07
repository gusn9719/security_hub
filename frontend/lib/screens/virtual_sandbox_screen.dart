// =============================================================================
// lib/screens/virtual_sandbox_screen.dart
// 역할: 백엔드 Browserless 샌드박스에 URL을 분석 요청하고 결과(스크린샷·탐지 항목)를 표시.
// 주의: WebView로 URL을 직접 여는 것이 아니라 서버 측 격리 컨테이너에서 실행한다.
// =============================================================================

import 'dart:convert';

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
  List<String> _findings = [];
  String? _screenshotInitial;
  String? _screenshotAfter3s;

  @override
  void initState() {
    super.initState();
    // 모드 선택 UI를 먼저 보여주기 위해 자동 실행하지 않는다.
  }

  Future<void> _startDirectBrowse() async {
    setState(() => _isBrowseStarting = true);
    try {
      final mq = MediaQuery.of(context);
      // 논리 픽셀(CSS px) 사용: 컨테이너 내부는 DPR이 없어 1px=1CSS px이므로
      // 물리 픽셀을 보내면 1080px = 데스크탑 뷰포트가 된다.
      // 논리 픽셀(예: 411px)을 보내면 모바일 레이아웃이 트리거된다.
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

  Future<void> _runSandbox() async {
    try {
      final result = await ApiService.startSandbox(widget.url);
      if (!mounted) return;
      setState(() {
        _findings = List<String>.from(result['findings'] ?? []);
        _screenshotInitial = result['screenshot_initial'] as String?;
        _screenshotAfter3s = result['screenshot_after3s'] as String?;
        _error = result['error'] as String?;
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
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.w700, color: Colors.white),
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
              style: TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 8),
            Text(
              widget.url,
              style: const TextStyle(color: Color(0xFF9CA3AF), fontSize: 12),
              overflow: TextOverflow.ellipsis,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 36),
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
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: () {
                  setState(() => _modeSelected = true);
                  _runSandbox();
                },
                icon: const Icon(Icons.smart_toy_outlined),
                label: const Padding(
                  padding: EdgeInsets.symmetric(vertical: 4),
                  child: Column(
                    children: [
                      Text('AI 자동 분석', style: TextStyle(fontSize: 15, fontWeight: FontWeight.w700)),
                      SizedBox(height: 2),
                      Text('Playwright가 자동으로 위협을 탐지', style: TextStyle(fontSize: 11)),
                    ],
                  ),
                ),
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF374151),
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(vertical: 14, horizontal: 20),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

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
            '격리 컨테이너 실행 중...',
            style: TextStyle(color: Color(0xFF9CA3AF), fontSize: 14),
          ),
          SizedBox(height: 6),
          Text(
            'Docker 컨테이너 생성 및 URL 분석에 최대 60초가 소요됩니다.',
            style: TextStyle(color: Color(0xFF6B7280), fontSize: 12),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildResultView() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (_error != null) _buildErrorCard(),
          // findings가 있을 때만 탐지 결과 카드 표시
          // (API 호출 자체가 실패하면 findings=[]이므로 빈 카드가 뜨지 않도록)
          if (_findings.isNotEmpty) ...[
            _buildFindingsCard(),
            const SizedBox(height: 16),
          ],
          if (_screenshotInitial != null) ...[
            _buildScreenshotCard('접속 직후 스크린샷', _screenshotInitial!),
            const SizedBox(height: 16),
          ],
          if (_screenshotAfter3s != null)
            _buildScreenshotCard('3초 후 스크린샷', _screenshotAfter3s!),
        ],
      ),
    );
  }

  Widget _buildErrorCard() {
    return Container(
      width: double.infinity,
      margin: const EdgeInsets.only(bottom: 12),
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
              style: const TextStyle(color: Color(0xFFFCA5A5), fontSize: 13, height: 1.5),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFindingsCard() {
    final hasWarnings = _findings.any((f) => f.startsWith('[경고]') || f.startsWith('[오류]'));
    final headerColor = hasWarnings ? const Color(0xFFD97706) : const Color(0xFF10B981);
    final borderColor = hasWarnings ? const Color(0xFF92400E) : const Color(0xFF065F46);
    final bgColor = hasWarnings ? const Color(0xFF1C1207) : const Color(0xFF052E16);

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
                hasWarnings ? Icons.warning_amber_rounded : Icons.check_circle_outline,
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
                  const Text('• ', style: TextStyle(color: Color(0xFF9CA3AF), fontSize: 13)),
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

  Widget _buildScreenshotCard(String title, String base64Data) {
    // base64Decode는 FormatException을 던질 수 있으므로 반드시 try-catch 처리
    Widget imageWidget;
    try {
      final bytes = base64Decode(base64Data);
      imageWidget = ClipRRect(
        borderRadius: BorderRadius.circular(12),
        child: Image.memory(
          bytes,
          width: double.infinity,
          fit: BoxFit.fitWidth,
          errorBuilder: (_, _, _) => _buildScreenshotPlaceholder(),
        ),
      );
    } catch (_) {
      imageWidget = _buildScreenshotPlaceholder();
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: Text(
            title,
            style: const TextStyle(
              color: Color(0xFF9CA3AF),
              fontSize: 12,
              fontWeight: FontWeight.w600,
              letterSpacing: 0.3,
            ),
          ),
        ),
        imageWidget,
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
