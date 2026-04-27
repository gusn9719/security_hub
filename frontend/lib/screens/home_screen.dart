import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show Clipboard, MethodCall;
import 'package:url_launcher/url_launcher.dart';
import 'package:permission_handler/permission_handler.dart';

import '../models/analysis_result.dart';
import '../services/api_service.dart';
import '../services/platform_service.dart';
import '../screens/virtual_sandbox_screen.dart';
import '../utils/url_utils.dart';
import '../widgets/quick_chip.dart';
import '../widgets/sms_picker_sheet.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen>
    with SingleTickerProviderStateMixin {
  final TextEditingController _textController = TextEditingController();
  AnalysisResult? _currentResult;
  bool _isLoading = false;
  StreamSubscription<Map<String, String>>? _smsSub;

  late AnimationController _animationController;
  late Animation<double> _fadeAnimation;
  late Animation<Offset> _slideAnimation;

  @override
  void initState() {
    super.initState();
    _animationController = AnimationController(
      duration: const Duration(milliseconds: 600),
      vsync: this,
    );
    _fadeAnimation = CurvedAnimation(
      parent: _animationController,
      curve: Curves.easeOut,
    );
    _slideAnimation = Tween<Offset>(
      begin: const Offset(0, 0.15),
      end: Offset.zero,
    ).animate(
      CurvedAnimation(parent: _animationController, curve: Curves.easeOut),
    );
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      await Permission.notification.request();
      await Permission.sms.request();  // RECEIVE_SMS 포함 — BroadcastReceiver 발동 필수
      await _getSharedText();
      await _checkClipboard();
    });
    PlatformService.setMethodCallHandler(_handlePlatformCall);
    _smsSub = PlatformService.incomingSmsStream.listen(_showIncomingSmsBar);
  }

  @override
  void dispose() {
    _smsSub?.cancel();
    _textController.dispose();
    _animationController.dispose();
    super.dispose();
  }

  // -------------------------------------------------------------------------
  // INP-02: 외부 앱 공유하기
  // -------------------------------------------------------------------------

  Future<void> _getSharedText() async {
    final text = await PlatformService.getSharedText();
    if (text != null && text.isNotEmpty && mounted) {
      _textController.text = text;
      _showSharedTextBanner();
    }
  }

  Future<dynamic> _handlePlatformCall(MethodCall call) async {
    if (call.method == 'onSharedText' && mounted) {
      final text = call.arguments as String?;
      if (text != null && text.isNotEmpty) {
        _textController.text = text;
        _showSharedTextBanner();
      }
    }
  }

  void _showSharedTextBanner() {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Text('공유된 텍스트를 불러왔습니다. 분석하기를 눌러주세요.'),
        behavior: SnackBarBehavior.floating,
        backgroundColor: const Color(0xFF0F9B58),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        duration: const Duration(seconds: 3),
      ),
    );
  }

  // -------------------------------------------------------------------------
  // INP-03: 클립보드 감지
  // -------------------------------------------------------------------------

  Future<void> _checkClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text?.trim() ?? '';
    if (text.isEmpty || !mounted) return;

    if (!containsUrl(text)) return;

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Text('클립보드에서 URL이 감지되었습니다.'),
        behavior: SnackBarBehavior.floating,
        backgroundColor: const Color(0xFF1A56DB),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        duration: const Duration(seconds: 5),
        action: SnackBarAction(
          label: '불러오기',
          textColor: Colors.white,
          onPressed: () => _textController.text = text,
        ),
      ),
    );
  }

  Future<void> _pasteFromClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text?.trim() ?? '';
    if (!mounted) return;
    if (text.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: const Text('클립보드가 비어 있습니다.'),
          behavior: SnackBarBehavior.floating,
          backgroundColor: Colors.grey[800],
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        ),
      );
      return;
    }
    _textController.text = text;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Text('클립보드 내용을 불러왔습니다.'),
        behavior: SnackBarBehavior.floating,
        backgroundColor: Colors.grey[800],
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        duration: const Duration(seconds: 2),
      ),
    );
  }

  // -------------------------------------------------------------------------
  // INP-05: 문자 수신 실시간 감지
  // -------------------------------------------------------------------------

  void _showIncomingSmsBar(Map<String, String> sms) {
    if (!mounted) return;
    final body = sms['body'] ?? '';
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Text('링크가 포함된 문자가 도착했습니다.'),
        behavior: SnackBarBehavior.floating,
        backgroundColor: const Color(0xFF1A56DB),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        duration: const Duration(seconds: 8),
        action: SnackBarAction(
          label: '지금 분석',
          textColor: Colors.white,
          onPressed: () {
            _textController.text = body;
            _onAnalyzePressed();
          },
        ),
      ),
    );
  }

  // -------------------------------------------------------------------------
  // INP-04: 문자 직접 읽기
  // -------------------------------------------------------------------------

  Future<void> _openSmsSheet() async {
    var status = await Permission.sms.status;

    if (status.isPermanentlyDenied) {
      if (!mounted) return;
      _showOpenSettingsSnackbar();
      return;
    }

    if (!status.isGranted) {
      status = await Permission.sms.request();
    }

    if (!mounted) return;

    if (status.isPermanentlyDenied) {
      _showOpenSettingsSnackbar();
      return;
    }

    if (!status.isGranted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: const Text('문자 읽기 권한이 거부되었습니다.'),
          behavior: SnackBarBehavior.floating,
          backgroundColor: Colors.red[700],
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        ),
      );
      return;
    }

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (_) => SmsPickerSheet(
        onSelected: (body) {
          _textController.text = body;
          Navigator.pop(context);
        },
      ),
    );
  }

  void _showOpenSettingsSnackbar() {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Text('설정에서 문자 읽기 권한을 허용해주세요.'),
        behavior: SnackBarBehavior.floating,
        backgroundColor: Colors.red[700],
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        duration: const Duration(seconds: 5),
        action: SnackBarAction(
          label: '설정 열기',
          textColor: Colors.white,
          onPressed: openAppSettings,
        ),
      ),
    );
  }

  // -------------------------------------------------------------------------
  // 이벤트 핸들러
  // -------------------------------------------------------------------------

  Future<void> _onAnalyzePressed() async {
    if (_textController.text.trim().isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: const Text('분석할 문자 내용을 먼저 입력해주세요.'),
          behavior: SnackBarBehavior.floating,
          backgroundColor: Colors.grey[800],
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        ),
      );
      return;
    }

    final text = _textController.text.trim();
    if (!containsUrl(text)) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: const Text('URL이 포함된 문자를 입력해 주세요.'),
          behavior: SnackBarBehavior.floating,
          backgroundColor: Colors.grey[800],
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          duration: const Duration(seconds: 4),
        ),
      );
      return;
    }

    setState(() {
      _isLoading = true;
      _currentResult = null;
    });
    _animationController.reset();

    try {
      final result = await ApiService.analyzeText(text);
      if (!mounted) return;
      setState(() {
        _currentResult = result;
        _isLoading = false;
      });
      _animationController.forward();
    } catch (e) {
      if (!mounted) return;
      setState(() => _isLoading = false);
      final message = e is Exception
          ? e.toString().replaceFirst('Exception: ', '')
          : '알 수 없는 오류가 발생했습니다.';
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(message),
          behavior: SnackBarBehavior.floating,
          backgroundColor: Colors.red[700],
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          duration: const Duration(seconds: 5),
        ),
      );
    }
  }

  // -------------------------------------------------------------------------
  // UI 빌더 메서드
  // -------------------------------------------------------------------------

  List<Color> _getStatusColors(RiskStatus status) {
    switch (status) {
      case RiskStatus.safe:
        return [const Color(0xFF0F9B58), const Color(0xFFECFDF5), const Color(0xFF6EE7B7)];
      case RiskStatus.suspicious:
        return [const Color(0xFFD97706), const Color(0xFFFFFBEB), const Color(0xFFFCD34D)];
      case RiskStatus.danger:
        return [const Color(0xFFDC2626), const Color(0xFFFEF2F2), const Color(0xFFFCA5A5)];
      case RiskStatus.idle:
        return [Colors.grey, Colors.grey[100]!, Colors.grey[300]!];
    }
  }

  IconData _getStatusIcon(RiskStatus status) {
    switch (status) {
      case RiskStatus.safe:       return Icons.verified_rounded;
      case RiskStatus.suspicious: return Icons.warning_amber_rounded;
      case RiskStatus.danger:     return Icons.dangerous_rounded;
      case RiskStatus.idle:       return Icons.search_rounded;
    }
  }

  String _getStatusLabel(RiskStatus status) {
    switch (status) {
      case RiskStatus.safe:       return '안전 (Safe)';
      case RiskStatus.suspicious: return '의심 (Suspicious)';
      case RiskStatus.danger:     return '위험 (Danger)';
      case RiskStatus.idle:       return '탐지 완료';
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF8F9FC),
      appBar: _buildAppBar(),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildInputSection(),
              const SizedBox(height: 20),
              _buildAnalyzeButton(),
              const SizedBox(height: 28),
              _buildResultSection(),
            ],
          ),
        ),
      ),
    );
  }

  AppBar _buildAppBar() {
    return AppBar(
      backgroundColor: Colors.white,
      elevation: 0,
      surfaceTintColor: Colors.transparent,
      centerTitle: false,
      title: Row(
        children: [
          Container(
            width: 32,
            height: 32,
            decoration: BoxDecoration(
              color: const Color(0xFF1A56DB),
              borderRadius: BorderRadius.circular(8),
            ),
            child: const Icon(Icons.security_rounded, color: Colors.white, size: 18),
          ),
          const SizedBox(width: 10),
          const Text(
            '보안 검증 시스템',
            style: TextStyle(
              fontSize: 17,
              fontWeight: FontWeight.w700,
              color: Color(0xFF111827),
              letterSpacing: -0.3,
            ),
          ),
        ],
      ),
      bottom: PreferredSize(
        preferredSize: const Size.fromHeight(1),
        child: Container(height: 1, color: const Color(0xFFE5E7EB)),
      ),
    );
  }

  Widget _buildInputSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          '문자 내용 입력',
          style: TextStyle(
            fontSize: 13,
            fontWeight: FontWeight.w600,
            color: Color(0xFF6B7280),
            letterSpacing: 0.3,
          ),
        ),
        const SizedBox(height: 8),
        Container(
          decoration: BoxDecoration(
            color: Colors.white,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: const Color(0xFFE5E7EB)),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withOpacity(0.04),
                blurRadius: 12,
                offset: const Offset(0, 2),
              ),
            ],
          ),
          child: TextField(
            controller: _textController,
            maxLines: 6,
            minLines: 6,
            style: const TextStyle(fontSize: 15, color: Color(0xFF1F2937), height: 1.6),
            decoration: const InputDecoration(
              hintText: '분석할 내용을 입력하세요.\n\n의심되는 URL, 코드, 메시지 등을 입력해주세요...',
              hintStyle: TextStyle(color: Color(0xFFADB5BD), fontSize: 14, height: 1.6),
              contentPadding: EdgeInsets.all(18),
              border: InputBorder.none,
            ),
          ),
        ),
        const SizedBox(height: 10),
        Row(
          children: [
            QuickChip(
              icon: Icons.content_paste_rounded,
              label: '클립보드',
              onTap: _pasteFromClipboard,
            ),
            const SizedBox(width: 8),
            QuickChip(
              icon: Icons.sms_rounded,
              label: '문자 불러오기',
              onTap: _openSmsSheet,
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildAnalyzeButton() {
    return SizedBox(
      height: 54,
      child: ElevatedButton(
        onPressed: _isLoading ? null : _onAnalyzePressed,
        style: ElevatedButton.styleFrom(
          backgroundColor: const Color(0xFF1A56DB),
          foregroundColor: Colors.white,
          disabledBackgroundColor: const Color(0xFF93AAED),
          elevation: 0,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
        ),
        child: _isLoading
            ? const SizedBox(
                width: 22,
                height: 22,
                child: CircularProgressIndicator(strokeWidth: 2.5, color: Colors.white),
              )
            : const Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(Icons.manage_search_rounded, size: 20),
                  SizedBox(width: 8),
                  Text(
                    '분석하기',
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700, letterSpacing: 0.2),
                  ),
                ],
              ),
      ),
    );
  }

  Widget _buildResultSection() {
    if (_currentResult == null) return _buildIdleResultArea();
    return FadeTransition(
      opacity: _fadeAnimation,
      child: SlideTransition(
        position: _slideAnimation,
        child: _buildResultCard(_currentResult!),
      ),
    );
  }

  Widget _buildIdleResultArea() {
    return Container(
      height: 200,
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: const Color(0xFFE5E7EB)),
      ),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.radar_rounded, size: 40, color: Colors.grey[300]),
          const SizedBox(height: 12),
          Text(
            '분석 결과가 여기에 표시됩니다',
            style: TextStyle(fontSize: 14, color: Colors.grey[400], fontWeight: FontWeight.w500),
          ),
          const SizedBox(height: 4),
          Text(
            '위에 문자 내용을 입력하고 분석하기를 눌러주세요',
            style: TextStyle(fontSize: 12, color: Colors.grey[350]),
          ),
        ],
      ),
    );
  }

  Widget _buildResultCard(AnalysisResult result) {
    final colors = _getStatusColors(result.status);
    final primaryColor = colors[0];
    final bgColor      = colors[1];
    final borderColor  = colors[2];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          '탐지 완료',
          style: TextStyle(
            fontSize: 13,
            fontWeight: FontWeight.w600,
            color: Color(0xFF6B7280),
            letterSpacing: 0.3,
          ),
        ),
        const SizedBox(height: 8),
        Container(
          width: double.infinity,
          decoration: BoxDecoration(
            color: bgColor,
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: borderColor, width: 1.5),
            boxShadow: [
              BoxShadow(
                color: primaryColor.withOpacity(0.1),
                blurRadius: 20,
                offset: const Offset(0, 4),
              ),
            ],
          ),
          child: Column(
            children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(24, 28, 24, 8),
                child: _buildTrafficLight(result.status, primaryColor),
              ),
              Text(
                _getStatusLabel(result.status),
                style: TextStyle(
                  fontSize: 22,
                  fontWeight: FontWeight.w800,
                  color: primaryColor,
                  letterSpacing: -0.5,
                ),
              ),
              const SizedBox(height: 4),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
                child: Divider(color: borderColor, height: 1),
              ),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 24),
                child: Text(
                  result.description,
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    fontSize: 13.5,
                    color: primaryColor.withOpacity(0.85),
                    height: 1.7,
                  ),
                ),
              ),
              const SizedBox(height: 20),
              Padding(
                padding: const EdgeInsets.fromLTRB(24, 0, 24, 24),
                child: SizedBox(
                  width: double.infinity,
                  height: 48,
                  child: ElevatedButton(
                    onPressed: () {
                      if (result.status == RiskStatus.suspicious) {
                        final url = extractFirstUrl(_textController.text);
                        if (url != null && context.mounted) {
                          Navigator.push(
                            context,
                            MaterialPageRoute(
                              builder: (context) => VirtualSandboxScreen(url: url),
                            ),
                          );
                        }
                      } else if (result.status == RiskStatus.safe) {
                        showDialog(
                          context: context,
                          builder: (ctx) => AlertDialog(
                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
                            title: const Row(
                              children: [
                                Icon(Icons.open_in_browser, color: Color(0xFF0F9B58)),
                                SizedBox(width: 8),
                                Text('웹 브라우저로 이동', style: TextStyle(fontSize: 18)),
                              ],
                            ),
                            content: const Text('해당 URL은 화이트리스트에 등록된 안전한 주소입니다.\n기본 웹 브라우저를 열어 이동하시겠습니까?'),
                            actions: [
                              TextButton(
                                onPressed: () => Navigator.pop(ctx),
                                child: const Text('취소', style: TextStyle(color: Colors.grey)),
                              ),
                              TextButton(
                                onPressed: () async {
                                  Navigator.pop(ctx);
                                  final urlRegExp = RegExp(r'https?:\/\/[^\s]+');
                                  final match = urlRegExp.firstMatch(_textController.text);
                                  if (match != null) {
                                    final uri = Uri.parse(match.group(0)!);
                                    try {
                                      await launchUrl(uri, mode: LaunchMode.externalApplication);
                                    } catch (e) {
                                      if (!context.mounted) return;
                                      ScaffoldMessenger.of(context).showSnackBar(
                                        const SnackBar(content: Text('해당 URL을 열 수 없습니다. 브라우저 앱이 설치되어 있는지 확인해주세요.')),
                                      );
                                    }
                                  } else {
                                    if (!context.mounted) return;
                                    ScaffoldMessenger.of(context).showSnackBar(
                                      const SnackBar(content: Text('이동할 URL을 찾을 수 없습니다.')),
                                    );
                                  }
                                },
                                child: const Text('이동하기', style: TextStyle(color: Color(0xFF0F9B58), fontWeight: FontWeight.bold)),
                              ),
                            ],
                          ),
                        );
                      } else if (result.status == RiskStatus.danger) {
                        showDialog(
                          context: context,
                          builder: (ctx) => AlertDialog(
                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
                            title: const Row(
                              children: [
                                Icon(Icons.block, color: Color(0xFFDC2626)),
                                SizedBox(width: 8),
                                Text('발신번호 차단', style: TextStyle(fontSize: 18)),
                              ],
                            ),
                            content: const Text('차단 기능은 추후 구현될 예정입니다.'),
                            actions: [
                              TextButton(
                                onPressed: () => Navigator.pop(ctx),
                                child: const Text('닫기'),
                              ),
                            ],
                          ),
                        );
                      }
                    },
                    style: ElevatedButton.styleFrom(
                      backgroundColor: primaryColor,
                      foregroundColor: Colors.white,
                      elevation: 0,
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                    ),
                    child: Text(
                      result.actionLabel,
                      style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 14),
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildTrafficLight(RiskStatus status, Color activeColor) {
    final items = [
      (RiskStatus.safe,       const Color(0xFF0F9B58)),
      (RiskStatus.suspicious, const Color(0xFFD97706)),
      (RiskStatus.danger,     const Color(0xFFDC2626)),
    ];

    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: items.map((item) {
        final isActive = item.$1 == status;
        return AnimatedContainer(
          duration: const Duration(milliseconds: 400),
          curve: Curves.easeInOut,
          margin: const EdgeInsets.symmetric(horizontal: 10),
          width: isActive ? 72 : 24,
          height: isActive ? 72 : 24,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: isActive ? item.$2 : item.$2.withOpacity(0.15),
            boxShadow: isActive
                ? [BoxShadow(color: item.$2.withOpacity(0.45), blurRadius: 20, spreadRadius: 4)]
                : null,
          ),
          child: isActive
              ? Icon(_getStatusIcon(status), color: Colors.white, size: 32)
              : null,
        );
      }).toList(),
    );
  }
}
