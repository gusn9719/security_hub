import 'package:flutter/material.dart';

import '../services/platform_service.dart';
import '../utils/url_utils.dart';

class SmsPickerSheet extends StatefulWidget {
  final ValueChanged<String> onSelected;

  const SmsPickerSheet({super.key, required this.onSelected});

  @override
  State<SmsPickerSheet> createState() => _SmsPickerSheetState();
}

class _SmsPickerSheetState extends State<SmsPickerSheet> {
  List<Map<String, String>> _messages = [];
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadMessages();
  }

  Future<void> _loadMessages() async {
    try {
      final messages = await PlatformService.getSmsMessages();
      if (!mounted) return;
      setState(() {
        _messages = messages.where((m) => containsUrl(m['body'] ?? '')).toList();
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = '문자를 불러오는 중 오류가 발생했습니다.';
        _loading = false;
      });
    }
  }

  String _formatDate(String epochMs) {
    final dt = DateTime.fromMillisecondsSinceEpoch(int.tryParse(epochMs) ?? 0);
    return '${dt.month}/${dt.day} ${dt.hour.toString().padLeft(2, '0')}:${dt.minute.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    return DraggableScrollableSheet(
      initialChildSize: 0.65,
      minChildSize: 0.4,
      maxChildSize: 0.92,
      builder: (_, controller) => Container(
        decoration: const BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
        ),
        child: Column(
          children: [
            const SizedBox(height: 12),
            Container(
              width: 40,
              height: 4,
              decoration: BoxDecoration(
                color: const Color(0xFFE5E7EB),
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            const SizedBox(height: 16),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: Row(
                children: [
                  const Icon(Icons.sms_rounded, color: Color(0xFF1A56DB), size: 20),
                  const SizedBox(width: 8),
                  const Text(
                    '최근 문자 선택',
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700, color: Color(0xFF111827)),
                  ),
                  const Spacer(),
                  Text(
                    '탭하면 분석 입력창에 채워집니다',
                    style: TextStyle(fontSize: 11, color: Colors.grey[500]),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),
            const Divider(height: 1),
            Expanded(child: _buildBody(controller)),
          ],
        ),
      ),
    );
  }

  Widget _buildBody(ScrollController controller) {
    if (_loading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_error != null) {
      return Center(child: Text(_error!, style: TextStyle(color: Colors.red[700])));
    }
    if (_messages.isEmpty) {
      return const Center(
        child: Text('받은 문자함이 비어 있습니다.', style: TextStyle(color: Color(0xFF9CA3AF))),
      );
    }
    return ListView.separated(
      controller: controller,
      padding: const EdgeInsets.symmetric(vertical: 8),
      itemCount: _messages.length,
      separatorBuilder: (context, index) => const Divider(height: 1, indent: 20, endIndent: 20),
      itemBuilder: (_, i) {
        final msg = _messages[i];
        final address = msg['address'] ?? '';
        final body    = msg['body']    ?? '';
        final date    = _formatDate(msg['date'] ?? '0');
        final hasUrl  = containsUrl(body);

        return ListTile(
          contentPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 4),
          leading: CircleAvatar(
            backgroundColor: hasUrl ? const Color(0xFFFEF2F2) : const Color(0xFFF3F4F6),
            radius: 20,
            child: Icon(
              hasUrl ? Icons.link_rounded : Icons.message_rounded,
              size: 18,
              color: hasUrl ? const Color(0xFFDC2626) : const Color(0xFF6B7280),
            ),
          ),
          title: Row(
            children: [
              Expanded(
                child: Text(
                  address,
                  style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: Color(0xFF111827)),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              if (hasUrl)
                Container(
                  margin: const EdgeInsets.only(left: 6),
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: const Color(0xFFFEF2F2),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: const Text('URL', style: TextStyle(fontSize: 10, color: Color(0xFFDC2626), fontWeight: FontWeight.w700)),
                ),
              const SizedBox(width: 8),
              Text(date, style: const TextStyle(fontSize: 11, color: Color(0xFF9CA3AF))),
            ],
          ),
          subtitle: Padding(
            padding: const EdgeInsets.only(top: 2),
            child: Text(
              body,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(fontSize: 12, color: Color(0xFF6B7280), height: 1.4),
            ),
          ),
          onTap: () => widget.onSelected(body),
        );
      },
    );
  }
}
