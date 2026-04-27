/// URL 감지 유틸리티
///
/// 앱 전체에서 URL 포함 여부 판단에 사용하는 단일 정규식.
/// - http/https 프로토콜 URL
/// - www. 로 시작하는 베어 도메인
// 백엔드 _PROTO_URL_RE / _BARE_DOMAIN_RE 와 동일한 제외 문자셋 적용
final _urlPattern = RegExp(r'''https?://[^\s\[\]()<>"']+|www\.[^\s\[\]()<>"'.]+\.[a-zA-Z]{2,}''');

bool containsUrl(String text) => _urlPattern.hasMatch(text);

String? extractFirstUrl(String text) => _urlPattern.firstMatch(text)?.group(0);
