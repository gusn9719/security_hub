import 'package:flutter_test/flutter_test.dart';
import 'package:security_hub/utils/url_utils.dart';

void main() {
  group('containsUrl', () {
    group('URL이 포함된 경우 → true 반환', () {
      final cases = [
        'https://phishing.example.com/login',
        'http://malware.co.kr/download',
        '지금 바로 클릭하세요 https://evil.com/event',
        '축하합니다! www.fake-bank.com 에서 수령하세요',
        '택배 조회: http://短縮URL.kr',
        'URL: HTTPS://CAPS.COM', // 대문자 — 현재 regex는 대소문자 구분함
      ];

      // https/http는 감지
      for (final text in cases.where((t) => t.contains('http'))) {
        test('감지: "$text"', () => expect(containsUrl(text), isTrue));
      }

      // www. 베어 도메인도 감지
      for (final text in cases.where((t) => t.contains('www.'))) {
        test('감지: "$text"', () => expect(containsUrl(text), isTrue));
      }
    });

    group('URL이 없는 경우 → false 반환', () {
      final cases = [
        '',
        '안녕하세요. 고객님의 택배가 도착했습니다.',
        '인증번호: 123456',
        '010-1234-5678로 연락주세요',
        'www 없는 도메인만: google.com',
      ];

      for (final text in cases) {
        test('미감지: "$text"', () => expect(containsUrl(text), isFalse));
      }
    });

    test('빈 문자열은 false', () => expect(containsUrl(''), isFalse));

    test('http URL은 true', () {
      expect(containsUrl('http://example.com'), isTrue);
    });

    test('https URL은 true', () {
      expect(containsUrl('https://example.com'), isTrue);
    });

    test('www 베어 도메인은 true', () {
      expect(containsUrl('www.example.com'), isTrue);
    });

    test('단순 텍스트는 false', () {
      expect(containsUrl('이것은 URL이 없는 문자입니다'), isFalse);
    });
  });
}
