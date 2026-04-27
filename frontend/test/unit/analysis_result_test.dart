import 'package:flutter_test/flutter_test.dart';
import 'package:security_hub/models/analysis_result.dart';

void main() {
  group('AnalysisResult.fromJson', () {
    test('danger 상태를 올바르게 파싱한다', () {
      final result = AnalysisResult.fromJson({
        'status': 'danger',
        'title': '위험',
        'description': '악성 URL 감지',
        'action_label': '차단하기',
      });
      expect(result.status, RiskStatus.danger);
      expect(result.title, '위험');
      expect(result.description, '악성 URL 감지');
      expect(result.actionLabel, '차단하기');
    });

    test('suspicious 상태를 올바르게 파싱한다', () {
      final result = AnalysisResult.fromJson({
        'status': 'suspicious',
        'title': '의심',
        'description': '의심스러운 패턴',
        'action_label': '가상환경 테스트',
      });
      expect(result.status, RiskStatus.suspicious);
    });

    test('safe 상태를 올바르게 파싱한다', () {
      final result = AnalysisResult.fromJson({
        'status': 'safe',
        'title': '안전',
        'description': '화이트리스트 등록 URL',
        'action_label': '열기',
      });
      expect(result.status, RiskStatus.safe);
    });

    test('알 수 없는 status는 suspicious로 폴백한다', () {
      final result = AnalysisResult.fromJson({
        'status': 'unknown_value',
        'title': '?',
        'description': '',
        'action_label': '확인',
      });
      expect(result.status, RiskStatus.suspicious);
    });

    test('누락된 필드는 기본값으로 채워진다', () {
      final result = AnalysisResult.fromJson({'status': 'safe'});
      expect(result.title, '분석 완료');
      expect(result.description, '');
      expect(result.actionLabel, '확인');
    });
  });
}
