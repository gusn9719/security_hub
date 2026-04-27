// =============================================================================
// lib/models/analysis_result.dart
// 역할: 백엔드 분석 API 응답을 담는 데이터 모델.
// main.dart에서 분리하여 재사용성을 높인다.
// =============================================================================

/// 분석 결과의 위험 상태를 나타내는 열거형(Enum).
enum RiskStatus { safe, suspicious, danger, idle }

/// 백엔드 분석 API의 응답을 담는 데이터 모델.
///
/// [status]:      위험 상태 (RiskStatus)
/// [title]:       결과 요약 제목
/// [description]: 위험 사유 상세 설명
/// [actionLabel]: 하단 액션 버튼 텍스트
class AnalysisResult {
  final RiskStatus status;
  final String title;
  final String description;
  final String actionLabel;

  const AnalysisResult({
    required this.status,
    required this.title,
    required this.description,
    required this.actionLabel,
  });

  /// JSON 응답을 [AnalysisResult]로 변환하는 팩토리 생성자.
  ///
  /// 방어적 프로그래밍: 알 수 없는 status 값은 [RiskStatus.suspicious]로 처리.
  factory AnalysisResult.fromJson(Map<String, dynamic> json) {
    final statusMap = {
      'safe': RiskStatus.safe,
      'suspicious': RiskStatus.suspicious,
      'danger': RiskStatus.danger,
    };

    return AnalysisResult(
      status: statusMap[json['status']] ?? RiskStatus.suspicious,
      title: json['title'] ?? '분석 완료',
      description: json['description'] ?? '',
      actionLabel: json['action_label'] ?? '확인',
    );
  }
}