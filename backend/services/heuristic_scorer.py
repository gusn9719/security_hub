# =============================================================================
# backend/services/heuristic_scorer.py
# 역할: 7단계 — 다중 시그널 가중합 휴리스틱 스코어링
#
# ════════════════════════════════════════════════════════════════════════════
# 모듈 개요
# ════════════════════════════════════════════════════════════════════════════
# URL 한 건에 대해 23종 시그널을 평가하고, 시그널별 가중치 합으로 위험 점수
# (0~상한없음)를 산출한다. 점수와 임계값 비교로 DANGER/SUSPICIOUS/SAFE 를
# 결정하지만, analysis_service.py 가 DC-06(SAFE 는 화이트리스트 단독 경로)을
# 적용하므로 본 모듈의 SAFE 반환은 호출자에서 SUSPICIOUS 로 강제된다.
#
# ════════════════════════════════════════════════════════════════════════════
# 설계 원칙
# ════════════════════════════════════════════════════════════════════════════
# [원칙 1] 판정은 점수 임계값만으로. 개별 시그널이 직접 판정하지 않는다.
#          이유: 단일 시그널 오탐이 즉시 DANGER 로 이어지지 않게 하여 설명
#          가능성을 확보.
#
# [원칙 2] 단일 시그널 가중치 < DANGER_THRESHOLD(70).
#          현재 최대 단일 가중치 = +40 (sandbox_danger_score).
#          따라서 DANGER 도달에는 항상 2개 이상 시그널 조합 필요.
#          → 사용자에게 "왜 위험한지" 다중 근거 제시 가능.
#
# [원칙 3] 외부 입력은 모두 선택적(domain_evidence/vote_counts/sandbox_score).
#          외부 의존성이 끊겨도(WHOIS 실패·DB 오류) 기본 12개 정적 시그널만으로
#          동작 — 서비스 중단 없음.
#
# [원칙 4] DC-06: 음수 점수도 SAFE 를 만들지 못한다.
#          음의 시그널(prior_safe_vote_*) 적용 후 점수가 0 미만이면 0으로
#          클램프. 화이트리스트 미히트 = 알 수 없음 = SUSPICIOUS 보수.
#
# [원칙 5] 한국 사용자 대상 시그널 우선.
#          KrCERT 스미싱 동향에서 한국 사용자 사칭 빈도가 가장 높은
#          항목(.apk 직링크, 정부기관·금융 사칭, 택배 스미싱 등)에 더 높은
#          가중치를 부여.
#
# ════════════════════════════════════════════════════════════════════════════
# 임계값
# ════════════════════════════════════════════════════════════════════════════
#   DANGER_THRESHOLD     = 70  → RiskStatus.DANGER (단독 시그널 불가, 조합 필요)
#   SUSPICIOUS_THRESHOLD = 30  → RiskStatus.SUSPICIOUS
#   < 30                 → RiskStatus.SAFE (그러나 DC-06 으로 호출측에서
#                                            SUSPICIOUS 강제)
#
# 임계값 70 상향 사유 (v0513 결정):
#   - v0507 까지 60 → 60점 시그널 단독 발동 또는 30+30 조합으로 도달 가능
#   - 휴리스틱 단독 차단의 정확도 부담 완화
#   - 우리 강점인 격리 샌드박스(7-A 직접 탐방·7-B AI 자동 테스트) 권유 폭 확대
#   - 시그널 단독으로 DANGER 도달 불가 보장 → 항상 2~3개 조합 필요
#
# ════════════════════════════════════════════════════════════════════════════
# 출처 표기 약어
# ════════════════════════════════════════════════════════════════════════════
# 가중치 산정에 참조한 자료를 시그널별 주석에 약어로 표기한다.
#
#   [KISA-PDF-XX]  KISA "주요정보통신기반시설 기술적 취약점 분석·평가 방법
#                  상세가이드" — Chapter X. Web Application(웹).
#                  21개 점검 항목 코드: CI/SI/DI/EP/IL/XS/CF/SF/BF/IA/IN/PR/
#                  PV/FU/FD/IS/SN/CC/AE/AU/WM.
#                  (주의: 본 가이드는 '서버측 자가취약점 점검표'이므로 외부
#                   URL 분류 시그널과 직접 매핑되지 않는 항목이 다수.)
#
#   [KrCERT-Smi]   한국인터넷진흥원 인터넷침해사고대응팀(KrCERT/CC) 스미싱
#                  동향 분석 보고서 — 매년 발표. 스미싱 메시지 본문·URL 패턴
#                  통계, 사칭 표적 1순위 군 등 한국 환경 특화 데이터.
#
#   [KrCERT-CTI]   KrCERT/CC 사이버 위협 인텔리전스 보고서 — lookalike
#                  domain, brand impersonation, watering hole 등 위협 사례.
#
#   [KISA-IDN]     KISA 동형이의자(homograph) 공격 분석 자료 — Unicode 혼동
#                  문자 사칭 방어 권고.
#
#   [APWG]         Anti-Phishing Working Group "Phishing Activity Trends
#                  Report" — 글로벌 피싱 패턴 / brand impersonation 통계.
#
#   [UTS39]        Unicode Technical Standard #39 "Security Mechanisms" —
#                  IDN homograph, mixed-script confusables 정의.
#
#   [OWASP-DE]     OWASP "Double Encoding" 공격 카탈로그.
#
#   [RFC3986]      "Uniform Resource Identifier (URI): Generic Syntax" —
#                  §3.2.1 userinfo 컴포넌트 정의.
#
#   [PhishStorm]   Marchal et al. "PhishStorm: Detecting Phishing With
#                  Streaming Analytics" (IEEE TNSM, 2014) — URL 길이·구조
#                  피처 통계 분석.
#
#   [본 앱-SRS]    본 졸업작품 독자 설계 (security_hub_srs_v11 / DC 로그) —
#                  사용자 투표·샌드박스 능동 탐지 피드백 순환 메커니즘.
#
# ════════════════════════════════════════════════════════════════════════════
# 변경 이력
# ════════════════════════════════════════════════════════════════════════════
# - Sprint 5E (DC-25): /analyze 파이프라인 7단계 휴리스틱 신설
# - Sprint 7 PROMPT-5: vote_counts 시그널 연결 (prior_danger_vote_high/low)
# - Sprint 7 PROMPT-6: sandbox_score 시그널 연결 (ANL-11)
# - v0513:             DANGER 임계값 60 → 70 상향
# - v0527 (현재):
#     · KISA 매핑 환각 주석 정정 — 실제 출처(KrCERT/APWG 등)로 교체
#     · 신규 시그널 5종 추가:
#         typosquat_levenshtein   (ANL-06 미구현 해소)
#         userinfo_injection      ('a.com@evil.kr' 패턴)
#         suspicious_keywords     (login/verify/secure 호스트 키워드)
#         punycode_in_url         (xn-- 노출)
#         many_hyphens            (도메인 하이픈 3개+)
#     · 가중치 상향:
#         homograph_idn        25 → 30  (실 공격이 임계값 가까스로 통과 못 함)
#         sandbox_danger_score 30 → 40  (능동 탐지의 권위 반영)
#     · 음의 시그널 신설:
#         prior_safe_vote_high -15      (사용자 검증된 신생 사이트 톤 완화)
#         prior_safe_vote_low   -5
#     · 0 클램프 추가 (음수 점수 → 0): DC-06 보호
# =============================================================================

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from services.url_validator import (
    get_registered_domain,
    normalize_idn_hostname,
    has_double_encoding,
    check_userinfo_injection,
)
from services.domain_similarity import detect_typosquat

logger = logging.getLogger(__name__)


# =============================================================================
# 임계값
# =============================================================================

DANGER_THRESHOLD:     int = 70
SUSPICIOUS_THRESHOLD: int = 30


# =============================================================================
# 시그널별 가중치
# =============================================================================
# 각 시그널의 가중치 근거는 _WEIGHTS 인접 주석에 표기.
#
# 가중치 등급 체계:
#   직접위협 (+35~+40): 강한 의도성. 단독으론 SUSPICIOUS, 다른 1개와 결합으로 DANGER.
#   강신호   (+30):     단독으론 SUSPICIOUS, 다른 약신호와 결합으로 DANGER.
#   중신호   (+20):     단독으론 SUSPICIOUS, 2~3개 결합으로 DANGER.
#   약신호   (+5~+15):  보조 신호. 단독으론 영향 미미.
#   음의신호 (-5~-15):  사용자 검증으로 톤 완화. 최종 점수는 0 클램프(원칙 4).

_WEIGHTS: dict[str, int] = {

    # ─────────────────────────────────────────────────────────────────────────
    # 직접 위협 (+35) — 단독으론 SUSPICIOUS, +1 시그널 결합 시 DANGER 도달 가능
    # ─────────────────────────────────────────────────────────────────────────

    # URL 호스트가 IP 주소(예: http://192.168.1.100/, http://8.8.8.8:8080/path).
    # 정상 서비스는 도메인을 사용하므로 IP 직접 노출은 도메인 등록·인증
    # 추적을 회피하려는 의도. 단기 운영 스미싱 인프라에서 흔함.
    # 출처: [KrCERT-Smi] 스미싱 동향 분석에서 IP 호스트 접속 패턴 다빈도 보고.
    "ip_in_url":              35,

    # URL 경로가 .apk/.exe/.bat/.dll/.msi 등 실행 파일로 끝남.
    # 한국 스미싱의 1순위 패턴은 '택배 미수령'·'교통위반 통지' 메시지 +
    # .apk 직링크. 클릭만으로 악성 앱 설치 페이지로 이동.
    # 출처: [KrCERT-Smi] 매년 연례 보고에서 .apk 직링크가 스미싱 URL 의 절반
    #       이상을 차지. [KISA-PDF-FU] 14절 악성 파일 업로드 항목도 .apk/.exe/
    #       .bat 등을 위험 콘텐츠로 명시.
    "dangerous_extension":    35,

    # URL 에 userinfo(@) 가 포함되어 호스트 위장.
    # 예: https://naver.com@evil.kr/login
    # 브라우저는 @ 앞부분을 사용자명으로 무시하고 실제로는 evil.kr 로 접속.
    # 모바일 사용자가 가장 속기 쉬운 패턴 — 화면이 좁아 @ 뒤가 잘림.
    # 출처: [RFC3986] §3.2.1 userinfo 정의. 본래 의도는 ftp://user@host
    #       같은 인증 정보 전달이지만 HTTP(S) 에서는 사칭 도구로 악용.
    #       현대 브라우저는 경고하나 신뢰성은 사용자의 주의력에 의존.
    "userinfo_injection":     35,

    # 등록 도메인이 알려진 표적 도메인(naver.com 등)의 편집 거리 1~2 변형.
    # 예: naverr.com, navver.com, k4kao.com, kkakao.com, hometax.go.kr →
    #     hometex.go.kr
    # ANL-06 — v0513 까지 미구현이었던 핵심 시그널. domain_similarity.py
    # 모듈에서 Levenshtein 으로 탐지.
    # 출처: [KrCERT-CTI] lookalike domain, [APWG] brand impersonation
    #       리포트에서 매년 주요 위협 유형으로 분류.
    "typosquat_levenshtein":  35,

    # 같은 URL 에 대해 사용자 'danger' 투표가 10건 이상이고 'safe' 보다 많음.
    # 본 앱의 핵심 차별화 — KISA C-TAS 가 못 잡은 신규 위협을 사용자 집단지성
    # 으로 발견하는 피드백 순환 (7-A 직접 탐방 + 투표).
    # 어그로 방어 4중(DC-35)으로 진실성 보호:
    #   Layer 1: DB UNIQUE(device_uuid, registered_domain) - 1기기 1표
    #   Layer 2: 본 코드 — safe_count > danger_count 시 미발동
    #   Layer 3: 7-A 세션 30초 체류 + (CDP 시) navigation 1회 이상
    #   Layer 4: 가중치 35로 제한 — 단독 DANGER 불가
    # 출처: [본 앱-SRS] DC-30 / ANL-10.
    "prior_danger_vote_high": 35,


    # ─────────────────────────────────────────────────────────────────────────
    # 강신호 (+30 ~ +40) — 단독으론 SUSPICIOUS, 다른 약/중 시그널과 결합 시 DANGER
    # ─────────────────────────────────────────────────────────────────────────

    # 서브도메인 부분에 유명 TLD 가 포함된 도메인 위장.
    # 예: naver.com.evil.kr
    #     hostname='naver.com.evil.kr', registered='evil.kr'
    #     subdomain_part='naver.com' → 'com' 발견 → 위장
    # 모바일 브라우저 주소창에서 'naver.com.' 까지만 보이게 만드는 수법.
    # 출처: [KrCERT-Smi] / [APWG] eCrime Trends — 모바일 환경에서 가장
    #       치명적인 도메인 위장 패턴으로 다년간 보고.
    "subdomain_spoofing":     30,

    # 호스트명에 비ASCII Unicode 혼동 문자(키릴 а, 그리스 ο 등) 포함.
    # 예: nаver.com  (а 는 키릴 문자 U+0430, 라틴 a 와 시각적 동일)
    # 사람 눈에는 정상 도메인과 구별 불가.
    # v0527: 25 → 30 상향 (이전 가중치로는 신생 도메인+무기록 결합해도 65점
    #        으로 임계값 가까스로 미달).
    # 출처: [UTS39] Unicode 보안 권고, [KISA-IDN] 동형이의자 공격 분석.
    "homograph_idn":          30,

    # 7-B AI 자동 테스트가 이전에 sandbox_score ≥ 70 을 기록한 URL.
    # 의미: Playwright 가 실제로 페이지를 렌더링하고 가짜 개인정보를 폼에
    #       제출했을 때 피싱 폼이 그 정보를 수집했다는 능동 증거.
    # 본 앱이 갖춘 가장 강력한 단일 시그널 — 정적 휴리스틱은 추측이지만
    # 샌드박스는 실증.
    # v0527: 30 → 40 상향. 능동 탐지의 권위에 비해 이전 가중치가 낮았음.
    #        +40 으로 두면 sandbox_score + 어떤 중신호(+20) 만으로 DANGER 60
    #        + 약신호 1개 추가하면 DANGER 도달 가능.
    # 출처: [본 앱-SRS] ANL-11.
    "sandbox_danger_score":   40,


    # ─────────────────────────────────────────────────────────────────────────
    # 중신호 (+20) — 단독으론 SUSPICIOUS, 2~3개 결합 시 DANGER
    # ─────────────────────────────────────────────────────────────────────────

    # 브랜드 키워드(naver/kakao/toss 등)가 호스트명에 있으나 등록 도메인이
    # 해당 브랜드 공식 도메인이 아님.
    # 예: kakao-event.click → 'kakao' 키워드 있으나 등록='kakao-event.click'
    #     이 도메인은 kakao.com 공식 도메인이 아님 → 사칭.
    # 단어 경계 정규식(\b)으로 'okb' → 'kb' 오탐 방지.
    # 출처: [APWG] brand impersonation, [KrCERT-Smi] 금융기관 사칭 패턴.
    "brand_keyword_mismatch": 20,

    # 도메인이 30일 이내에 등록됨 (WHOIS creation_date 기반).
    # 피싱 캠페인은 신고 → 차단 → 폐기 주기가 짧아 단기 도메인을 매번 새로
    # 등록해 사용. 정상 신생 사이트도 있어 단독 사용 시 오탐 — 다른 시그널
    # 과 결합 평가가 핵심.
    # 출처: [KrCERT-Smi] 침해 도메인 평균 생존 기간 통계 (수일 ~ 수주).
    #       Google Safe Browsing 도 '신생 도메인'을 공개 시그널로 다룸.
    "new_domain":             20,

    # WHOIS 조회가 NO_MATCH 또는 응답 없음.
    # 익명 등록 또는 privacy proxy 서비스 사용. 침해사고 추적 회피 의도.
    # 단, 일부 정상 도메인도 privacy proxy 를 쓰므로 단독 신호로 약함.
    # 출처: [APWG], [KrCERT-CTI] — 익명 WHOIS 의 피싱 도메인 비율 일관되게
    #       정상 도메인보다 높음.
    "whois_no_record":        20,

    # 같은 URL 에 대해 사용자 'danger' 투표 3~9건 + danger>safe.
    # high 단계(10건+) 보다 약한 신호. 신생 위협 도메인이 점진적으로 발견
    # 되는 초기 단계를 잡기 위한 중신호.
    # 출처: [본 앱-SRS] DC-30.
    "prior_danger_vote_low":  20,

    # 호스트명에 피싱 행위 키워드(login/verify/secure/account/update 등) 포함
    # 이고 화이트리스트 미히트.
    # 예: secure-naver-login.click, account-update.shop
    # 정상 사이트도 'login' 단어를 쓰지만 보통 path 에 두지 호스트명에 두지
    # 않음. 호스트명에 노출된 행위 키워드는 사칭 의도 가능성 ↑.
    # 출처: [KrCERT-Smi] 스미싱 URL 호스트 키워드 분석 — 'verify', 'secure',
    #       'login' 등이 상위.
    "suspicious_keywords":    20,


    # ─────────────────────────────────────────────────────────────────────────
    # 약신호 (+5 ~ +15) — 보조 신호. 단독 영향 미미, 누적 시 의미.
    # ─────────────────────────────────────────────────────────────────────────

    # URL 에 %25xx 패턴(이중 인코딩) 포함.
    # 예: %252F → %25 + %2F → 디코드 시 /
    # 보안 필터(WAF) 우회에 사용. 정상 사이트도 일부 사용하므로 약신호.
    # 출처: [OWASP-DE] Double Encoding 공격 카탈로그.
    #       [KISA-PDF-FD] 15절 파일 다운로드 항목의 '우회 방안 예시' 표에
    #       이중 URL 인코딩(.%252e, /%252f 등)이 명시되어 있음.
    "double_encoding":        15,

    # 서브도메인 3레벨 이상.
    # 예: api.subdomain1.subdomain2.example.shop → 서브도메인 부분 3레벨.
    # 모바일에서 실제 등록 도메인을 주소창 화면 밖으로 밀어내는 수법.
    # 정상 CDN/SaaS 도 다단계 서브도메인을 쓰므로 약신호.
    # 출처: [KrCERT-Smi] / Microsoft Defender SmartScreen 휴리스틱.
    "excessive_subdomains":   15,

    # 도메인 등록 + SSL 인증서 발급이 모두 30일 이내.
    # 단기 운영을 전제로 한 피싱 인프라 패턴. new_domain 과 다소 중복되나
    # SSL 신생까지 결합되면 단기 캠페인 가능성이 더 명확.
    # 출처: Cloudflare/Akamai 위협 인텔리전스 보고서.
    "fresh_infrastructure":   15,

    # 호스트명 어디든 'xn--' 접두 (Punycode 노출).
    # IDN 도메인을 ASCII 로 인코딩한 결과. 정상 한글 도메인(예: 한국.kr 의
    # ASCII 형태 xn--3e0b707e)도 있지만 휴대폰 주소창이 punycode 를 그대로
    # 보여줄 때 사용자가 의미를 파악 못 함 → 사칭 도구로 악용 가능.
    # 출처: [UTS39], [KISA-IDN].
    "punycode_in_url":        15,

    # 등록 도메인에 하이픈 3개 이상 (예: secure-bank-update-2026.com).
    # 정상 도메인은 보통 1~2개 하이픈. 다수 하이픈은 키워드 조합형 사칭
    # 도메인 다빈도 패턴.
    # 출처: [KrCERT-Smi] 스미싱 도메인 통계 — 다중 하이픈 비율 정상 대비 ↑.
    "many_hyphens":           10,

    # 등록 도메인 TLD 가 피싱 다빈도 TLD (.xyz, .top, .click, .shop 등).
    # 저렴한 대량 구매 가능 + 등록 절차 단순 → 피싱 사이트가 즐겨 사용.
    # 정상 신규 비즈니스도 사용하므로 약신호로 유지.
    # 출처: Interisle "Phishing Landscape" 연례 보고서, Spamhaus TLD abuse
    #       통계.
    "suspicious_tld":         10,

    # URL 에 비표준 포트 명시 (예: :8080, :8443).
    # 정상 웹은 80/443. 비표준 포트는 우회 운영 또는 임시 노출 인프라
    # 가능성. 사내 서비스도 사용하므로 약신호.
    # 출처: [RFC3986] 비표준 포트 사용 사례, Cisco Talos URL reputation.
    "port_in_url":            10,

    # 같은 URL 에 대해 사용자 'spam' 투표 10건 이상 + spam>safe.
    # 위협은 아니지만 광고·홍보성 페이지로 사용자 경고용. 단독 발동 시
    # SUSPICIOUS 임계값(30)에 도달하지 않도록 +10 으로 제한.
    # 출처: [본 앱-SRS] DC-30 확장 — vote 종류 'safe/danger/spam/unsure'.
    "prior_spam_vote_high":   10,

    # URL 전체 길이 100자 초과.
    # 파라미터 난수화·경로 위장에 사용되는 긴 URL 패턴.
    # 정상 URL 도 길어질 수 있으므로 가장 약한 신호.
    # 출처: [PhishStorm] 논문의 URL 길이 통계 분포 분석.
    "url_too_long":            5,

    # spam 투표 3~9건 + spam>safe.
    # spam_high(+10) 보다 약한 단계.
    "prior_spam_vote_low":     5,


    # ─────────────────────────────────────────────────────────────────────────
    # 음의 시그널 — 사용자 검증으로 톤 완화. DC-06 보호: 합산 후 0 클램프.
    # ─────────────────────────────────────────────────────────────────────────
    #
    # 도입 배경:
    #   v0527 이전에는 사용자 'safe' 투표가 점수에 영향을 주지 못함. 결과:
    #   정상 신생 사이트(예: 동네 빵집 my-bakery.shop)가 신생도메인(+20)·
    #   suspicious_tld(+10)·whois_no_record(+20) 로 50점 SUSPICIOUS 에 고정.
    #   사용자 10명이 안전 투표를 해도 경고가 그대로 떠 있어 UX 저하.
    #
    # DC-06 위반 방지 메커니즘:
    #   - 음수 점수가 나와도 score = max(0, score) 로 0 클램프
    #   - 화이트리스트 히트만 SAFE 판정 가능 (analysis_service 가 강제)
    #   - 즉 본 신호는 'SAFE 로의 승격'이 아닌 '경고 톤 완화' 효과만
    #
    # 출처: [본 앱-SRS] v0527 확장 — 정상 신생 사이트 UX 개선.

    # safe 투표 10건 이상 + safe>danger.
    "prior_safe_vote_high":  -15,

    # safe 투표 3~9건 + safe>danger.
    "prior_safe_vote_low":    -5,
}


# =============================================================================
# 탐지 기준 상수
# =============================================================================

# 위험 파일 확장자.
# 출처: [KrCERT-Smi] .apk 직링크 1순위, [KISA-PDF-FU] 14절에서 .exe/.bat/.dll
#       등을 악성 콘텐츠로 명시.
_DANGEROUS_EXTENSIONS: frozenset[str] = frozenset({
    ".apk", ".exe", ".bat", ".cmd", ".scr",
    ".vbs", ".ps1", ".jar", ".msi", ".dmg",
})

# 피싱에 자주 사용되는 저가 TLD.
# 출처: Interisle "Phishing Landscape" 연례 보고서 (.xyz/.top/.click 다빈도).
_SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    ".xyz", ".top", ".club", ".shop", ".site", ".online",
    ".live", ".click", ".link", ".store", ".cyou", ".icu",
    ".uno", ".sbs", ".mom", ".lol", ".bar", ".pw", ".fun",
    ".world", ".space", ".website", ".stream", ".press",
})

# 서브도메인 위장 탐지용: 유명 TLD 가 서브도메인 레벨에 끼어 있는 경우.
_COMMON_TLDS_IN_SUBDOMAINS: frozenset[str] = frozenset({
    "com", "net", "org", "co", "kr", "jp", "us",
})

# 피싱 호스트명에 자주 나타나는 행위 키워드.
# 정상 사이트도 path 에는 자주 쓰지만 호스트명에 등장하는 경우는 사칭 의도가
# 높음.
# 출처: [KrCERT-Smi] 스미싱 URL 호스트 키워드 분석.
_PHISHING_ACTION_KEYWORDS: frozenset[str] = frozenset({
    "login", "signin", "logon",
    "verify", "verification", "confirm",
    "secure", "security", "auth",
    "account", "update", "password", "passwd",
    "banking", "wallet", "billing", "payment",
})

# 사칭 빈도 높은 브랜드 키워드.
# 단어 경계 매칭으로 'kb' → 'okb' 오탐 방지.
# 출처: [KrCERT-Smi] 사칭 표적 1순위 군 + [APWG] brand impersonation.
_BRAND_KEYWORDS: list[str] = [
    # 포털·메신저
    "naver", "kakao", "daum",
    # 금융
    "toss", "kbank",
    "shinhan", "woori", "hana", "ibk", "keb",
    # 커머스
    "coupang", "baemin", "gmarket",
    # 글로벌
    "paypal", "samsung", "apple", "google", "microsoft", "amazon", "netflix",
    # 정부·공공 (스미싱 사칭 최다)
    "nhis",      # 국민건강보험
    "hometax", "wetax", "irs",   # 국세청·지방세
]

# 각 브랜드의 공식 등록 도메인 (부분 일치 허용).
# 키워드는 _BRAND_KEYWORDS 와 1:1 매핑.
_BRAND_OFFICIAL_DOMAINS: dict[str, frozenset[str]] = {
    "naver":     frozenset({"naver.com", "naver.net", "navercorp.com"}),
    "kakao":     frozenset({"kakao.com", "kakaobank.com", "kakaopay.com", "daum.net"}),
    "daum":      frozenset({"daum.net", "kakao.com"}),
    "toss":      frozenset({"toss.im", "toss.securities", "viva.com"}),
    "kbank":     frozenset({"kbanknow.com"}),
    "shinhan":   frozenset({"shinhan.com", "shinhancard.com", "shinhanlife.co.kr"}),
    "woori":     frozenset({"wooribank.com", "wooricard.com"}),
    "hana":      frozenset({"hanabank.com", "hanacard.co.kr", "kebhana.com"}),
    "ibk":       frozenset({"ibk.co.kr"}),
    "keb":       frozenset({"kebhana.com"}),
    "coupang":   frozenset({"coupang.com"}),
    "baemin":    frozenset({"baemin.com", "baedalui.com"}),
    "gmarket":   frozenset({"gmarket.co.kr"}),
    "paypal":    frozenset({"paypal.com"}),
    "samsung":   frozenset({"samsung.com", "samsung.co.kr"}),
    "apple":     frozenset({"apple.com"}),
    "google":    frozenset({"google.com", "googleapis.com", "gstatic.com"}),
    "microsoft": frozenset({"microsoft.com", "microsoftonline.com", "live.com"}),
    "amazon":    frozenset({"amazon.com", "amazonaws.com", "amazon.co.kr"}),
    "netflix":   frozenset({"netflix.com"}),
    "nhis":      frozenset({"nhis.or.kr"}),
    "hometax":   frozenset({"hometax.go.kr"}),
    "wetax":     frozenset({"wetax.go.kr"}),
    "irs":       frozenset({"irs.gov"}),
}


# =============================================================================
# 결과 타입
# =============================================================================

@dataclass
class HeuristicResult:
    """
    score_url() 반환 타입.

    score:     합산 점수 (0 이상 클램프 적용. 상한 없음)
    verdict:   'DANGER' | 'SUSPICIOUS' | 'SAFE'
    triggered: 발화된 시그널 → 기여 점수 딕셔너리 (음수 포함)
               설명 카드 생성(explanation_service) 및 로그·통계용.
    """
    score:     int
    verdict:   str
    triggered: dict[str, int] = field(default_factory=dict)


# =============================================================================
# 내부 시그널 함수 — 각각 순수 함수 (side-effect 없음)
# =============================================================================

def _signal_ip_in_url(hostname: str) -> bool:
    """호스트가 IPv4/IPv6 주소인지."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _signal_subdomain_spoofing(hostname: str, registered_domain: str | None) -> bool:
    """
    서브도메인 부분에 유명 TLD 가 끼어 있는 도메인 위장.

    예: naver.com.evil.kr
        hostname='naver.com.evil.kr', registered_domain='evil.kr'
        subdomain_part='naver.com' → parts=['naver', 'com']
        'com' ∈ _COMMON_TLDS_IN_SUBDOMAINS → True
    """
    if not registered_domain:
        return False
    if not hostname.endswith("." + registered_domain):
        return False
    subdomain_part = hostname[: -(len(registered_domain) + 1)]
    if not subdomain_part:
        return False
    parts = subdomain_part.split(".")
    return any(p in _COMMON_TLDS_IN_SUBDOMAINS for p in parts)


def _signal_brand_keyword_mismatch(hostname: str, registered_domain: str | None) -> bool:
    """
    브랜드 키워드가 호스트명에 있으나 등록 도메인이 해당 브랜드 공식 도메인이 아님.
    """
    host_lower = hostname.lower()
    rd = (registered_domain or "").lower()

    for keyword in _BRAND_KEYWORDS:
        # 단어 경계 매칭으로 'kb' → 'okb' 오탐 방지
        pattern = r"(?<![a-z0-9])" + re.escape(keyword) + r"(?![a-z0-9])"
        if not re.search(pattern, host_lower):
            continue
        official = _BRAND_OFFICIAL_DOMAINS.get(keyword, frozenset())
        if official and rd not in official:
            return True
    return False


def _signal_homograph(hostname: str) -> bool:
    """호스트명에 비ASCII Unicode 문자 포함 — homograph 공격 의심."""
    _, is_idn = normalize_idn_hostname(hostname)
    return is_idn


def _signal_dangerous_extension(path: str) -> bool:
    """URL 경로 끝이 위험 파일 확장자 (.apk/.exe 등)."""
    path_lower = path.lower().split("?")[0]
    return any(path_lower.endswith(ext) for ext in _DANGEROUS_EXTENSIONS)


def _signal_suspicious_tld(registered_domain: str | None) -> bool:
    """등록 도메인 TLD 가 피싱 다빈도 TLD."""
    if not registered_domain:
        return False
    parts = registered_domain.rsplit(".", 1)
    tld = f".{parts[1]}" if len(parts) == 2 else ""
    return tld in _SUSPICIOUS_TLDS


def _signal_excessive_subdomains(hostname: str, registered_domain: str | None) -> bool:
    """
    서브도메인 3레벨 이상.

    a.b.c.naver.com  → subdomain_part='a.b.c' (점 2개) → True
    a.b.naver.com    → subdomain_part='a.b'   (점 1개) → False
    login.naver.com  → subdomain_part='login' (점 0개) → False
    """
    if not registered_domain:
        # tldextract 폴백: 전체 파트 수로 보수적 판단 (5파트 이상 = 3+ 서브도메인)
        return hostname.count(".") >= 4
    if not hostname.endswith("." + registered_domain):
        return False
    subdomain_part = hostname[: -(len(registered_domain) + 1)]
    if not subdomain_part:
        return False
    return subdomain_part.count(".") >= 2


def _signal_port_in_url(netloc: str) -> bool:
    """netloc 에 비표준 포트 명시 (80/443 외)."""
    if ":" not in netloc:
        return False
    port_str = netloc.rsplit(":", 1)[-1]
    if not port_str.isdigit():
        return False
    port = int(port_str)
    return port not in (80, 443)


def _signal_suspicious_keywords(hostname: str) -> bool:
    """호스트명에 피싱 행위 키워드(login/verify/secure 등) 포함."""
    h = hostname.lower()
    for kw in _PHISHING_ACTION_KEYWORDS:
        # 단어 경계 — 'mylogin' 같은 부분일치 방지하지만 도메인은 보통 - · . 로 구분
        pattern = r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])"
        if re.search(pattern, h):
            return True
    return False


def _signal_punycode_in_url(hostname: str) -> bool:
    """호스트명에 xn-- Punycode 접두."""
    return any(part.startswith("xn--") for part in hostname.split("."))


def _signal_many_hyphens(registered_domain: str | None) -> bool:
    """등록 도메인에 하이픈 3개 이상."""
    if not registered_domain:
        return False
    return registered_domain.count("-") >= 3


# =============================================================================
# 공개 인터페이스
# =============================================================================

def score_url(
    url: str,
    domain_evidence: dict | None = None,
    vote_counts: dict | None = None,
    sandbox_score: int | None = None,
) -> HeuristicResult:
    """
    URL 에 대해 23종 시그널 가중합 점수를 계산한다.

    판정을 직접 내리지 않고 점수와 발화 시그널을 반환한다.
    판정(DANGER/SUSPICIOUS/SAFE)은 점수와 임계값 비교로 결정한다.
    음수 점수는 0 으로 클램프된다 (DC-06 보호).

    [url]:             분석 대상 URL (정규화 권장)
    [domain_evidence]: analyze_domain_reputation() 반환값 (선택)
    [vote_counts]:     get_vote_counts() 반환값 {safe/danger/spam/unsure: int}
    [sandbox_score]:   이전 7-B 자동탐지 sandbox_score (선택, ANL-11)
    반환값: HeuristicResult
    """
    triggered: dict[str, int] = {}

    # ── URL 파싱 ─────────────────────────────────────────────────────────────
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
    except Exception:
        logger.warning("[휴리스틱] URL 파싱 실패: %s", url)
        return HeuristicResult(score=0, verdict="SAFE", triggered={})

    # parsed.hostname: 포트·IPv6 괄호 자동 제거, 소문자 반환
    hostname     = (parsed.hostname or "").lower()
    netloc       = parsed.netloc.lower()
    path         = parsed.path or ""
    registered   = get_registered_domain(url)

    # ─────────────────────────────────────────────────────────────────────────
    # 정적 시그널 (URL 자체만으로 평가 — 외부 의존성 없음)
    # ─────────────────────────────────────────────────────────────────────────

    if _signal_ip_in_url(hostname):
        triggered["ip_in_url"] = _WEIGHTS["ip_in_url"]

    if _signal_dangerous_extension(path):
        triggered["dangerous_extension"] = _WEIGHTS["dangerous_extension"]

    if check_userinfo_injection(url):
        triggered["userinfo_injection"] = _WEIGHTS["userinfo_injection"]

    # 타이포스쿼팅 (Levenshtein) — domain_similarity 위임
    is_typo, _target, _dist = detect_typosquat(registered)
    if is_typo:
        triggered["typosquat_levenshtein"] = _WEIGHTS["typosquat_levenshtein"]

    if _signal_subdomain_spoofing(hostname, registered):
        triggered["subdomain_spoofing"] = _WEIGHTS["subdomain_spoofing"]

    if _signal_homograph(hostname):
        triggered["homograph_idn"] = _WEIGHTS["homograph_idn"]

    if _signal_brand_keyword_mismatch(hostname, registered):
        triggered["brand_keyword_mismatch"] = _WEIGHTS["brand_keyword_mismatch"]

    if _signal_suspicious_keywords(hostname):
        triggered["suspicious_keywords"] = _WEIGHTS["suspicious_keywords"]

    if has_double_encoding(url):
        triggered["double_encoding"] = _WEIGHTS["double_encoding"]

    if _signal_excessive_subdomains(hostname, registered):
        triggered["excessive_subdomains"] = _WEIGHTS["excessive_subdomains"]

    if _signal_punycode_in_url(hostname):
        triggered["punycode_in_url"] = _WEIGHTS["punycode_in_url"]

    if _signal_many_hyphens(registered):
        triggered["many_hyphens"] = _WEIGHTS["many_hyphens"]

    if _signal_suspicious_tld(registered):
        triggered["suspicious_tld"] = _WEIGHTS["suspicious_tld"]

    if _signal_port_in_url(netloc):
        triggered["port_in_url"] = _WEIGHTS["port_in_url"]

    if len(url) > 100:
        triggered["url_too_long"] = _WEIGHTS["url_too_long"]

    # ─────────────────────────────────────────────────────────────────────────
    # 도메인 평판 시그널 (외부 WHOIS/SSL 조회 결과 기반, 선택)
    # ─────────────────────────────────────────────────────────────────────────
    if domain_evidence and not domain_evidence.get("skipped"):
        if domain_evidence.get("new_domain"):
            triggered["new_domain"] = _WEIGHTS["new_domain"]
        if domain_evidence.get("fresh_infrastructure"):
            triggered["fresh_infrastructure"] = _WEIGHTS["fresh_infrastructure"]
        if domain_evidence.get("whois_no_record"):
            triggered["whois_no_record"] = _WEIGHTS["whois_no_record"]

    # ─────────────────────────────────────────────────────────────────────────
    # 사용자 투표 시그널 (피드백 순환 — 본 앱의 핵심 차별화)
    # ─────────────────────────────────────────────────────────────────────────
    # 어그로 방어 Layer 2 (우세 방향 가드) + Layer 5 (가입자 가중) 동시 적용.
    #
    #   우세 방향 (합계 기준):
    #     danger > safe → danger 시그널
    #     safe > danger → safe 시그널 (음의 가중치)
    #     spam > safe   → spam 시그널
    #
    #   가입자/익명 임계값 (Phase 2 — AUTH-01):
    #     prior_*_vote_high : anon_X ≥ 10  OR  user_X ≥ 3
    #     prior_*_vote_low  : anon_X ≥ 3   OR  user_X ≥ 1
    #     → 가입자 1 명 ≈ 익명 3~4 명 권위. 카카오 계정은 본인인증을 거친
    #       자연인이라 임시 UUID 100 개보다 신뢰도가 본질적으로 다르다.
    #
    # 'unsure' 카운트는 본 분기에서 사용하지 않음 (DB 슬롯도 점유 안 함).
    if vote_counts:
        # 합계 — 우세 방향 가드용. 후방 호환 키 (safe/danger/spam).
        danger_count = vote_counts.get("danger", 0)
        safe_count   = vote_counts.get("safe", 0)
        spam_count   = vote_counts.get("spam", 0)

        # 분리 카운트 — 새 임계값용. dict 에 없으면 0 fallback.
        anon_danger = vote_counts.get("anon_danger", 0)
        user_danger = vote_counts.get("user_danger", 0)
        anon_safe   = vote_counts.get("anon_safe",   0)
        user_safe   = vote_counts.get("user_safe",   0)
        anon_spam   = vote_counts.get("anon_spam",   0)
        user_spam   = vote_counts.get("user_spam",   0)

        # danger 우세 — 양의 시그널
        if danger_count > safe_count:
            if anon_danger >= 10 or user_danger >= 3:
                triggered["prior_danger_vote_high"] = _WEIGHTS["prior_danger_vote_high"]
            elif anon_danger >= 3 or user_danger >= 1:
                triggered["prior_danger_vote_low"] = _WEIGHTS["prior_danger_vote_low"]

        # safe 우세 — 음의 시그널 (정상 신생 사이트 톤 완화, v0527 신규)
        if safe_count > danger_count:
            if anon_safe >= 10 or user_safe >= 3:
                triggered["prior_safe_vote_high"] = _WEIGHTS["prior_safe_vote_high"]
            elif anon_safe >= 3 or user_safe >= 1:
                triggered["prior_safe_vote_low"] = _WEIGHTS["prior_safe_vote_low"]

        # spam 우세 — 보조 약신호
        if spam_count > safe_count:
            if anon_spam >= 10 or user_spam >= 3:
                triggered["prior_spam_vote_high"] = _WEIGHTS["prior_spam_vote_high"]
            elif anon_spam >= 3 or user_spam >= 1:
                triggered["prior_spam_vote_low"] = _WEIGHTS["prior_spam_vote_low"]

    # ─────────────────────────────────────────────────────────────────────────
    # 7-B 샌드박스 능동 탐지 시그널 (ANL-11)
    # ─────────────────────────────────────────────────────────────────────────
    if sandbox_score is not None and sandbox_score >= 70:
        triggered["sandbox_danger_score"] = _WEIGHTS["sandbox_danger_score"]

    # ─────────────────────────────────────────────────────────────────────────
    # 점수 합산 및 판정
    # ─────────────────────────────────────────────────────────────────────────
    raw_score = sum(triggered.values())

    # DC-06 보호: 음수 점수도 SAFE 를 만들지 못한다.
    # 음의 시그널(prior_safe_vote_*)이 적용돼도 화이트리스트 히트 없이는
    # SAFE 절대 금지. analysis_service 가 최종 판정을 강제하지만 본 모듈도
    # 0 클램프로 안전장치.
    score = max(0, raw_score)

    if score >= DANGER_THRESHOLD:
        verdict = "DANGER"
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    logger.info(
        "[휴리스틱] %s | raw=%d clamped=%d verdict=%s triggered=%s",
        registered or hostname, raw_score, score, verdict, list(triggered.keys()),
    )

    return HeuristicResult(score=score, verdict=verdict, triggered=triggered)
