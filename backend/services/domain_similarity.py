# =============================================================================
# backend/services/domain_similarity.py
# 역할: 타이포스쿼팅(typosquatting) 탐지 — Levenshtein 편집 거리 기반
#       ANL-06 / v0513 §4 단계 5 신규 시그널.
#
# ─────────────────────────────────────────────────────────────────────────────
# 왜 필요한가
# ─────────────────────────────────────────────────────────────────────────────
# 휴리스틱 18종(이전 버전)으로는 'naverr.com', 'kakaoo.com', 'k4kao.com' 같이
# 1~2글자만 변형한 도메인을 어떤 시그널도 잡지 못한다.
#   - subdomain_spoofing: 서브도메인 패턴이 아님
#   - brand_keyword_mismatch: '\bnaver\b' 단어 경계 정규식이 'naverr'에는 미매칭
#   - homograph_idn:        ASCII 문자만 사용했으므로 IDN 아님
#   - new_domain/whois 등:  공격자가 오래된 도메인을 매입했다면 미발동
#
# 결과적으로 이전 휴리스틱에서 '편집 거리 1~2 변형 도메인' = 0점 = SUSPICIOUS 폴백.
# 우리 앱의 가장 자주 만나는 스미싱 패턴을 사실상 무방비로 통과시키는 구조였다.
#
# ─────────────────────────────────────────────────────────────────────────────
# 출처·근거
# ─────────────────────────────────────────────────────────────────────────────
# [KrCERT-CTI]  KrCERT/CC 사이버 위협 인텔리전스 보고서 — lookalike domain 분석
# [KrCERT-Smi]  KrCERT 스미싱 동향 분석 — 브랜드 사칭 도메인 패턴
# [APWG]        Anti-Phishing Working Group eCrime Trends Report
# [Edit-Dist]   Levenshtein, V.I. (1966) "Binary codes capable of correcting
#               deletions, insertions, and reversals" — 편집 거리 알고리즘
#
# 단, KISA 가이드 본책(주요정보통신기반시설 기술적 취약점 분석·평가 방법)은
# 서버측 자가취약점 점검표이므로 본 시그널은 직접 해당 항목이 없다.
# 대신 KISA 산하 KrCERT의 침해사고 분석·인텔리전스 보고서가 이 패턴을
# 매년 주요 스미싱 유형으로 다룬다.
#
# ─────────────────────────────────────────────────────────────────────────────
# 알고리즘 선택 이유
# ─────────────────────────────────────────────────────────────────────────────
# Levenshtein 편집 거리: 두 문자열 간 최소 편집 횟수(삽입·삭제·치환).
#   naver.com  → naverr.com   : 거리 1 (삽입)
#   naver.com  → naveer.com   : 거리 1 (삽입)
#   naver.com  → naver.con    : 거리 1 (치환 m→n)
#   kakao.com  → k4kao.com    : 거리 1 (치환 a→4)
#   naver.com  → navver.com   : 거리 1 (삽입)
#
# 임계 거리 d ∈ {1, 2}:
#   d=0: 동일 도메인 — 정상이므로 미발동
#   d=1: 99%가 타이포스쿼팅 의도 (오타 가능성도 있으나 위험성 동일)
#   d=2: 의도적 변형 다수 (k4ka00 등) — 검출 대상
#   d≥3: 무관 도메인일 가능성 ↑ — 미발동 (오탐 회피)
#
# 짧은 표적 도메인 보호:
#   대상 도메인 길이 < 6 글자 시 미발동.
#   'sk.com' 표적이면 'st.com'까지 거리 1이 되어 정상 도메인을 오탐.
#   기본 표적 도메인 목록은 모두 6글자 이상이지만 안전장치.
#
# 외부 라이브러리 미사용:
#   python-Levenshtein/rapidfuzz 같은 외부 의존성을 피하기 위해 순수 파이썬
#   동적계획법 구현. 표적 도메인 ~30개 × 길이 ~20글자 → 호출당 ~600 cell
#   계산 = 마이크로초 단위. requirements.txt 변경 없음.
#
# 변경 이력:
#   - v0527: 신규 작성 (ANL-06 미구현 해소)
# =============================================================================

import logging

logger = logging.getLogger(__name__)


# =============================================================================
# 표적 도메인 — 사칭 빈도가 높은 공식 도메인 목록
# =============================================================================
# 본 목록은 heuristic_scorer._BRAND_OFFICIAL_DOMAINS 와 의도적으로 분리한다.
# 분리 이유:
#   - heuristic_scorer 의 _BRAND_OFFICIAL_DOMAINS 는 '브랜드 키워드 + 비공식
#     도메인' 매칭을 위한 인덱스(브랜드 키워드 → 공식 도메인 집합)
#   - 본 모듈은 '편집 거리 1~2 변형'을 잡으므로 평면 도메인 리스트만 필요
#
# 출처: KrCERT 스미싱 동향 분석에서 사칭 1순위 군 + 한국인터넷진흥원 피싱
#       신고센터 통계 상위 도메인.
# 단, KISA 가이드 본책은 사칭 표적 명단을 제공하지 않으므로 본 목록은
# 보조 출처(언론·KrCERT 산발 발표)를 종합한 졸업작품 자체 큐레이션.
_TARGET_DOMAINS: tuple[str, ...] = (
    # 포털·메신저
    "naver.com", "navercorp.com",
    "kakao.com", "kakaobank.com", "kakaopay.com",
    "daum.net",
    # 금융
    "toss.im",
    "kbanknow.com",
    "shinhan.com", "shinhancard.com",
    "wooribank.com", "wooricard.com",
    "hanabank.com", "kebhana.com",
    "ibk.co.kr",
    # 커머스·배달
    "coupang.com",
    "baemin.com",
    "gmarket.co.kr",
    # 글로벌
    "paypal.com",
    "samsung.com",
    "apple.com",
    "google.com",
    "microsoft.com",
    "amazon.com",
    "netflix.com",
    # 정부·공공 (스미싱 사칭 최다)
    "nhis.or.kr",       # 국민건강보험
    "hometax.go.kr",    # 국세청
    "wetax.go.kr",      # 지방세
    "epost.go.kr",      # 우정사업본부 (택배 스미싱 사칭)
    "kt.com",           # KT (통신사 사칭)
    "skt.com", "sktelecom.com",
    "lguplus.com",
)


# 짧은 도메인은 거리 1로도 정상 도메인이 오탐될 위험이 큼 → 최소 길이 보호.
_MIN_TARGET_LENGTH: int = 6


# =============================================================================
# 편집 거리 — Levenshtein (pure Python)
# =============================================================================

def _levenshtein(a: str, b: str) -> int:
    """
    두 문자열의 Levenshtein 편집 거리.

    동적계획법 O(len(a) × len(b)). 우리 사용 케이스(도메인 vs 표적)는
    모두 길이 ≤ 30 이므로 호출당 1ms 미만.

    [a], [b]: 비교할 문자열 (소문자 권장)
    반환값:    최소 편집(삽입·삭제·치환) 횟수
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    # 1차원 롤링 배열로 메모리 절약
    prev: list[int] = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr: list[int] = [i + 1]
        for j, cb in enumerate(b):
            insert_cost = curr[j] + 1
            delete_cost = prev[j + 1] + 1
            replace_cost = prev[j] + (0 if ca == cb else 1)
            curr.append(min(insert_cost, delete_cost, replace_cost))
        prev = curr
    return prev[-1]


# =============================================================================
# 공개 인터페이스
# =============================================================================

def detect_typosquat(
    registered_domain: str | None,
    max_distance: int = 2,
) -> tuple[bool, str | None, int]:
    """
    등록 도메인이 알려진 표적 도메인의 편집 거리 1~max_distance 변형인지 검사.

    탐지 조건:
        1. registered_domain 이 표적 도메인과 정확히 일치 → 미발동 (정상)
        2. 표적 도메인 길이 ≥ _MIN_TARGET_LENGTH (짧은 도메인 오탐 보호)
        3. 편집 거리 1 ≤ d ≤ max_distance

    [registered_domain]: tldextract 로 얻은 등록 도메인 ('naverr.com')
    [max_distance]:      허용 최대 편집 거리 (기본 2)
    반환값: (is_typosquat, target_domain, distance)
            is_typosquat=False 인 경우 target/distance 는 None/0
    """
    if not registered_domain:
        return (False, None, 0)

    rd = registered_domain.lower().strip()
    if not rd:
        return (False, None, 0)

    # 표적 도메인과 정확히 같으면 정상 — 미발동
    if rd in _TARGET_DOMAINS:
        return (False, None, 0)

    # 가장 가까운 표적 도메인을 찾는다 (탐지 시에는 거리 작은 것 우선)
    best_target: str | None = None
    best_distance: int = max_distance + 1

    for target in _TARGET_DOMAINS:
        # 짧은 표적은 거리 1로도 정상 도메인이 오탐될 위험 → 건너뜀
        if len(target) < _MIN_TARGET_LENGTH:
            continue

        # 길이 차이가 max_distance 보다 크면 편집 거리도 그보다 큼 — 조기 종료
        if abs(len(rd) - len(target)) > max_distance:
            continue

        d = _levenshtein(rd, target)
        if 1 <= d <= max_distance and d < best_distance:
            best_target = target
            best_distance = d
            if d == 1:
                # 거리 1 발견 시 더 좋아질 수 없음 — 조기 종료
                break

    if best_target is None:
        return (False, None, 0)

    logger.info(
        "[타이포스쿼팅] %s → 표적 '%s' 와 편집거리 %d",
        rd, best_target, best_distance,
    )
    return (True, best_target, best_distance)
