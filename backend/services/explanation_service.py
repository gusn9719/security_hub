# =============================================================================
# backend/services/explanation_service.py
# 역할: 시그널 → 설명 카드 변환 (Gemini /analyze 호출 대체, DC-25)
#
# 설계 원칙:
#   - 외부 API 호출 없음. 로컬 딕셔너리 기반.
#   - 모든 함수는 순수함수.
#   - 카드 형식: {"icon": str, "title": str, "desc": str}
#   - 구버전 AnalyzeResponse.description(str) 호환을 위해 cards_to_text() 제공.
# =============================================================================

# =============================================================================
# 설명 카드 사전
# 키 = 시그널 이름 (heuristic_scorer.triggered / 특수 판정 키)
# =============================================================================

EXPLANATION_DICT: dict[str, dict] = {
    # ── 블랙리스트 판정 ────────────────────────────────────────────────────
    "blacklist_hit": {
        "icon":  "🚫",
        "title": "악성 URL 데이터베이스에 등록된 주소",
        "desc":  (
            "금융보안원 C-TAS에 실제 피해가 신고된 악성 URL입니다. "
            "절대 접속하지 마세요."
        ),
    },

    # ── 위험 스킴 ─────────────────────────────────────────────────────────
    "dangerous_scheme": {
        "icon":  "💀",
        "title": "위험한 링크 형식",
        "desc":  (
            "일반 웹 주소(http/https)가 아닌 위험한 형식의 링크입니다. "
            "스크립트 실행이나 파일 접근에 악용됩니다."
        ),
    },

    # ── 화이트리스트 판정 ──────────────────────────────────────────────────
    "safe": {
        "icon":  "✅",
        "title": "검증된 안전 도메인",
        "desc":  "공식 확인된 화이트리스트 도메인입니다.",
    },
    "high_risk_brand": {
        "icon":  "🏦",
        "title": "사칭 빈도가 높은 기관",
        "desc":  (
            "이 기관은 스미싱 사칭 빈도가 매우 높습니다. "
            "도메인 철자를 한 번 더 확인하세요."
        ),
    },

    # ── 휴리스틱 시그널 ───────────────────────────────────────────────────

    # SI 항목
    "ip_in_url": {
        "icon":  "🔢",
        "title": "IP 주소를 직접 사용한 링크",
        "desc":  (
            "정상 서비스는 도메인 주소를 사용합니다. "
            "IP 주소를 직접 쓰는 링크는 추적을 피하려는 의도일 수 있습니다."
        ),
    },

    # WM 항목 — 서브도메인 위장
    "subdomain_spoofing": {
        "icon":  "🎭",
        "title": "도메인 위장 의심",
        "desc":  (
            "실제 주소는 다르지만 유명 사이트 주소처럼 보이게 만든 링크입니다. "
            "주소의 맨 마지막 부분(진짜 도메인)을 반드시 확인하세요."
        ),
    },

    # WM 항목 — 브랜드 키워드 사칭
    "brand_keyword_mismatch": {
        "icon":  "⚠️",
        "title": "유명 브랜드·기관 사칭 의심",
        "desc":  (
            "링크에 유명 기업·기관 이름이 포함되어 있지만 "
            "실제 공식 도메인과 다릅니다."
        ),
    },

    # SF 항목 — homograph
    "homograph_idn": {
        "icon":  "🔤",
        "title": "시각적으로 유사한 가짜 주소",
        "desc":  (
            "영문자처럼 보이는 다른 언어 문자를 사용해 "
            "진짜 주소로 착각하게 만드는 수법입니다."
        ),
    },

    # EP 항목 — 이중 인코딩
    "double_encoding": {
        "icon":  "🔃",
        "title": "이중 인코딩된 URL",
        "desc":  (
            "URL이 여러 번 인코딩되어 있습니다. "
            "보안 필터 우회에 자주 사용되는 기법입니다."
        ),
    },

    # FD 항목 — 위험 파일
    "dangerous_extension": {
        "icon":  "📦",
        "title": "악성 파일 다운로드 가능성",
        "desc":  (
            "링크에 앱 설치 파일(.apk) 또는 실행 파일이 포함되어 있습니다. "
            "클릭 시 악성 앱이 설치될 수 있습니다."
        ),
    },

    # 일반 — 피싱 다빈도 TLD
    "suspicious_tld": {
        "icon":  "🌐",
        "title": "피싱에 자주 사용되는 도메인 종류",
        "desc":  (
            "이 링크의 도메인 종류(.xyz, .top 등)는 "
            "스미싱·피싱 사이트에서 저렴하게 대량 구매해 사용하는 경우가 많습니다."
        ),
    },

    # IL 항목 — 과다 서브도메인
    "excessive_subdomains": {
        "icon":  "🌿",
        "title": "비정상적으로 복잡한 주소 구조",
        "desc":  (
            "정상 사이트는 단순한 주소를 사용합니다. "
            "여러 단계의 하위 주소는 실제 목적지를 감추려는 수법일 수 있습니다."
        ),
    },

    # 일반 — 비표준 포트
    "port_in_url": {
        "icon":  "🔌",
        "title": "비표준 포트 사용",
        "desc":  (
            "일반 웹사이트는 기본 포트(80/443)를 사용합니다. "
            "특수 포트 번호가 포함된 링크는 일반적이지 않습니다."
        ),
    },

    # IL 항목 — 긴 URL
    "url_too_long": {
        "icon":  "📏",
        "title": "비정상적으로 긴 URL",
        "desc":  (
            "정상 서비스는 간결한 주소를 사용합니다. "
            "지나치게 긴 URL은 실제 목적지를 숨기는 데 사용될 수 있습니다."
        ),
    },

    # 도메인 평판 시그널
    "new_domain": {
        "icon":  "🆕",
        "title": "최근 만들어진 도메인",
        "desc":  (
            "이 주소의 도메인은 최근 30일 이내에 등록되었습니다. "
            "피싱 사이트는 신고 후 빠르게 폐기되므로 단기 도메인을 주로 사용합니다."
        ),
    },
    "fresh_infrastructure": {
        "icon":  "⚡",
        "title": "단기 피싱 인프라 의심",
        "desc":  (
            "도메인과 SSL 인증서가 모두 최근에 만들어졌습니다. "
            "단기 피싱 사이트의 전형적인 패턴입니다."
        ),
    },
    "whois_no_record": {
        "icon":  "❓",
        "title": "도메인 등록 정보 없음",
        "desc":  (
            "이 도메인의 등록 정보를 확인할 수 없습니다. "
            "추적을 피하기 위해 정보를 숨기는 경우에 해당할 수 있습니다."
        ),
    },

    # 화이트리스트 Open Redirect
    "open_redirect": {
        "icon":  "🔀",
        "title": "외부 사이트 강제 이동 파라미터",
        "desc":  (
            "신뢰 도메인이지만 다른 사이트로 강제 이동시키는 "
            "파라미터가 URL에 포함되어 있습니다."
        ),
    },
}

# 판정별 기본 카드 (시그널이 없을 때 fallback)
_DEFAULT_CARDS: dict[str, dict] = {
    "DANGER": {
        "icon":  "🚨",
        "title": "위험한 링크입니다",
        "desc":  "여러 악성 지표가 동시에 감지되었습니다. 접속하지 마세요.",
    },
    "SUSPICIOUS": {
        "icon":  "🔍",
        "title": "의심스러운 링크입니다",
        "desc":  "분석 결과 이상 지표가 발견되었습니다. 접속에 주의하세요.",
    },
}


# =============================================================================
# 공개 인터페이스
# =============================================================================

def build_explanation_cards(
    triggered_signals: dict[str, int],
    verdict: str = "SUSPICIOUS",
    extra_keys: list[str] | None = None,
) -> list[dict]:
    """
    발화된 시그널 딕셔너리에서 설명 카드 리스트를 생성한다.

    카드 순서: triggered 점수 내림차순 → extra_keys → fallback(시그널 없을 때만).

    [triggered_signals]: heuristic_scorer.HeuristicResult.triggered
    [verdict]          : 'DANGER' | 'SUSPICIOUS' | 'SAFE'
    [extra_keys]       : 스코어 없이 추가할 시그널 키 (예: ['blacklist_hit', 'open_redirect'])
    반환값: 카드 딕셔너리 리스트
    """
    cards: list[dict] = []
    seen: set[str] = set()

    # 점수 높은 시그널 순으로 카드 추가
    for key in sorted(triggered_signals, key=lambda k: triggered_signals[k], reverse=True):
        card = EXPLANATION_DICT.get(key)
        if card and key not in seen:
            cards.append(card)
            seen.add(key)

    # 추가 키 (블랙리스트 히트, open_redirect 등)
    for key in (extra_keys or []):
        card = EXPLANATION_DICT.get(key)
        if card and key not in seen:
            cards.append(card)
            seen.add(key)

    # fallback: 발화 시그널이 없을 때 판정별 기본 카드
    if not cards and verdict in _DEFAULT_CARDS:
        cards.append(_DEFAULT_CARDS[verdict])

    return cards


def cards_to_text(cards: list[dict]) -> str:
    """
    설명 카드 리스트를 단일 텍스트 문자열로 변환한다.

    구버전 AnalyzeResponse.description(str) 호환용.
    Step 5 스키마 업데이트 후 제거 예정.

    [cards]: build_explanation_cards() 반환값
    반환값: 아이콘·제목·설명을 합친 멀티라인 텍스트
    """
    if not cards:
        return "분석 결과 이상이 발견되지 않았습니다."
    segments = []
    for card in cards:
        segments.append(f"{card['icon']} {card['title']}\n{card['desc']}")
    return "\n\n".join(segments)


def build_safe_cards(risk_level: str = "normal") -> list[dict]:
    """
    화이트리스트 SAFE 판정용 카드를 생성한다.

    [risk_level]: 'normal' | 'high_risk'
    반환값: 카드 리스트 (1~2개)
    """
    cards = [EXPLANATION_DICT["safe"]]
    if risk_level == "high_risk":
        cards.append(EXPLANATION_DICT["high_risk_brand"])
    return cards


def build_blacklist_cards(category: str | None = None) -> list[dict]:
    """
    블랙리스트 DANGER 판정용 카드를 생성한다.

    [category]: C-TAS 카테고리 ('공공기관', '택배', '금융', '기타')
    반환값: 카드 리스트
    """
    cards = [EXPLANATION_DICT["blacklist_hit"]]

    # 카테고리별 맥락 카드 추가
    category_hints: dict[str, dict] = {
        "공공기관": {
            "icon":  "🏛️",
            "title": "공공기관 사칭 스미싱",
            "desc":  (
                "건강보험공단·국세청·우체국 등 공공기관을 사칭한 문자입니다. "
                "공공기관은 문자로 앱 설치나 개인정보를 요구하지 않습니다."
            ),
        },
        "택배": {
            "icon":  "📬",
            "title": "택배 사칭 스미싱",
            "desc":  (
                "택배 배송 안내를 가장한 피싱 문자입니다. "
                "링크 클릭 시 개인정보 탈취 또는 악성앱 설치로 이어질 수 있습니다."
            ),
        },
        "금융": {
            "icon":  "💳",
            "title": "금융기관 사칭 스미싱",
            "desc":  (
                "은행·카드사·핀테크를 사칭한 문자입니다. "
                "금융기관은 문자로 계좌번호나 비밀번호를 요구하지 않습니다."
            ),
        },
    }
    hint = category_hints.get(category or "")
    if hint:
        cards.append(hint)

    return cards
