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
    # 시그널 키는 heuristic_scorer._WEIGHTS 와 1:1 대응.
    # 각 시그널의 출처·근거는 heuristic_scorer.py 의 _WEIGHTS 인접 주석 참조.

    # IP 직접 접속 — 추적 회피 의도
    "ip_in_url": {
        "icon":  "🔢",
        "title": "IP 주소를 직접 사용한 링크",
        "desc":  (
            "정상 서비스는 도메인 주소를 사용합니다. "
            "IP 주소를 직접 쓰는 링크는 추적을 피하려는 의도일 수 있습니다."
        ),
    },

    # 서브도메인 부분에 유명 TLD 끼워넣기 위장
    "subdomain_spoofing": {
        "icon":  "🎭",
        "title": "도메인 위장 의심",
        "desc":  (
            "실제 주소는 다르지만 유명 사이트 주소처럼 보이게 만든 링크입니다. "
            "주소의 맨 마지막 부분(진짜 도메인)을 반드시 확인하세요."
        ),
    },

    # 브랜드 키워드 사칭 — 호스트명에 유명 브랜드명, 등록 도메인은 비공식
    "brand_keyword_mismatch": {
        "icon":  "⚠️",
        "title": "유명 브랜드·기관 사칭 의심",
        "desc":  (
            "링크에 유명 기업·기관 이름이 포함되어 있지만 "
            "실제 공식 도메인과 다릅니다."
        ),
    },

    # IDN 동형이의자 공격 — 비ASCII 혼동 문자
    "homograph_idn": {
        "icon":  "🔤",
        "title": "시각적으로 유사한 가짜 주소",
        "desc":  (
            "영문자처럼 보이는 다른 언어 문자를 사용해 "
            "진짜 주소로 착각하게 만드는 수법입니다."
        ),
    },

    # 이중 URL 인코딩 — WAF 우회 기법
    "double_encoding": {
        "icon":  "🔃",
        "title": "이중 인코딩된 URL",
        "desc":  (
            "URL이 여러 번 인코딩되어 있습니다. "
            "보안 필터 우회에 자주 사용되는 기법입니다."
        ),
    },

    # 악성 파일 직링크 (.apk/.exe 등) — 한국 스미싱 1순위 패턴
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

    # 과다 서브도메인 — 모바일에서 실제 도메인을 화면 밖으로 밀어내는 수법
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

    # URL 100자 초과 — 파라미터 난수화·경로 위장 패턴
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

    # 7-B 샌드박스 점수 시그널 (ANL-11)
    "sandbox_danger_score": {
        "icon":  "🧪",
        "title": "가상 환경 분석에서 위험으로 판정",
        "desc":  (
            "이 URL은 이전에 AI 자동 분석(가상 샌드박스)을 통해 "
            "높은 위험 점수(70점 이상)를 받은 이력이 있습니다."
        ),
    },

    # 사용자 투표 시그널
    "prior_danger_vote_high": {
        "icon":  "👥",
        "title": "다수 사용자가 위험으로 신고한 링크",
        "desc":  (
            "10명 이상의 이전 방문자가 이 링크를 위험하다고 평가했습니다. "
            "접속하지 않을 것을 강력히 권장합니다."
        ),
    },
    "prior_danger_vote_low": {
        "icon":  "👥",
        "title": "사용자 위험 신고 이력 있음",
        "desc":  (
            "이전 방문자 중 일부가 이 링크를 위험하다고 평가했습니다. "
            "접속에 주의하세요."
        ),
    },
    "prior_spam_vote_high": {
        "icon":  "📢",
        "title": "다수 사용자가 광고/스팸으로 신고",
        "desc":  (
            "10명 이상의 이전 방문자가 이 링크를 광고·스팸으로 평가했습니다. "
            "사기 위험은 낮을 수 있지만 마케팅성 페이지일 가능성이 큽니다."
        ),
    },
    "prior_spam_vote_low": {
        "icon":  "📢",
        "title": "광고/스팸 신고 이력 있음",
        "desc":  (
            "이전 방문자 중 일부가 이 링크를 광고·스팸으로 평가했습니다."
        ),
    },

    # 사용자 안전 검증 시그널 (v0527 신규, 음의 가중치 — 톤 완화용)
    "prior_safe_vote_high": {
        "icon":  "🛡️",
        "title": "다수 사용자가 안전 확인",
        "desc":  (
            "10명 이상의 이전 방문자가 이 링크를 안전하다고 평가했습니다. "
            "다만 본 앱은 화이트리스트 확인 없이는 SAFE 판정을 내리지 않습니다."
        ),
    },
    "prior_safe_vote_low": {
        "icon":  "🛡️",
        "title": "사용자 안전 평가 이력",
        "desc":  (
            "이전 방문자 중 일부가 이 링크를 안전하다고 평가했습니다."
        ),
    },

    # ── v0527 신규 시그널 ─────────────────────────────────────────────────

    # @ userinfo 인젝션 — RFC3986 userinfo 악용
    "userinfo_injection": {
        "icon":  "🎯",
        "title": "주소에 '@' 가 포함된 위장 링크",
        "desc":  (
            "주소 안에 '@' 기호가 있어 실제 접속 도메인이 표시된 것과 다를 수 "
            "있습니다. 예: 'naver.com@evil.kr' 는 실제로 evil.kr 로 접속됩니다. "
            "모바일에서 가장 속기 쉬운 사칭 패턴입니다."
        ),
    },

    # 타이포스쿼팅 — 1~2글자 변형 도메인
    "typosquat_levenshtein": {
        "icon":  "🔍",
        "title": "유명 사이트와 비슷한 가짜 주소",
        "desc":  (
            "주소가 잘 알려진 사이트(예: naver.com, kakao.com)와 1~2글자만 "
            "다릅니다. 오타를 노린 사칭 도메인일 가능성이 높습니다."
        ),
    },

    # 호스트명에 피싱 행위 키워드 (login/verify/secure 등)
    "suspicious_keywords": {
        "icon":  "🪤",
        "title": "주소에 의심 키워드 포함",
        "desc":  (
            "주소에 'login', 'verify', 'secure', 'account' 같은 단어가 호스트 "
            "이름에 포함되어 있습니다. 정상 사이트는 보통 이런 단어를 주소 "
            "본체보다는 경로(URL 뒷부분)에 둡니다."
        ),
    },

    # Punycode (xn--) 노출
    "punycode_in_url": {
        "icon":  "🔡",
        "title": "Punycode 형식 주소",
        "desc":  (
            "주소에 'xn--' 로 시작하는 부분이 있습니다. 한글·외국어 도메인을 "
            "ASCII 로 변환한 표기인데, 사칭에 악용되기도 합니다. 원래 도메인을 "
            "확인하세요."
        ),
    },

    # 도메인 하이픈 3개 이상
    "many_hyphens": {
        "icon":  "➖",
        "title": "도메인에 하이픈 다수",
        "desc":  (
            "주소 본체에 하이픈(-)이 여러 개 포함되어 있습니다. 정상 도메인은 "
            "보통 1~2개 이내인데 비해, 키워드를 조합한 사칭 도메인이 다수 "
            "하이픈을 사용하는 패턴이 자주 관찰됩니다."
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
