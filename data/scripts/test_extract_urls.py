# =============================================================================
# backend/scripts/test_extract_urls.py
# 역할: extract_urls() 단위 테스트 (Sprint 5A 작업 1 검증)
# 실행:
#   $env:PYTHONPATH = "C:\dev\security_hub\backend"
#   python scripts/test_extract_urls.py
# =============================================================================

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from database.blacklist_service import extract_urls


CASES: list[tuple[str, list[str]]] = [
    # 시나리오 A — 프로토콜 없는 도메인
    (
        "[Web발신][정부24] 벌점통지서발송. gov.oe3m.me",
        ["https://gov.oe3m.me"],
    ),
    # 프로토콜 있는 단축 URL
    (
        "배송조회: https://bit.ly/abc123",
        ["https://bit.ly/abc123"],
    ),
    # 이메일 제외 + 프로토콜 없는 도메인
    (
        "문의: help@naver.com 또는 naver.com 방문",
        ["https://naver.com"],
    ),
    # 마침표만 있는 한글 문장
    (
        "안녕하세요.",
        [],
    ),
    # 추가: 프로토콜 + 비프로토콜 혼합
    (
        "공식: https://www.kbstar.com 사칭: kb-secure.xyz/login",
        ["https://www.kbstar.com", "https://kb-secure.xyz/login"],
    ),
    # 추가: 한글 인접 (re.ASCII 검증)
    (
        "[CU팡] 배송 실패. coupang-delivery.info/recheck",
        ["https://coupang-delivery.info/recheck"],
    ),
    # 추가: 알 수 없는 TLD는 제외
    (
        "더미 도메인 something.notatld 입니다",
        [],
    ),
]


def main() -> int:
    fail = 0
    for idx, (text, expected) in enumerate(CASES, 1):
        actual = extract_urls(text)
        ok = actual == expected
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] case {idx}")
        print(f"  input    : {text}")
        print(f"  expected : {expected}")
        print(f"  actual   : {actual}")
        if not ok:
            fail += 1
    print(f"\n총 {len(CASES)}건 중 {len(CASES) - fail}건 통과 / {fail}건 실패")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
