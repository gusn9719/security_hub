# =============================================================================
# backend/routers/test_phishing.py
# 역할: 7-B 자동탐지 테스트용 라우터
#   - HTTP 302 리다이렉트 체인 (redirect_count >= 3 트리거)
#   - /noop POST 엔드포인트 (폼 전송 더미)
# 주의: 개발/QA 전용. 프로덕션에서는 ENABLE_TEST_PHISHING=1 환경변수 없이 비활성화.
# =============================================================================

import os
from fastapi import APIRouter
from fastapi.responses import RedirectResponse, HTMLResponse

router = APIRouter(prefix="/test-phishing", tags=["test-phishing"])

_ENABLED = os.environ.get("ENABLE_TEST_PHISHING", "1").lower() not in ("0", "false", "no")


def _disabled():
    return HTMLResponse(
        content="<h3>테스트 페이지가 비활성화되어 있습니다 (ENABLE_TEST_PHISHING=0)</h3>",
        status_code=404,
    )


# ── 리다이렉트 체인 (302 × 3회 → 4_redirect_landing.html) ────────────────────
# Playwright _on_response 핸들러: status 302 마다 redirect_counter += 1
# start → step2 → step3 → step4 → 4_redirect_landing.html (302 × 4회, redirect_count=4 ≥ 3)

@router.get("/redirect/start")
async def redirect_start():
    if not _ENABLED:
        return _disabled()
    return RedirectResponse(url="/test-phishing/redirect/step2", status_code=302)


@router.get("/redirect/step2")
async def redirect_step2():
    if not _ENABLED:
        return _disabled()
    return RedirectResponse(url="/test-phishing/redirect/step3", status_code=302)


@router.get("/redirect/step3")
async def redirect_step3():
    if not _ENABLED:
        return _disabled()
    return RedirectResponse(url="/test-phishing/redirect/step4", status_code=302)


@router.get("/redirect/step4")
async def redirect_step4():
    if not _ENABLED:
        return _disabled()
    # 정적 파일로 최종 리다이렉트 (이 302는 redirect_counter에 포함되어 총 3회)
    return RedirectResponse(url="/test-phishing/4_redirect_landing.html", status_code=302)


# ── 폼 전송 더미 (1_password.html form action="/test-phishing/noop") ──────────
@router.post("/noop")
async def form_noop():
    return HTMLResponse(content="<html><body><p>OK (테스트용 더미 엔드포인트)</p></body></html>")
