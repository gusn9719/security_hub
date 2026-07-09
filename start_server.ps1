# =============================================================================
# start_server.ps1
# setup.ps1 을 먼저 1회 실행한 뒤 사용. 백엔드를 매번 켤 때 이 스크립트만 실행하면 됨.
# =============================================================================

$RepoRoot = $PSScriptRoot
$Python = Join-Path $RepoRoot "backend\venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    Write-Host "backend\venv 가 없습니다. 먼저 .\setup.ps1 을 실행하세요." -ForegroundColor Red
    exit 1
}

Set-Location (Join-Path $RepoRoot "backend")
& $Python -m uvicorn main:app --reload --port 8000
