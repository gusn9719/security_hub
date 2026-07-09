# =============================================================================
# setup.ps1
# 신규 PC에서 최초 1회만 실행. 이후엔 start_server.ps1 로 서버만 켜면 됨.
#
# 수행 작업:
#   1. backend/venv 생성 + 패키지 설치
#   2. backend/.env 없으면 .env.example 복사 + JWT_SECRET 자동 생성
#   3. GitHub Release(dev-v260701)에서 C-TAS/화이트리스트 CSV 다운로드
#   4. DB 마이그레이션 + 블랙리스트/화이트리스트 적재
#
# 재실행해도 안전 (이미 있는 단계는 건너뜀).
# =============================================================================

$ErrorActionPreference = "Stop"
$RepoRoot = $PSScriptRoot

Write-Host "=== 1. 백엔드 venv + 패키지 설치 ===" -ForegroundColor Cyan
$VenvDir = Join-Path $RepoRoot "backend\venv"
if (-not (Test-Path $VenvDir)) {
    python -m venv $VenvDir
}
$Pip = Join-Path $VenvDir "Scripts\pip.exe"
& $Pip install -r (Join-Path $RepoRoot "backend\requirements.txt")

Write-Host "`n=== 2. backend/.env 준비 ===" -ForegroundColor Cyan
$EnvFile = Join-Path $RepoRoot "backend\.env"
$EnvExample = Join-Path $RepoRoot "backend\.env.example"
if (-not (Test-Path $EnvFile)) {
    Copy-Item $EnvExample $EnvFile
    Write-Host "backend\.env 생성 완료 (.env.example 복사)"
}

# JWT_SECRET 이 비어있으면 자동 생성해서 채워넣는다.
# 로그인 기능을 안 쓰면 이 값은 서버 기동을 막지 않지만, 카카오 로그인 테스트 시엔
# 32자 이상이 필요하다 (RFC 7518 §3.2). 값이 서로 달라도 상관없어 자동 생성해도 무방.
#
# Get-Content/Set-Content 를 인코딩 지정 없이 쓰면 Windows PowerShell 5.1은 시스템
# ANSI 코드페이지(cp949 등)로 읽고 써서 .env.example 의 한글 주석이 깨지고, 그 결과
# python-dotenv 가 UnicodeDecodeError 를 낸다. .NET File I/O 로 UTF-8(BOM 없이)을
# 명시해 PowerShell 버전/시스템 로케일과 무관하게 안전하게 만든다.
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$envContent = [System.IO.File]::ReadAllText($EnvFile, $Utf8NoBom)
if ($envContent -match '(?m)^JWT_SECRET=\s*$') {
    # RandomNumberGenerator]::Fill 은 .NET Core/5+ 전용이라 Windows PowerShell 5.1
    # (.NET Framework, setup.bat 이 호출하는 powershell.exe)에선 메서드를 못 찾아 실패한다.
    # RNGCryptoServiceProvider 는 양쪽 다 지원해 pwsh/powershell 어디서 실행해도 동작한다.
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    $secret = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
    $envContent = $envContent -replace '(?m)^JWT_SECRET=\s*$', "JWT_SECRET=$secret"
    [System.IO.File]::WriteAllText($EnvFile, $envContent, $Utf8NoBom)
    Write-Host "JWT_SECRET 자동 생성 완료"
} else {
    Write-Host "JWT_SECRET 이미 설정되어 있음 (건너뜀)"
}

Write-Host "`n참고: GEMINI_API_KEY 는 7-B AI 자동테스트 요약 기능에서만 사용됩니다." -ForegroundColor Yellow
Write-Host "      비워둬도 핵심 탐지 파이프라인(/analyze)과 카카오 로그인은 정상 동작합니다." -ForegroundColor Yellow
Write-Host "      필요하면 https://aistudio.google.com/apikey 에서 무료 발급 후 backend\.env 에 채워넣으세요." -ForegroundColor Yellow

Write-Host "`n=== 3. C-TAS/화이트리스트 CSV 다운로드 ===" -ForegroundColor Cyan
$RawDir = Join-Path $RepoRoot "data\raw"
New-Item -ItemType Directory -Force -Path $RawDir | Out-Null

$ReleaseTag = "dev-v260701"
$ReleaseBase = "https://github.com/gusn9719/security_hub/releases/download/$ReleaseTag"
$Assets = @(
    "2024_smishing_cfrs_level2_1735667584010.csv",
    "202511_smishing_cfrs_level2_1764523860099.csv",
    "2025_smishing_cfrs_level2_1767196380491.csv",
    "2026_smishing_cfrs_level2_1774720380083.csv",
    "whitelist_v2.csv"
)
foreach ($f in $Assets) {
    $dest = Join-Path $RawDir $f
    # 이전 실행이 다운로드 도중 실패하면 0바이트/손상된 파일이 남을 수 있어
    # 존재 여부뿐 아니라 크기까지 확인한다 — 안 그러면 계속 건너뛰고 손상 파일이 남는다.
    $needsDownload = (-not (Test-Path $dest)) -or ((Get-Item $dest).Length -eq 0)
    if ($needsDownload) {
        Write-Host "다운로드 중: $f"
        Invoke-WebRequest -Uri "$ReleaseBase/$f" -OutFile $dest -UseBasicParsing
    } else {
        Write-Host "$f 이미 존재 (건너뜀)"
    }
}

Write-Host "`n=== 4. DB 마이그레이션 + 데이터 적재 ===" -ForegroundColor Cyan
$Python = Join-Path $VenvDir "Scripts\python.exe"
& $Python (Join-Path $RepoRoot "data\scripts\migrate_db.py")
& $Python (Join-Path $RepoRoot "data\scripts\load_ctas_csv.py") --dir (Join-Path $RepoRoot "data\raw")

$env:PYTHONPATH = Join-Path $RepoRoot "backend"
& $Python (Join-Path $RepoRoot "data\scripts\load_whitelist_csv.py") --file (Join-Path $RepoRoot "data\raw\whitelist_v2.csv")

Write-Host "`n=== 셋업 완료 ===" -ForegroundColor Green
Write-Host "다음 순서로 진행하세요:"
Write-Host "  1. .\start_server.ps1 실행 (백엔드 기동)"
Write-Host "  2. Docker Desktop 설치 + 실행 (샌드박스 기능 테스트 시 필요)"
Write-Host "  3. adb connect 127.0.0.1:<포트> && adb reverse tcp:8000 tcp:8000"
Write-Host "  4. 배포된 APK 설치 후 실행"
Write-Host "자세한 내용은 docs\SETUP.md 참조"
