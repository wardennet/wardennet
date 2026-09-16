<#
  sync-website.ps1 - WardenNet website -> public -> GitHub one-click sync

  Copies website/ from the full private repo to WardenNet-public/website/ (separate repo).
  Excludes Next.js build artifacts, node_modules, AI agent configs, and secrets.

  Workflow:
    1. Create target dir if missing (+ optional git init)
    2. robocopy from website/ to WardenNet-public/website/
    3. Post-copy scan: remove any build artifacts / closed-source that leaked
    4. Security scan + size report
    5. git add + commit + push

  Prerequisites:
    - Source: d:\coder\business\WardenNet\website\
    - Target: d:\coder\business\WardenNet-public\website\
      (can be fresh dir; script will git init if .git absent)

  Usage:
    ./sync-website.ps1
    ./sync-website.ps1 -Message "docs: update architecture page"
    ./sync-website.ps1 -Message "v1.0 launch" -Push
    ./sync-website.ps1 -DryRun
    ./sync-website.ps1 -InitGit     # first-run: init + commit
#>

param(
    [string]$Message = "",
    [switch]$Push,
    [switch]$DryRun,
    [switch]$InitGit
)

$ErrorActionPreference = "Continue"

# ======== Paths ========
$fullSrcDir     = Join-Path $PSScriptRoot "website"
$parentDir      = Split-Path -Parent $PSScriptRoot
$publicDstDir   = Join-Path $parentDir "WardenNet-public\website"

# Directories to exclude by NAME (robocopy /XD)
$excludeDirs = @(
    ".git", ".trae", ".trae-cn", ".cursor", ".aider",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "node_modules",
    # Next.js build artifacts
    ".next",
    "out",
    ".vercel",
    ".turbo",
    ".cache",
    "dist",
    "build",
    ".svelte-kit",
    ".nuxt"
)

# Files to exclude by wildcard (robocopy /XF)
$excludeFiles = @(
    ".env", ".env.*", ".env.local",
    "*.local", "*.log", "*.log.*"
)

# Closed-source / private paths that must be DELETED after robocopy
$closedPathsToDelete = @(
    # AI agent configs (internal workflow)
    "CLAUDE.md",
    "AGENTS.md",
    # Private / dev-only
    ".env",
    ".env.local",
    ".env.development",
    ".env.staging"
)

# Blocked paths that must NEVER appear in public website repo
$blockedCheckPaths = @(
    ".next",
    "node_modules",
    "CLAUDE.md",
    "AGENTS.md",
    ".env",
    ".env.local",
    ".vercel",
    ".turbo"
)

Write-Host ""
Write-Host "==============================================" -ForegroundColor Magenta
Write-Host " WardenNet website -> public (GitHub)" -ForegroundColor Magenta
Write-Host "==============================================" -ForegroundColor Magenta
Write-Host "  Source (website): $fullSrcDir"
Write-Host "  Target (public):   $publicDstDir"
Write-Host ""

# ======== Pre-flight checks ========
if (-not (Test-Path $fullSrcDir)) {
    Write-Host "FAIL: Source website dir not found: $fullSrcDir" -ForegroundColor Red
    exit 1
}

# Create target if missing
if (-not (Test-Path $publicDstDir)) {
    if ($DryRun) {
        Write-Host "  [DRY-RUN] Would create target: $publicDstDir" -ForegroundColor Yellow
    } else {
        New-Item -ItemType Directory -Path $publicDstDir -Force | Out-Null
        Write-Host "  Created target dir: $publicDstDir" -ForegroundColor Green
    }
}

# Git init if requested or .git missing
$targetGitDir = Join-Path $publicDstDir ".git"
if ($InitGit -and -not (Test-Path $targetGitDir)) {
    if ($DryRun) {
        Write-Host "  [DRY-RUN] Would git init + initial commit" -ForegroundColor Yellow
    } else {
        Write-Host ""
        Write-Host "[0/5] Initializing git repo..." -ForegroundColor Cyan
        Push-Location $publicDstDir
        git init 2>&1 | Out-Null
        git checkout -b main 2>&1 | Out-Null
        Pop-Location
        Write-Host "  git init done on main branch" -ForegroundColor Green
    }
}

# ======== Step 1: robocopy ========
Write-Host ""
Write-Host "[1/5] robocopy website -> public..." -ForegroundColor Cyan

$robocopyArgs = @(
    $fullSrcDir,
    $publicDstDir,
    "/E", "/DCOPY:DAT", "/COPY:DAT", "/R:1", "/W:1", "/NFL", "/NDL", "/NP", "/XJ", "/MT:8",
    "/IS", "/IT",
    "/XD"
)
$robocopyArgs += $excludeDirs
$robocopyArgs += "/XF"
$robocopyArgs += $excludeFiles

if ($DryRun) {
    Write-Host "  [DRY-RUN] Skipping robocopy" -ForegroundColor Yellow
} else {
    Write-Host "  Copying..." -ForegroundColor DarkGray
    robocopy @robocopyArgs | Out-Null
    if ($LASTEXITCODE -gt 7) {
        Write-Host "FAIL: robocopy error (exit=$LASTEXITCODE)" -ForegroundColor Red
        exit 1
    }
    Write-Host "  OK (exit=$LASTEXITCODE, 0-7 are success)" -ForegroundColor Green
}

# ======== Step 2: Remove closed-source / private content ========
Write-Host ""
Write-Host "[2/5] Remove closed-source / private content..." -ForegroundColor Cyan

foreach ($relPath in $closedPathsToDelete) {
    $checkPath = Join-Path $publicDstDir $relPath
    if (Test-Path $checkPath) {
        if ($DryRun) {
            Write-Host "  [DRY-RUN] Would delete: $relPath" -ForegroundColor Yellow
        } else {
            Remove-Item $checkPath -Recurse -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $checkPath)) {
                Write-Host "  Deleted: $relPath" -ForegroundColor Green
            } else {
                Write-Host "  WARN: Failed to delete: $relPath" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "  Already excluded: $relPath" -ForegroundColor DarkGray
    }
}

# ======== Step 3: Security scan ========
Write-Host ""
Write-Host "[3/5] Security scan (private content must NOT be in public)..." -ForegroundColor Cyan

$foundBlocked = $false
foreach ($relPath in $blockedCheckPaths) {
    $checkPath = Join-Path $publicDstDir $relPath
    if (Test-Path $checkPath) {
        Write-Host "  FAIL: Found private content: $relPath" -ForegroundColor Red
        $foundBlocked = $true
    } else {
        Write-Host "  Confirmed excluded: $relPath" -ForegroundColor DarkGray
    }
}

if ($foundBlocked) {
    Write-Host ""
    Write-Host "FAIL: Private content leaked into public website!" -ForegroundColor Red
    Write-Host "  Please fix manually then re-run." -ForegroundColor Red
    exit 1
}

# --- Step 3b: size report ---
$files = Get-ChildItem -Path $publicDstDir -Recurse -File -ErrorAction SilentlyContinue
$totalMB = [math]::Round(($files | Measure-Object Length -Sum).Sum / 1MB, 2)
Write-Host ""
Write-Host "  Public website: $($files.Count) files, $totalMB MB" -ForegroundColor Green

Write-Host "  Breakdown:"
Get-ChildItem $publicDstDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $dirSize = [math]::Round((Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1MB, 2)
    Write-Host "    $($_.Name)/: $dirSize MB" -ForegroundColor DarkGray
}
Get-ChildItem $publicDstDir -File -ErrorAction SilentlyContinue | ForEach-Object {
    $szKB = [math]::Round($_.Length / 1KB, 1)
    Write-Host "    $($_.Name): $szKB KB" -ForegroundColor DarkGray
}

Write-Host "  Security scan passed" -ForegroundColor Green

# ======== Step 4: Git operations ========
Write-Host ""
Write-Host "[4/5] Git operations..." -ForegroundColor Cyan

Push-Location $publicDstDir
try {
    $isGit = git rev-parse --is-inside-work-tree 2>&1
    if (-not $isGit) {
        Write-Host "  Not a git repo. Use -InitGit first." -ForegroundColor Yellow
        return
    }

    git stash 2>&1 | Out-Null
    git stash drop 2>&1 | Out-Null

    $hasRemote = (git remote 2>&1 | Measure-Object).Count -gt 0
    if ($hasRemote) {
        Write-Host "  git pull --rebase..." -ForegroundColor DarkGray
        git pull --rebase 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    } else {
        Write-Host "  Skip pull (no remote configured yet)" -ForegroundColor DarkGray
    }

    if ($DryRun) {
        Write-Host ""
        Write-Host "  [DRY-RUN] Skipping git commit/push" -ForegroundColor Yellow
        return
    }

    git add .

    $status = git status --short 2>&1
    if (-not $status) {
        Write-Host "  No changes, nothing to commit" -ForegroundColor DarkGray
        return
    }

    Write-Host "  Changed files:" -ForegroundColor DarkGray
    $status | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

    if ($Message -eq "") {
        Push-Location $fullSrcDir
        $lastMsg = git log -1 --pretty=%s 2>&1
        Pop-Location
        if ($lastMsg -and $lastMsg.Trim() -ne "") {
            $Message = "[website] " + $lastMsg
        } else {
            $Message = "website: sync $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        }
    }

    Write-Host "  git commit -m `"$Message`"" -ForegroundColor DarkGray
    git commit -m $Message

    # ======== Step 5: Push ========
    if ($Push) {
        Write-Host ""
        Write-Host "[5/5] Push to GitHub..." -ForegroundColor Cyan
        git push origin main 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        Write-Host "  Push complete" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "[5/5] Push skipped (use -Push to auto-push)" -ForegroundColor DarkGray
        Write-Host "  Manual: cd $publicDstDir ; git push origin main" -ForegroundColor Yellow
    }
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host " Website sync complete!" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green
