<#
  WardenNet 构建脚本 — 支持多种部署模式
  统一在 WSL Ubuntu 中编译，产物放到项目根目录

  用法:
    ./build-all.ps1                         # 默认: 交互式选择
    ./build-all.ps1 -Mode static            # 静态整合版（推荐部署用）
    ./build-all.ps1 -Mode online            # 静态 + 无插件（单机离线）
    ./build-all.ps1 -Mode cloud             # CGO=1 整合云端（需同版本 glibc）
    ./build-all.ps1 -Mode so                # CGO=1 + 独立 .so 插件
    ./build-all.ps1 -Mode all               # 全部 4 种都构建一份

  模式说明:
    static   — CGO_ENABLED=0 + -tags="plugin"   推荐
               单个静态二进制, CloudPlugin 已整合, 任何 Linux 通吃
               无 glibc 依赖, 部署最省心

    online   — CGO_ENABLED=0 + -tags=""
               单个静态二进制, 无云端插件（NoopPlugin 降级）
               适合纯本地检测, 不连云端

    cloud    — CGO_ENABLED=1 + -tags="plugin"
               CGO 动态链接, CloudPlugin 整合进主程序
               产物依赖构建时 WSL Ubuntu 的 glibc 版本

    so       — CGO_ENABLED=1 主程序 + 独立 libcloudplugin.so
               传统 plugin.Open 动态加载方式

    all      — 依次构建以上 4 种 + 独立 .so 插件, 输出到 dist/ 目录

  示例:
    ./build-all.ps1 -Mode static -Version v1.0.0
    ./build-all.ps1 -Mode all    -Version v1.0.0
#>

param(
    [Parameter(Position=0)]
    [ValidateSet("static", "online", "cloud", "so", "all")]
    [string]$Mode = "",

    [string]$Version = "v0.2",

    [string]$WslDistro = "Ubuntu"
)

$ErrorActionPreference = "Stop"

$wslAgentDir = "/mnt/d/coder/business/WardenNet/agent"
$goProxy = "https://goproxy.cn,direct"

# 交互选择
if ($Mode -eq "") {
    Write-Host "WardenNet 构建脚本 — 请选择构建模式:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] static  — 静态 + CloudPlugin 整合（推荐，任何 Linux 通吃）" -ForegroundColor Green
    Write-Host "  [2] online  — 静态 + 无插件（单机离线，不连云端）"
    Write-Host "  [3] cloud   — CGO 动态 + CloudPlugin 整合（需同版本 glibc）"
    Write-Host "  [4] so      — CGO 主程序 + 独立 libcloudplugin.so"
    Write-Host "  [5] all     — 全部 4 种 + 独立 .so，输出到 dist/"
    Write-Host ""
    $choice = Read-Host "输入选项 [1-5]"
    switch ($choice) {
        "1" { $Mode = "static" }
        "2" { $Mode = "online" }
        "3" { $Mode = "cloud" }
        "4" { $Mode = "so" }
        "5" { $Mode = "all" }
        default { Write-Host "无效选择，退出" -ForegroundColor Red; exit 1 }
    }
}

# 模式配置（用字符串 key 避免 PowerShell 保留字冲突）
$buildConfigs = @{
    "static" = @{
        Name   = "wardennet_linux_static"
        CGO    = "0"
        Tags   = "plugin"
        Desc   = "静态链接 + CloudPlugin 整合（推荐部署，无 glibc 依赖）"
    }
    "online" = @{
        Name   = "wardennet_linux_online"
        CGO    = "0"
        Tags   = ""
        Desc   = "静态链接 + 无插件（单机离线模式）"
    }
    "cloud" = @{
        Name   = "wardennet_linux_cloud"
        CGO    = "1"
        Tags   = "plugin"
        Desc   = "CGO 动态链接 + CloudPlugin 整合（需同版本 glibc）"
    }
    "so" = @{
        Name   = "wardennet_linux_so"
        CGO    = "1"
        Tags   = ""
        Desc   = "CGO 动态链接 + 独立 .so 插件"
    }
}

# 辅助: 执行 WSL 命令
function Invoke-Wsl($label, $bashCmd) {
    Write-Host ""
    Write-Host "===== $label =====" -ForegroundColor Cyan
    Write-Host $bashCmd -ForegroundColor DarkGray
    $fullCmd = "cd $wslAgentDir && $bashCmd"
    wsl -d $WslDistro -- bash -c $fullCmd
    if ($LASTEXITCODE -ne 0) {
        Write-Host "失败：$label" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

# 辅助: 根据配置构建主程序
function Build-MainBinary($cfg, $outDir) {
    $envCGO = $cfg.CGO
    $goTags = $cfg.Tags
    $outName = if ($outDir) { "$outDir/$($cfg.Name)" } else { $cfg.Name }

    $tagsArg = ""
    if ($goTags -ne "") {
        $tagsArg = "-tags=$goTags"
    }

    # CGO=1 时 ldflags 不能带 -s -w（可能 strip CGO 符号出问题）
    if ($envCGO -eq "1") {
        $stripArg = "-X main.Version=$Version"
    } else {
        $stripArg = "-s -w -X main.Version=$Version"
    }

    $bashCmd = @"
GOPROXY=$goProxy CGO_ENABLED=$envCGO go build $tagsArg -ldflags='$stripArg' -o $outName ./cmd/wardennet && file $outName && ls -lh $outName
"@
    Invoke-Wsl "构建 $($cfg.Name) ($($cfg.Desc))" $bashCmd
}

# 辅助: 构建独立 .so 插件
function Build-SoPlugin($outDir) {
    $outName = if ($outDir) { "$outDir/libcloudplugin.so" } else { "libcloudplugin.so" }
    $bashCmd = @"
GOPROXY=$goProxy CGO_ENABLED=1 go build -buildmode=plugin -ldflags='-s -w -X main.Version=$Version' -o $outName ./libcloudplugin/ && ls -lh $outName
"@
    Invoke-Wsl "构建 libcloudplugin.so（独立插件）" $bashCmd
}

# ===== 清理 =====
Write-Host "===== 清理旧产物 =====" -ForegroundColor Cyan
$cleanCmd = @"
cd $wslAgentDir && rm -f wardennet_linux wardennet_linux_static wardennet_linux_online wardennet_linux_cloud wardennet_linux_so libcloudplugin.so && rm -rf dist && go clean -cache && echo "cleaned"
"@
wsl -d $WslDistro -- bash -c $cleanCmd

# ===== 按模式构建 =====
Write-Host ""
Write-Host "===== WardenNet Build =====" -ForegroundColor Magenta
Write-Host "  Version : $Version"
Write-Host "  Mode    : $Mode"
Write-Host "  WSL     : $WslDistro"
Write-Host ""

if ($Mode -eq "all") {
    Invoke-Wsl "创建 dist 目录" "mkdir -p dist"
    foreach ($k in $buildConfigs.Keys) {
        Build-MainBinary $buildConfigs[$k] "dist"
    }
    Build-SoPlugin "dist"
    Write-Host ""
    Write-Host "===== dist/ 产物总览 =====" -ForegroundColor Cyan
    Invoke-Wsl "验证产物" @"
echo '--- 文件类型 ---' && file dist/wardennet_linux_* dist/libcloudplugin.so 2>/dev/null && echo && ls -lh dist/
"@
} else {
    Build-MainBinary $buildConfigs[$Mode] ""
    if ($Mode -eq "so") {
        Build-SoPlugin ""
    }
}

# ===== 最终提示 =====
Write-Host ""
Write-Host "===== 构建完成 =====" -ForegroundColor Green
Write-Host ""

if ($Mode -eq "static") {
    Write-Host "产物: wardennet_linux_static"
    Write-Host "说明: 静态链接, CloudPlugin 已整合, 无 glibc 依赖"
    Write-Host "      放到任何 Linux (CentOS 5 ~ 最新) 都能直接运行"
    Write-Host "scp wardennet_linux_static root@服务器:/opt/wardennet/wardennet"
} elseif ($Mode -eq "online") {
    Write-Host "产物: wardennet_linux_online"
    Write-Host "说明: 静态链接, 无云端插件 (NoopPlugin 降级)"
    Write-Host "      适合纯本地检测, 不连云端"
} elseif ($Mode -eq "cloud") {
    Write-Host "产物: wardennet_linux_cloud"
    Write-Host "说明: CGO 动态链接 + CloudPlugin 整合"
    Write-Host "注意: 目标服务器 glibc 版本需 >= WSL Ubuntu 的 glibc"
} elseif ($Mode -eq "so") {
    Write-Host "产物: wardennet_linux_so + libcloudplugin.so"
    Write-Host "说明: 传统 plugin.Open 方式"
    Write-Host "注意: 主程序和 .so 需在同环境 glibc 下运行"
    Write-Host "scp wardennet_linux_so root@服务器:/opt/wardennet/wardennet"
    Write-Host "scp libcloudplugin.so root@服务器:/opt/wardennet/"
} elseif ($Mode -eq "all") {
    Write-Host "产物: dist/ 目录下全部构建"
    Write-Host "  wardennet_linux_static  - 推荐部署, 任何 Linux 通吃"
    Write-Host "  wardennet_linux_online  - 单机离线模式"
    Write-Host "  wardennet_linux_cloud   - CGO 整合云端"
    Write-Host "  wardennet_linux_so      - CGO 主程序 (需配合 .so)"
    Write-Host "  libcloudplugin.so       - 独立云端插件"
}
