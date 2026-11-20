[CmdletBinding()]
param(
    [string]$TargetVendorBoot,
    [string]$DonorVendorBoot,
    [string]$OutputDirectory,
    [switch]$InspectOnly,
    [switch]$ConfirmPGZ110,
    [switch]$AllowUnverifiedRuntime
)
$ErrorActionPreference = 'Stop'
# Packaging dependencies only. Never run cargo, NDK, make, adb or fastboot.
function LinuxPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^([A-Za-z]):\\(.*)$') { throw 'Only local drive paths are supported by this WSL launcher.' }
    return '/mnt/' + $Matches[1].ToLowerInvariant() + '/' + $Matches[2].Replace('\','/')
}
try {
    if (-not $TargetVendorBoot) { $TargetVendorBoot = (Read-Host '目标版本原厂 vendor_boot.img 路径（可拖入后去掉首尾引号）').Trim('"') }
    if (-not (Test-Path -LiteralPath $TargetVendorBoot -PathType Leaf)) { throw 'Target stock image not found.' }
    if (-not $DonorVendorBoot) {
        $bundled = Join-Path $PSScriptRoot 'donor'
        if (Test-Path -LiteralPath (Join-Path $bundled 'manifest.json')) { $DonorVendorBoot = $bundled }
        else { $DonorVendorBoot = (Read-Host '现成可用的 Skyward vendor_boot.img 路径（不会重新编译）').Trim('"') }
    }
    if (-not (Test-Path -LiteralPath $DonorVendorBoot)) { throw 'Skyward donor image/payload not found.' }
    if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot ('output\' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff')) }
    $script = Join-Path $PSScriptRoot 'repack_only.py'
    $avb = Join-Path $PSScriptRoot 'avbtool.py'
    if (-not (Test-Path -LiteralPath $avb)) { throw 'Missing avbtool.py packaging dependency beside launcher.' }
    Write-Host '仅限同一 PGZ110 的目标版本原厂底包。保留原厂 DTB/modules，不编译、不刷机。' -ForegroundColor Yellow
    Write-Host 'ramdisk: legacy LZ4 -12（最高级别）；超容量将停止，不删功能。'
    if (-not $ConfirmPGZ110 -and (Read-Host '确认目标属于 PGZ110，请输入 PGZ110') -cne 'PGZ110') { throw 'Model confirmation not supplied.' }
    # Linux distributions can provide python3 and lz4 without any Android build toolchain.
    & wsl.exe --exec python3 -c 'import sys,tomllib; assert sys.version_info >= (3,11)'
    if ($LASTEXITCODE -ne 0) { throw 'WSL Python3.11+ with tomllib is required.' }
    & wsl.exe --exec lz4 --version
    if ($LASTEXITCODE -ne 0) { throw 'WSL lz4 is required (Ubuntu: sudo apt install lz4).' }
    $arguments = @('--exec','python3',(LinuxPath $script),'--target',(LinuxPath $TargetVendorBoot),'--donor',(LinuxPath $DonorVendorBoot),'--report',(LinuxPath (Join-Path $OutputDirectory 'report.json')),'--same-device-pgz110')
    if ($InspectOnly) { $arguments += '--inspect-only' }
    else {
        $arguments += @('--out',(LinuxPath (Join-Path $OutputDirectory 'vendor_boot-REPACK-UNTESTED.img')),'--avbtool',(LinuxPath $avb))
        if ($AllowUnverifiedRuntime) { $arguments += '--allow-unverified-runtime' }
    }
    & wsl.exe @arguments
    if ($LASTEXITCODE -ne 0) { throw ('Repack stopped. Read report: ' + (Join-Path $OutputDirectory 'report.json')) }
    Write-Host ('完成。报告/输出目录: ' + $OutputDirectory) -ForegroundColor Green
    Write-Host '重打包成功不代表解密/联网/刷包已验证；不要将本输出当成跨版本通刷镜像。'
} catch {
    Write-Error $_
    exit 1
}
