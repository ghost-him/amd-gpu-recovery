#Requires -Version 5.1
<#
  amd-gpu-fix.ps1 - AMD 显卡崩溃后自动检测与恢复脚本
  背景、修复内容与处理逻辑详见同目录 README.md

  用法:
    powershell -ExecutionPolicy Bypass -File amd-gpu-fix.ps1            # 检测并尝试修复
    powershell -ExecutionPolicy Bypass -File amd-gpu-fix.ps1 -Diagnose  # 仅检测报告，不做任何修改
    powershell -ExecutionPolicy Bypass -File amd-gpu-fix.ps1 -NoElevate # 跳过自动提权（仅调试用）

  退出码:
    0  所有 AMD 显卡状态正常
    1  仍有异常设备未恢复
    2  提权被取消或失败
    3  未找到 AMD 显卡设备
#>
param(
    [switch]$Diagnose,   # 仅检测报告，不执行任何修复
    [switch]$NoElevate,  # 跳过自动提权，直接运行（仅调试用，修复操作需要管理员权限）
    [switch]$Elevated    # 内部参数：已被提权重入时不再提权
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

$LogPath         = Join-Path $env:TEMP 'amd_gpu_fix.log'
$WaitEnableSec   = 5
$WaitRestartSec  = 6
$MaxAttempts     = 3
$script:ExitCode = 0

function Get-Amds {
    # 只匹配 AMD 显示设备（PCI VEN_1002 或名称含 Radeon/AMD），不触碰其他显示适配器（如虚拟显示器）
    Get-PnpDevice -Class Display -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -like '*VEN_1002*' -or $_.FriendlyName -match 'Radeon|AMD' }
}

function Main {
    param([switch]$Diagnose)

    $devices = @(Get-Amds)
    if ($devices.Count -eq 0) {
        Write-Output '未找到 AMD 显卡设备（PCI VEN_1002）。请确认显卡为 AMD Radeon 系列。'
        $script:ExitCode = 3
        return
    }

    $anyBroken = $false

    foreach ($dev in $devices) {
        $id   = $dev.InstanceId
        $name = $dev.FriendlyName

        Write-Output ('=' * 64)
        Write-Output ("设备: {0}" -f $name)
        Write-Output ("实例: {0}" -f $id)
        try {
            $ver = (Get-CimInstance Win32_PnPSignedDriver -Filter ("DeviceID='{0}'" -f ($id -replace "'", "''")) -ErrorAction Stop).DriverVersion
            if ($ver) { Write-Output ("驱动版本: {0}" -f $ver) }
        }
        catch { }

        $cur = Get-PnpDevice -InstanceId $id -ErrorAction SilentlyContinue
        Write-Output ("当前状态: {0} ({1})" -f $cur.Problem, $cur.ProblemDescription)

        if ($cur.Problem -eq 'CM_PROB_NONE') {
            Write-Output '状态正常 (CM_PROB_NONE)，无需处理。'
            continue
        }

        if ($Diagnose) {
            $anyBroken = $true
            Write-Output '[诊断模式] 该设备异常，仅报告，不做任何修改。'
            continue
        }

        $attempt = 0
        $fixed   = $false
        while ($attempt -lt $MaxAttempts) {
            $attempt++
            $cur = Get-PnpDevice -InstanceId $id -ErrorAction SilentlyContinue
            if ($cur.Problem -eq 'CM_PROB_NONE') { $fixed = $true; break }

            if ($cur.Problem -eq 'CM_PROB_DISABLED') {
                Write-Output ("[尝试 {0}/{1}] 设备被禁用 (Code 22) -> Enable-PnpDevice 启用该设备..." -f $attempt, $MaxAttempts)
                try {
                    Enable-PnpDevice -InstanceId $id -Confirm:$false -ErrorAction Stop
                    Write-Output ("    命令已发送，等待 {0} 秒让驱动加载..." -f $WaitEnableSec)
                }
                catch {
                    Write-Output ("    Enable-PnpDevice 失败: {0}" -f $_.Exception.Message)
                    break
                }
                Start-Sleep -Seconds $WaitEnableSec
            }
            else {
                # CM_PROB_FAILED_ADD (31) / CM_PROB_FAILED_START (43) 等驱动加载类问题
                Write-Output ("[尝试 {0}/{1}] 驱动加载异常 ({2}) -> pnputil /restart-device 强制重初始化..." -f $attempt, $MaxAttempts, $cur.Problem)
                $out = (& pnputil /restart-device $id 2>&1) | Out-String
                foreach ($line in ($out -split "`r?`n" | Where-Object { $_.Trim() })) {
                    Write-Output ("    {0}" -f $line)
                }
                Write-Output ("    等待 {0} 秒..." -f $WaitRestartSec)
                Start-Sleep -Seconds $WaitRestartSec
            }
        }

        $final = Get-PnpDevice -InstanceId $id -ErrorAction SilentlyContinue
        if ($final.Problem -eq 'CM_PROB_NONE') {
            Write-Output '结果: 已恢复 (CM_PROB_NONE) OK'
        }
        else {
            Write-Output ("结果: 仍未恢复 ({0}: {1})" -f $final.Problem, $final.ProblemDescription)
            Write-Output '建议: 重启电脑后再运行本脚本。若仍异常，请在设备管理器中右键该设备 -> 卸载设备（勾选"尝试删除此设备的驱动程序"）-> 重新安装 AMD 显卡驱动。'
            $anyBroken = $true
        }
    }

    Write-Output ('=' * 64)
    $script:ExitCode = if ($anyBroken) { 1 } else { 0 }
}

# ---------- 入口 ----------

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and -not $NoElevate) {
    Write-Output '当前无管理员权限，即将通过 UAC 提权（请在弹窗中点"是"）...'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath), '-Elevated')
    if ($Diagnose) { $argList += '-Diagnose' }

    $p = $null
    try {
        $p = Start-Process powershell -Verb RunAs -WindowStyle Hidden -PassThru -Wait -ArgumentList $argList
    }
    catch {
        Write-Output ('提权失败或用户取消了 UAC: {0}' -f $_.Exception.Message)
        exit 2
    }

    if (Test-Path $LogPath) {
        Write-Output '===== 提权实例的输出 ====='
        Get-Content -Path $LogPath -Encoding UTF8
        Remove-Item -Path $LogPath -ErrorAction SilentlyContinue
    }
    exit $p.ExitCode
}

# 已是管理员（或 -NoElevate 调试模式）：直接执行修复逻辑
$output = @()
try {
    $output = @(& Main -Diagnose:$Diagnose)
    if ($output) { $output }
}
catch {
    Write-Output ('脚本执行出错: {0}' -f $_.Exception.Message)
    $script:ExitCode = 1
}

# 提权实例：把输出写入日志，供非提权父进程回显
if ($Elevated) {
    try { ($output -join "`r`n") | Out-File -FilePath $LogPath -Encoding utf8 } catch { }
}

exit $script:ExitCode
