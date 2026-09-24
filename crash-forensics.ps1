<#
.SYNOPSIS
    崩溃取证 + 系统健康自检（纯只读）。

.DESCRIPTION
    面向"屏幕卡住/变灰 → 电脑自己重启"这类现象，一次跑完下列检查并给出结论与下一步建议：
      1) 非正常关机（Kernel-Power 41 / EventLog 6008）逐条分类：
         蓝屏 / 长按电源键强制断电 / 睡眠恢复途中掉电 / 无记录整机复位
      2) 蓝屏证据：BugCheck 1001 事件、Minidump、MEMORY.DMP、转储配置
      3) 硬件错误：WHEA-Logger
      4) 显示子系统：WER 内核实况转储（Kernel_*/LiveKernelEvent 代码）、显卡 TDR 事件、
         显示设备 PnP 状态与错误码、驱动版本、TDR 注册表
      5) 存储完整性：卷健康/脏位、NTFS 与磁盘错误事件、物理磁盘健康
      6) 可选：由显卡驱动模块导致的应用程序崩溃

    本脚本只读：不修改系统、不重启、不安装任何东西。需要管理员才能读到的部分会标注 [需管理员]。

.PARAMETER Days
    回溯天数，默认 30。

.PARAMETER IncludeAppErrors
    额外统计"出错模块是显卡驱动"的应用程序崩溃（amdxx64.dll / atio6axx.dll / nvlddmkm 等）。

.PARAMETER Json
    以 JSON 输出（便于后续脚本或看板消费），不再输出人读文本。

.PARAMETER OutFile
    同时把报告写入指定文件（文本模式为 UTF-8 文本，-Json 模式为 UTF-8 JSON）。

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\crash-forensics.ps1

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\crash-forensics.ps1 -Days 90 -IncludeAppErrors

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\crash-forensics.ps1 -Json -OutFile .\crash-report.json

.NOTES
    退出码: 0 = 未发现异常; 1 = 发现异常(看报告); 2 = 运行失败(例如读不到系统事件日志)
#>
[CmdletBinding()]
param(
    [int]$Days = 30,
    [switch]$IncludeAppErrors,
    [switch]$Json,
    [string]$OutFile
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }

# ------------------------------------------------------------------ 输出
$script:Lines = New-Object System.Collections.Generic.List[string]
function Add-Line { param([string]$Text = '') $script:Lines.Add($Text) }
function Add-Section { param([string]$Title) Add-Line ''; Add-Line ('-' * 74); Add-Line ("[ $Title ]"); Add-Line ('-' * 74) }
function Add-Kv { param([string]$Key, $Value) Add-Line ("  {0,-20} {1}" -f ($Key + ':'), $Value) }

# ------------------------------------------------------------------ 通用
function Invoke-Safe { param([scriptblock]$Query) try { return @(& $Query) } catch { return @() } }
function Get-NamedData {
    param($Event)
    $h = @{}
    try {
        $x = [xml]$Event.ToXml()
        foreach ($d in $x.Event.EventData.Data) { if ($d.Name) { $h[[string]$d.Name] = [string]$d.'#text' } }
    } catch { }
    return $h
}
function Format-Time { param($T) if ($T) { ([datetime]$T).ToString('yyyy-MM-dd HH:mm:ss') } else { '-' } }
function Format-Bytes { param([double]$B) if ($B -ge 1GB) { '{0:n1} GB' -f ($B / 1GB) } else { '{0:n0} MB' -f ($B / 1MB) } }

# 蓝屏代码解读（只列常见项，其余原样打印）
$BugcheckMap = @{
    '0x116' = 'VIDEO_TDR_FAILURE — 显卡驱动超时后未能恢复（显示子系统）'
    '0x117' = 'VIDEO_TDR_TIMEOUT_DETECTED — 显卡驱动响应超时'
    '0x119' = 'VIDEO_SCHEDULER_INTERNAL_ERROR — 显示调度器内部错误'
    '0x124' = 'WHEA_UNCORRECTABLE_ERROR — 硬件不可纠正错误（CPU/内存/PCIe）'
    '0x133' = 'DPC_WATCHDOG_VIOLATION — 某驱动长时间占用处理器'
    '0x9F'  = 'DRIVER_POWER_STATE_FAILURE — 电源状态转换（睡眠/唤醒）失败'
    '0xA'   = 'IRQL_NOT_LESS_OR_EQUAL — 驱动非法内存访问'
    '0xD1'  = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL — 驱动非法内存访问'
    '0x50'  = 'PAGE_FAULT_IN_NONPAGED_AREA — 内存/驱动问题'
    '0x1E'  = 'KMODE_EXCEPTION_NOT_HANDLED'
    '0x3B'  = 'SYSTEM_SERVICE_EXCEPTION'
    '0x7E'  = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED'
    '0xEF'  = 'CRITICAL_PROCESS_DIED — 关键进程终止'
    '0x139' = 'KERNEL_SECURITY_CHECK_FAILURE'
}
# WER "Kernel_<code>" 实况转储代码解读（未列出的原样打印）
$LiveMap = @{
    '141'     = '0x141 VIDEO_ENGINE_TIMEOUT_DETECTED — GPU 引擎超时（显卡/显示驱动卡死）'
    '116'     = '0x116 VIDEO_TDR_FAILURE — 显卡驱动超时未恢复'
    '117'     = '0x117 VIDEO_TDR_TIMEOUT_DETECTED — 显卡驱动响应超时'
    '1a1'     = '0x1A1 — 显示内核(dxgkrnl)实况转储：本机历史中与 0x141 同批出现'
    '1a2'     = '0x1A2 — 显示内核(dxgkrnl)实况转储：本机历史中与 0x141 同批出现'
    'a1000001' = '0xA1000001 — 显示内核(dxgkrnl)实况转储：本机历史中与 0x141 同批出现'
    'a2000002' = '0xA2000002 — 显示内核(dxgkrnl)实况转储：本机历史中与 0x141 同批出现'
}
$PnpProblemMap = @{
    'CM_PROB_DISABLED'    = 'Code 22 — 设备被禁用'
    'CM_PROB_FAILED_ADD'  = 'Code 31 — 驱动加载失败'
    'CM_PROB_FAILED_START' = 'Code 10 — 设备无法启动'
    'CM_PROB_NEED_RESTART' = 'Code 14 — 需要重启'
    'CM_PROB_DISABLED_SERVICE' = 'Code 32 — 驱动服务被禁用'
    'CM_PROB_FAILED_INSTALL' = 'Code 28 — 未安装驱动'
}
$GpuModulePattern = 'amdxx64|atio6axx|amdxc64|amdvlk|nvlddmkm|ig[dn]d|dxgkrnl|amdkmd'

$since  = (Get-Date).AddDays(-[math]::Abs($Days))
$findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param([string]$Level, [string]$Text)
    $findings.Add([pscustomobject]([ordered]@{ level = $Level; text = $Text }))
    if ($Level -eq '警告') { Add-Line ("  [!] " + $Text) } else { Add-Line ("  [-] " + $Text) }
}

# ================================================================== 0. 主机现状
Add-Section '主机与启动状态'
$os   = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$boot = $os.LastBootUpTime
$uptime = if ($boot) { [math]::Round(((Get-Date) - $boot).TotalHours, 2) } else { $null }
Add-Kv '计算机' $env:COMPUTERNAME
Add-Kv '系统' ("{0} (Build {1})" -f $os.Caption, $os.BuildNumber)
Add-Kv '上次启动' (Format-Time $boot)
Add-Kv '已运行' ("$uptime 小时")

$bootEvt = Invoke-Safe { Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Boot'; StartTime=$boot} -ErrorAction Stop }
$bootType = $null
foreach ($e in $bootEvt) { if ($e.Id -eq 27 -and $e.Message -match '0x([0-9a-fA-F]+)') { $bootType = $matches[1].ToLower(); break } }
$bootTypeText = switch ($bootType) { '0' { '0x0 冷启动（上次关机不干净或全新加电）' } '1' { '0x1 快速启动(hybrid/hiberboot)' } '2' { '0x2 从休眠恢复' } default { "未知($bootType)" } }
Add-Kv '本次引导类型' $bootTypeText

$prevShutdown = Invoke-Safe { Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Boot'; Id=20; StartTime=$since} -ErrorAction Stop }
foreach ($e in $prevShutdown) {
    $ok = if ($e.Message -match '(true|false)') { $matches[1] } else { '?' }
    Add-Line ("  {0}  上一次关机成功={1}" -f (Format-Time $e.TimeCreated), $ok)
}

# ================================================================== 1. 非正常关机
Add-Section "非正常关机扫描（最近 $Days 天）"
$crash41 = Invoke-Safe { Get-WinEvent -FilterHashtable @{LogName='System'; Id=41; StartTime=$since} -ErrorAction Stop }
$ev6008  = Invoke-Safe { Get-WinEvent -FilterHashtable @{LogName='System'; Id=6008; StartTime=$since} -ErrorAction Stop }
Add-Kv 'Kernel-Power 41' ("{0} 次" -f @($crash41).Count)
Add-Kv 'EventLog 6008' ("{0} 次" -f @($ev6008).Count)

$uncleanList = New-Object System.Collections.Generic.List[object]
$idx = 0
foreach ($e in @($crash41 | Sort-Object TimeCreated -Descending)) {
    $d = Get-NamedData $e
    $bc = 0; if ($d['BugcheckCode']) { $bc = [int]$d['BugcheckCode'] }
    $hasPowerBtn = ($d['PowerButtonTimestamp'] -and $d['PowerButtonTimestamp'] -ne '0')
    $hasSleep    = ($d['SleepInProgress'] -and $d['SleepInProgress'] -ne '0')

    $kind = ''; $detail = ''
    if ($bc -ne 0) {
        $key = '0x{0:X}' -f $bc
        $kind = '蓝屏(BugCheck)'
        $detail = "$key $($BugcheckMap[$key])"
    } elseif ($hasPowerBtn) {
        $kind = '长按电源键强制断电'
        $detail = '电源按钮时间戳非 0：关机由人为长按电源键触发'
    } elseif ($hasSleep) {
        $kind = '睡眠/恢复过程中断电或卡死'
        $detail = "SleepInProgress=$($d['SleepInProgress'])"
    } else {
        $kind = '无蓝屏记录的整机复位（挂起或瞬时断电）'
        $detail = 'BugcheckCode=0 且无电源键、无睡眠转换 → 操作系统来不及写任何记录'
    }
    Add-Line ''
    Add-Line ("  #{0} {1}" -f (++$idx), (Format-Time $e.TimeCreated))
    Add-Line ("      类型: {0}" -f $kind)
    Add-Line ("      判据: {0}" -f $detail)
    Add-Line ("      原始: BugcheckCode={0} SleepInProgress={1} PowerButtonTimestamp={2} Checkpoint={3}" -f $d['BugcheckCode'], $d['SleepInProgress'], $d['PowerButtonTimestamp'], $d['Checkpoint'])
    $uncleanList.Add([pscustomobject]([ordered]@{
        detectedAt    = (Format-Time $e.TimeCreated)
        kind          = $kind
        detail        = $detail
        bugcheckCode  = $bc
        sleepInProgress = $d['SleepInProgress']
        powerButtonTimestamp = $d['PowerButtonTimestamp']
    }))
}

# 最近一次崩溃的“最后一条系统事件”，用来估计真实崩溃时刻
if (@($crash41).Count -gt 0) {
    $lastCrash = @($crash41 | Sort-Object TimeCreated -Descending)[0]
    $winStart = $lastCrash.TimeCreated.AddHours(-24)
    $ctx = Invoke-Safe { Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$winStart; EndTime=$lastCrash.TimeCreated.AddSeconds(-2)} -ErrorAction Stop }
    $lastEvt = @($ctx | Sort-Object TimeCreated -Descending) | Select-Object -First 1
    Add-Line ''
    Add-Line '  最近一次崩溃的现场（崩溃前系统最后几条动态）:'
    if ($lastEvt) {
        foreach ($e in (@($ctx | Sort-Object TimeCreated -Descending) | Select-Object -First 6)) {
            $msg = ($e.Message -replace '\s+', ' ')
            if ($msg.Length -gt 110) { $msg = $msg.Substring(0, 110) + '…' }
            Add-Line ("      {0}  Id={1,-5} {2}  {3}" -f $e.TimeCreated.ToString('HH:mm:ss'), $e.Id, $e.ProviderName, $msg)
        }
        $gap = [math]::Round(($lastCrash.TimeCreated - $lastEvt.TimeCreated).TotalMinutes, 1)
        Add-Line ("      注: 6008 自报的关机时间往往滞后；以【最后一条系统事件之后 {0} 分钟内掉电】估算真实崩溃时刻。" -f $gap)
    } else {
        Add-Line '      （无法读取崩溃前的系统事件）'
    }
}

# ================================================================== 2. 蓝屏证据
Add-Section '蓝屏证据与转储配置'
$bugcheckEvt = Invoke-Safe { Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'; Id=1001; StartTime=$since} -ErrorAction Stop }
if (@($bugcheckEvt).Count -eq 0) { $bugcheckEvt = Invoke-Safe { Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001; StartTime=$since} -ErrorAction Stop } }
Add-Kv 'BugCheck 1001 事件' ("{0} 次" -f @($bugcheckEvt).Count)
foreach ($e in @($bugcheckEvt)) {
    $msg = ($e.Message -replace '\s+', ' ')
    Add-Line ("      {0}  {1}" -f (Format-Time $e.TimeCreated), $msg)
}

$dumps = @()
foreach ($p in @("$env:SystemRoot\Minidump", "$env:SystemRoot\LiveKernelReports")) {
    $f = Get-ChildItem -Path $p -Recurse -Filter *.dmp -Force -ErrorAction SilentlyContinue |
         Where-Object { $_.LastWriteTime -gt $since } | Sort-Object LastWriteTime -Descending
    Add-Kv $p ("{0} 个 .dmp（窗口内）" -f @($f).Count)
    foreach ($x in @($f | Select-Object -First 10)) { Add-Line ("      {0}  {1}" -f (Format-Time $x.LastWriteTime), $x.FullName) }
    $dumps += $f
}
$mem = Get-Item "$env:SystemRoot\MEMORY.DMP" -ErrorAction SilentlyContinue
Add-Kv 'MEMORY.DMP' $(if ($mem) { "$(Format-Time $mem.LastWriteTime)  $(Format-Bytes $mem.Length)" } else { '不存在' })

$cc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction SilentlyContinue
$dumpModeText = switch ([int]$cc.CrashDumpEnabled) {
    0 { '0 = 不写入转储' } 1 { '1 = 完整内存转储' } 2 { '2 = 内核内存转储' } 3 { '3 = 小内存转储(256KB)' } 7 { '7 = 自动内存转储(推荐)' } default { "$($cc.CrashDumpEnabled)" }
}
Add-Kv '转储配置' $dumpModeText
Add-Kv 'AutoReboot' $cc.AutoReboot

# ================================================================== 3. 硬件错误
Add-Section '硬件错误 (WHEA)'
$whea = Invoke-Safe { Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; StartTime=$since} -ErrorAction Stop }
Add-Kv 'WHEA 事件数' ("{0} 次" -f @($whea).Count)
foreach ($e in @($whea | Select-Object -First 10)) {
    Add-Line ("      {0}  Id={1}  {2}" -f (Format-Time $e.TimeCreated), $e.Id, (($e.Message -replace '\s+', ' ')))
}

# ================================================================== 4. 显示子系统
Add-Section '显示子系统 (GPU)'
# 4.1 WER 内核实况转储
$liveEvents = New-Object System.Collections.Generic.List[object]
foreach ($root in @("$env:ProgramData\Microsoft\Windows\WER\ReportArchive", "$env:ProgramData\Microsoft\Windows\WER\ReportQueue")) {
    if (-not (Test-Path $root)) { continue }
    foreach ($d in @(Get-ChildItem $root -Directory -Force -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -like 'Kernel_*' -and $_.LastWriteTime -gt $since })) {
        $tok = (($d.Name -split '_')[1]).ToLower()
        $liveEvents.Add([pscustomobject]([ordered]@{
            time = Format-Time $d.LastWriteTime
            code = $tok
            text = $(if ($LiveMap.ContainsKey($tok)) { $LiveMap[$tok] } else { "0x$($tok.ToUpper())（未收录代码，详见报告目录）" })
            path = $d.FullName
        }))
    }
}
Add-Kv '内核实况转储' ("{0} 次（窗口内）" -f $liveEvents.Count)
foreach ($g in @($liveEvents | Group-Object code | Sort-Object Count -Descending)) {
    Add-Line ("      {0,-10} x{1}   {2}" -f $g.Name, $g.Count, ($g.Group[0].text))
}
foreach ($x in @($liveEvents | Sort-Object { [datetime]$_.time } -Descending | Select-Object -First 10)) {
    Add-Line ("      {0}  {1}" -f $x.time, $x.code)
}

# 4.2 显卡 TDR 恢复事件（Display 提供程序 4101/4103）
$tdrEvt = Invoke-Safe { Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Display'; StartTime=$since} -ErrorAction Stop }
Add-Kv 'Display 提供程序事件' ("{0} 次（4101 = 驱动卡死但已恢复）" -f @($tdrEvt).Count)
foreach ($e in @($tdrEvt | Select-Object -First 5)) { Add-Line ("      {0}  Id={1}  {2}" -f (Format-Time $e.TimeCreated), $e.Id, (($e.Message -replace '\s+', ' '))) }

# 4.3 显示设备状态
$displayDevices = New-Object System.Collections.Generic.List[object]
foreach ($d in @(Get-PnpDevice -Class Display -ErrorAction SilentlyContinue)) {
    $probText = "$($d.Problem) $($d.ProblemDescription)"
    if ($PnpProblemMap.ContainsKey("$($d.Problem)")) { $probText = $PnpProblemMap["$($d.Problem)"] }
    Add-Line ''
    Add-Line ("      设备: {0}" -f $d.FriendlyName)
    Add-Line ("        状态: {0}   Problem: {1}" -f $d.Status, $probText)
    Add-Line ("        实例: {0}" -f $d.InstanceId)
    $displayDevices.Add([pscustomobject]([ordered]@{ name = $d.FriendlyName; status = "$($d.Status)"; problem = "$($d.Problem)"; problemText = $probText; instanceId = $d.InstanceId }))
    if ("$($d.Problem)" -ne 'CM_PROB_NONE') {
        Add-Finding '警告' ("显示设备异常: {0} → {1}（参考 amd-gpu-fix.ps1 恢复）" -f $d.FriendlyName, $probText)
    }
}
foreach ($v in @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)) {
    if (-not $v.DriverVersion) { continue }
    Add-Line ("      驱动: {0}  版本 {1}  日期 {2}  分辨率 {3}x{4}" -f $v.Name, $v.DriverVersion, $v.DriverDate, $v.CurrentHorizontalResolution, $v.CurrentVerticalResolution)
}

# 4.4 TDR 注册表
$tdr = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -ErrorAction SilentlyContinue
Add-Kv 'TdrLevel' $(if ($null -eq $tdr.TdrLevel) { '(未设置 → 默认: 自动恢复)' } else { $tdr.TdrLevel })
Add-Kv 'TdrDelay' $(if ($null -eq $tdr.TdrDelay) { '(未设置 → 默认 2 秒)' } else { $tdr.TdrDelay })
if ($null -ne $tdr.TdrLevel -and [int]$tdr.TdrLevel -eq 0) { Add-Finding '警告' 'TdrLevel=0：显卡卡死时已关闭自动恢复，会直接整机挂起' }

# 4.5 可选：显卡驱动导致的应用程序崩溃
if ($IncludeAppErrors) {
    $appErr = Invoke-Safe { Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000; StartTime=$since} -ErrorAction Stop }
    $gpuApp = @($appErr | Where-Object { $_.Message -match $GpuModulePattern })
    Add-Kv '显卡模块导致的程序崩溃' ("{0} 次（窗口内）" -f $gpuApp.Count)
    foreach ($e in @($gpuApp | Select-Object -First 5)) {
        Add-Line ("      {0}  {1}" -f (Format-Time $e.TimeCreated), (($e.Message -replace '\s+', ' ')))
    }
}

# ================================================================== 5. 存储完整性
Add-Section '存储与文件系统完整性'
$diskIssues = New-Object System.Collections.Generic.List[string]
foreach ($v in @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter })) {
    $freePct = if ($v.Size -gt 0) { [math]::Round(100 * $v.SizeRemaining / $v.Size, 1) } else { 0 }
    $line = "      {0}:  {1}  可用 {2} GB / {3} GB ({4}%)  Health={5}" -f $v.DriveLetter, $v.FileSystemLabel, [math]::Round($v.SizeRemaining / 1GB, 1), [math]::Round($v.Size / 1GB, 1), $freePct, $v.HealthStatus
    Add-Line $line
    if ("$($v.HealthStatus)" -ne 'Healthy') {
        $diskIssues.Add("卷 $($v.DriveLetter): HealthStatus=$($v.HealthStatus)（通常为脏位/需修复）")
        Add-Finding '警告' ("卷 {0}: 健康状态为 {1} → 管理员执行: chkdsk {0}: /f" -f $v.DriveLetter, $v.HealthStatus)
    }
    $dirty = ''
    try { $dirty = (cmd /c "fsutil dirty query $($v.DriveLetter):" 2>&1 | Out-String).Trim() } catch { }
    if ($dirty) { Add-Line ("        脏位检查: {0}" -f ($dirty -replace '\s+', ' ')) }
    if ($dirty -match '错误 5|Access is denied|拒绝访问') { Add-Line '        (脏位检查需要管理员权限，当前跳过)' }
    if ($freePct -lt 10 -and $v.DriveLetter -eq 'C') { Add-Finding '警告' '系统盘可用空间低于 10%，转储文件可能写不下' }
}
foreach ($p in @(Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
    Add-Line ("      物理盘: {0}  {1}  Health={2}  Operational={3}" -f $p.FriendlyName, $p.MediaType, $p.HealthStatus, $p.OperationalStatus)
    if ("$($p.HealthStatus)" -ne 'Healthy') { Add-Finding '警告' ("物理磁盘 {0} 健康状态 {1}" -f $p.FriendlyName, $p.HealthStatus) }
}

$ntfsAll = Invoke-Safe { Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Ntfs'; StartTime=$since} -ErrorAction Stop }
$ntfsBad = @($ntfsAll | Where-Object { $_.Id -ne 98 })
Add-Kv 'NTFS 事件' ("{0} 条（其中健康报告 98: {1} 条，异常: {2} 条）" -f @($ntfsAll).Count, @($ntfsAll | Where-Object { $_.Id -eq 98 }).Count, $ntfsBad.Count)
foreach ($e in @($ntfsBad | Select-Object -First 10)) { Add-Line ("      {0}  Id={1}  {2}" -f (Format-Time $e.TimeCreated), $e.Id, (($e.Message -replace '\s+', ' '))) }
if ($ntfsBad.Count -gt 0) { Add-Finding '警告' '文件系统报告了非健康事件（可能有损坏，先备份再 chkdsk）' }

$volEvt = Invoke-Safe { Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName=@('volmgr','disk','stornvme','storahci'); StartTime=$since} -ErrorAction Stop }
$volBad = @($volEvt | Where-Object { $_.LevelDisplayName -ne '信息' })
Add-Kv '磁盘/控制器警告错误' ("{0} 条" -f $volBad.Count)
foreach ($e in @($volBad | Select-Object -First 8)) { Add-Line ("      {0}  Id={1}  {2}  {3}" -f (Format-Time $e.TimeCreated), $e.Id, $e.ProviderName, (($e.Message -replace '\s+', ' '))) }

# ================================================================== 6. 结论
Add-Section '结论与建议'
$latest = if ($uncleanList.Count -gt 0) { $uncleanList[0] } else { $null }
if ($latest) {
    Add-Line ("  最近一次异常关机: {0}  →  {1}" -f $latest.detectedAt, $latest.kind)
    if ($latest.bugcheckCode -ne 0) {
        Add-Line '    这是标准蓝屏（有 BugCheck 代码），应优先分析转储文件（WinDbg !analyze -v）。'
    } elseif ($latest.kind -match '长按电源键') {
        Add-Line '    关机由长按电源键触发：说明当时系统已经卡死到无法响应，需要找出卡死原因。'
    } elseif ($latest.kind -match '睡眠') {
        Add-Line '    发生在睡眠/恢复转换过程中，属于典型的电源/唤醒稳定性问题。'
    } else {
        Add-Line '    这属于【操作系统没有留下任何记录的整机复位】：没有蓝屏、没有转储、没有电源键记录。'
        Add-Line '    这类复位发生在硬件层（供电瞬断、显卡/PCIe 掉链、过热保护、内存不稳），因此只能从硬件与负载侧找证据。'
    }
} else {
    Add-Line "  最近 $Days 天内没有发现异常关机。"
}
if ($liveEvents.Count -gt 0) {
    Add-Line ''
    Add-Line ("  历史上有 {0} 次内核实况转储，其中 GPU 相关的（0x141/0x116/0x117/dxgkrnl）占多数 → 显示子系统存在反复卡死的客观记录。" -f $liveEvents.Count)
}

$warningCount = @($findings | Where-Object { $_.level -eq '警告' }).Count
Add-Line ''
Add-Line '  建议（按优先级）:'
if ($liveEvents.Count -gt 0 -or ($latest -and $latest.kind -match '整机复位|长按电源键')) {
    Add-Line '    1. 显卡驱动：用 DDU 在安全模式彻底清除后重装/升级 Adrenalin，再观察；这是本机历史上最明确的疑点。'
    Add-Line '    2. 供电与散热：显卡用两条独立 PCIe 供电线、重插显卡与供电；记录 GPU 结温与整机功耗（Radeon Software / 传感器日志），看崩溃是否出现在功耗尖峰或高温时。'
    Add-Line '    3. 平台交叉验证：BIOS 关闭 EXPO/内存超频（或降到 JEDEC 频率）跑几天对照；有条件升级主板 BIOS/AGESA。'
    Add-Line '    4. 持续传感器日志：用 HWiNFO 之类工具把温度/电压/功耗记到磁盘，重启后翻最后几行，这是【无记录复位】唯一能留下证据的方式。'
} else {
    Add-Line '    1. 暂时没有异常信号，继续保留本脚本定期巡检即可。'
}
if ($diskIssues.Count -gt 0) {
    Add-Line '    5. 磁盘：对上面标记的卷执行管理员 chkdsk X: /f，先备份重要文件。'
}
if (@($bugcheckEvt).Count -eq 0 -and @($dumps).Count -eq 0) {
    Add-Line '    6. 转储配置：当前转储模式见上；如需在【真蓝屏】时拿到完整证据，可设为【自动内存转储】（CrashDumpControl=7，需重启生效）。注意本次这类无蓝屏复位不会产生任何转储文件。'
}
Add-Line '    7. 若已按 1-4 排除仍复发：依次怀疑电源（PSU 老化/余量不足）、显卡本体、内存条，建议借件替换法定位。'
$thirdParty = New-Object System.Collections.Generic.List[string]
foreach ($d in @(Get-PnpDevice -Class Display -ErrorAction SilentlyContinue)) {
    if ($d.InstanceId -like 'ROOT\DISPLAY*') { $thirdParty.Add("虚拟显示适配器 $($d.FriendlyName)（$($d.InstanceId)）") }
}
foreach ($s in @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'NTIOLib|XLGuard|Wintun' })) {
    $thirdParty.Add("第三方内核驱动 $($s.Name)（$($s.State)）")
}
if ($thirdParty.Count -gt 0) {
    Add-Line ''
    Add-Line ('  检测到的第三方显示/内核组件（可临时禁用做对照）: ' + ($thirdParty -join '、'))
}

# ================================================================== 7. 输出
$summary = [pscustomobject]([ordered]@{
    generatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    computer    = $env:COMPUTERNAME
    os          = ("{0} (Build {1})" -f $os.Caption, $os.BuildNumber)
    bootTime    = (Format-Time $boot)
    uptimeHours = $uptime
    windowDays  = $Days
    uncleanShutdowns = $uncleanList
    bugcheckEvents   = @($bugcheckEvt | ForEach-Object { [pscustomobject]([ordered]@{ time = (Format-Time $_.TimeCreated); message = ($_.Message -replace '\s+', ' ') }) })
    dumps            = @($dumps | ForEach-Object { [pscustomobject]([ordered]@{ time = (Format-Time $_.LastWriteTime); path = $_.FullName }) })
    crashDumpMode    = $dumpModeText
    bootType         = $bootTypeText
    wheaEvents       = @($whea | ForEach-Object { [pscustomobject]([ordered]@{ time = (Format-Time $_.TimeCreated); id = $_.Id; message = ($_.Message -replace '\s+', ' ') }) })
    gpuLiveKernel    = $liveEvents
    tdrEvents        = @($tdrEvt | ForEach-Object { [pscustomobject]([ordered]@{ time = (Format-Time $_.TimeCreated); id = $_.Id }) })
    displayDevices   = $displayDevices
    ntfsBad          = @($ntfsBad | ForEach-Object { [pscustomobject]([ordered]@{ time = (Format-Time $_.TimeCreated); id = $_.Id }) })
    diskIssues       = $diskIssues
    thirdPartyComponents = $thirdParty
    findings         = $findings
})
$problem = ($uncleanList.Count -gt 0) -or (@($bugcheckEvt).Count -gt 0) -or (@($whea).Count -gt 0) -or
           ($liveEvents.Count -gt 0) -or ($warningCount -gt 0) -or ($ntfsBad.Count -gt 0) -or ($diskIssues.Count -gt 0)
Add-Member -InputObject $summary -NotePropertyName problemFound -NotePropertyValue $problem -Force

if ($Json) {
    $text = $summary | ConvertTo-Json -Depth 8
    if ($OutFile) { [System.IO.File]::WriteAllText($OutFile, $text, (New-Object System.Text.UTF8Encoding($false))) }
    Write-Output $text
} else {
    Add-Section '汇总'
    Add-Kv '非正常关机' ("{0} 次" -f $uncleanList.Count)
    Add-Kv '蓝屏' ("{0} 次 / 转储 {1} 个" -f @($bugcheckEvt).Count, @($dumps).Count)
    Add-Kv 'WHEA 硬件错误' ("{0} 次" -f @($whea).Count)
    Add-Kv 'GPU 内核实况转储' ("{0} 次" -f $liveEvents.Count)
    Add-Kv '警告项' $warningCount
    Add-Line ''
    if ($problem) { Add-Line '  >>> 发现异常，请按上面【建议】逐项处理。' } else { Add-Line '  >>> 未发现异常。' }
    $text = ($script:Lines -join "`r`n")
    if ($OutFile) { $text | Out-File -FilePath $OutFile -Encoding utf8 }
    Write-Output $text
}

if ($problem) { exit 1 } else { exit 0 }
