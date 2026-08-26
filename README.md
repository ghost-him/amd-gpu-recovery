# AMD 显卡崩溃自动修复脚本（amd-gpu-fix.ps1）

## 背景

2026-08-26 的一起实际故障：AMD Radeon RX 7800 XT。该故障中**显卡硬件本身是好的**，问题出在系统状态上。当时经过是：电脑死机 → 强制重启 → 重启后显示器分辨率变得很低（显卡已不工作）→ 排查发现显卡在设备管理器中处于**被禁用**状态（`Get-PnpDevice` 显示 `CM_PROB_DISABLED`，即错误代码 22 "该设备已被禁用"）。启用设备后驱动初次加载失败（`CM_PROB_FAILED_ADD`，即错误代码 31 "Windows 无法加载此设备的驱动程序"），最终通过**强制重新初始化设备**（`pnputil /restart-device`）成功恢复，分辨率恢复正常。

当时的手动排查过程：

1. 检查显卡状态：`Get-PnpDevice -Class Display` 确认 AMD 显卡状态与错误代码；
2. 启用被禁用的设备：`Enable-PnpDevice -InstanceId <设备实例ID>`（需管理员权限）；
3. 若启用后出现驱动加载失败，强制重初始化：`pnputil /restart-device <设备实例ID>`（需管理员权限）；
4. 复查状态，确认恢复为 `CM_PROB_NONE`。

本脚本将以上手动流程自动化：遇到同类故障时直接运行即可尝试修复。

## 脚本尝试修复的内容

- 定位所有 **AMD 显卡**显示设备（PCI `VEN_1002` 或名称含 `Radeon`/`AMD`），不会误动其他显示适配器（如虚拟显示器、其他品牌显卡）。
- **Code 22（设备被禁用）**：用 `Enable-PnpDevice` 启用该设备。
- **Code 31（驱动加载失败，`CM_PROB_FAILED_ADD`）及类似驱动加载错误（如 Code 43）**：用 `pnputil /restart-device` 强制重新初始化设备。
- 每个设备最多尝试 **3 轮**，每步操作后等待数秒再复查状态。
- 修复结束后自动汇总结果，并给出退出码；若仍未恢复，提示重启电脑或重装驱动的建议。

## 脚本的处理逻辑

1. **权限检查**：无管理员权限时，自动通过 UAC 提权重启自身（用户需在弹出窗口点"是"）。提权实例将输出写入 `%TEMP%\amd_gpu_fix.log`，父进程等待结束后回显该日志，保证用户能看到结果。
2. **设备扫描**：枚举显示设备，仅筛选 AMD 显卡。
3. **逐设备处理**：
   - `CM_PROB_NONE`（正常）→ 跳过；
   - `CM_PROB_DISABLED`（Code 22）→ 启用设备，等待 5 秒；
   - 其他驱动加载类错误（Code 31/43 等）→ 强制重启设备，等待 6 秒；
   - 每次操作后重新读取状态，判断是否恢复；未恢复则进入下一轮（最多 3 轮）。
4. **结果汇报**：逐设备打印最终状态；存在未恢复设备时输出处理建议。

## 使用方法

```powershell
# 检测并尝试修复（推荐；会自动请求 UAC 提权）
powershell -ExecutionPolicy Bypass -File amd-gpu-fix.ps1

# 仅检测报告，不做任何修改
powershell -ExecutionPolicy Bypass -File amd-gpu-fix.ps1 -Diagnose

# 跳过自动提权（仅调试用；修复操作需要管理员权限）
powershell -ExecutionPolicy Bypass -File amd-gpu-fix.ps1 -NoElevate
```

## 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 所有 AMD 显卡状态正常 |
| 1 | 仍有异常设备未恢复（可尝试重启电脑后重跑） |
| 2 | 提权被取消或失败 |
| 3 | 未找到 AMD 显卡设备 |

## 注意事项

- 仅适用于 Windows 10 1809+ / Windows 11（`Enable-PnpDevice`、`pnputil /restart-device` 需要此版本及以上）。
- 修复动作需要管理员权限；脚本会自动请求 UAC 提权。
- 脚本只能处理"设备被禁用 / 驱动加载失败"类软故障。如果显卡硬件本身损坏（如检查状态为 Code 43 且重启后依然存在），需要重装驱动，必要时送修。

---

# AMD GPU Crash Recovery Script (amd-gpu-fix.ps1) — English Version

## Background

A real incident on 2026-08-26 with an AMD Radeon RX 7800 XT: the **GPU hardware itself was fine** — the problem was in the system state. The sequence: the PC froze → forced restart → after restarting, the display resolution was very low (the GPU was no longer working) → investigation showed the GPU was **disabled** in Device Manager (`Get-PnpDevice` reported `CM_PROB_DISABLED`, error Code 22 "This device is disabled"). After enabling it, the driver failed to load (`CM_PROB_FAILED_ADD`, error Code 31 "Windows cannot load the driver"), and the device finally recovered via **forced device re-initialization** (`pnputil /restart-device`), with the resolution back to normal.

Manual troubleshooting steps at the time:

1. Check GPU status with `Get-PnpDevice -Class Display` (status and error code);
2. Enable the disabled device: `Enable-PnpDevice -InstanceId <instance ID>` (requires administrator);
3. If the driver fails to load after enabling, force re-initialize: `pnputil /restart-device <instance ID>` (requires administrator);
4. Re-check the status until it returns to `CM_PROB_NONE`.

This script automates that workflow: run it directly the next time the same kind of failure occurs.

## What the Script Tries to Fix

- Targets all **AMD graphics** display devices (PCI `VEN_1002` or name containing `Radeon`/`AMD`); other display adapters (virtual displays, other GPU vendors) are never touched.
- **Code 22 (device disabled)**: enables the device with `Enable-PnpDevice`.
- **Code 31 (`CM_PROB_FAILED_ADD`) and similar driver-load errors (e.g. Code 43)**: forces device re-initialization with `pnputil /restart-device`.
- Up to **3 attempts per device**, waiting a few seconds between each action, and re-checking status after each step.
- Prints a per-device summary at the end and returns an exit code. If a device is still broken, it suggests rebooting or reinstalling the driver.

## Script Logic

1. **Privilege check**: without administrator rights, the script self-elevates via UAC (click "Yes" on the prompt). The elevated instance writes its output to `%TEMP%\amd_gpu_fix.log`; the parent process waits and echoes the log so the result is always visible.
2. **Device scan**: enumerates display devices and filters AMD GPUs only.
3. **Per-device handling**:
   - `CM_PROB_NONE` (healthy) → skipped;
   - `CM_PROB_DISABLED` (Code 22) → enable the device, wait 5 s;
   - other driver-load errors (Code 31/43, …) → force device restart, wait 6 s;
   - re-read device status after each action; retry up to 3 rounds if not recovered.
4. **Reporting**: prints the final status of every device and gives a recommendation if any device remains broken.

## Usage

```powershell
# Detect and attempt repair (recommended; self-elevates via UAC)
powershell -ExecutionPolicy Bypass -File amd-gpu-fix.ps1

# Report only, no modifications
powershell -ExecutionPolicy Bypass -File amd-gpu-fix.ps1 -Diagnose

# Skip auto-elevation (debug only; repair actions require administrator)
powershell -ExecutionPolicy Bypass -File amd-gpu-fix.ps1 -NoElevate
```

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | All AMD GPUs are healthy |
| 1 | Some device is still broken (reboot and retry) |
| 2 | Elevation canceled or failed |
| 3 | No AMD GPU found |

## Notes

- Requires Windows 10 1809+ / Windows 11 (`Enable-PnpDevice` and `pnputil /restart-device` need these versions).
- Repair actions require administrator rights; the script auto-requests UAC elevation.
- The script only fixes software-level issues (disabled device / driver load failure). If a Code 43 persists after a reboot, the hardware may be faulty — reinstall the driver, and seek repair if needed.
