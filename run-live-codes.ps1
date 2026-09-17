# Окно с кодами 2FA поверх всех окон (удобно держать рядом с браузером).
#
# Запуск (в папке проекта):
#   powershell -ExecutionPolicy Bypass -File .\run-live-codes.ps1
#   .\run-live-codes.ps1 -Filter github     # только записи со словом "github"
#   .\run-live-codes.ps1 -TopLeft           # прижать окно в левый верхний угол
#   .\run-live-codes.ps1 -NoTopMost         # не закреплять поверх остальных
param(
    [string]$Filter = "",
    [switch]$TopLeft,
    [switch]$NoTopMost
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

# Ищем Python: сначала py -3 (стандартный лаунчер Windows), затем python
if (Get-Command py -ErrorAction SilentlyContinue) {
    $exe = "py"; $pre = @("-3")
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $exe = "python"; $pre = @()
} else {
    throw "Python не найден в PATH. Установите с python.org и отметьте 'Add Python to PATH'."
}

$args = $pre + @((Join-Path $root "gauth.py"), "codes")
if ($Filter) { $args += $Filter }

$proc = Start-Process -FilePath $exe -ArgumentList $args -WorkingDirectory $root -PassThru
Start-Sleep -Milliseconds 1200

if (-not $NoTopMost) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WinTop {
    [DllImport("user32.dll")]
    public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    public static extern bool MoveWindow(IntPtr h, int x, int y, int cx, int cy, bool repaint);
    public static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
    public const uint SWP_NOMOVE = 0x2, SWP_NOSIZE = 0x1;
}
"@
    $hwnd = [WinTop]::GetForegroundWindow()
    if ($TopLeft) {
        [WinTop]::MoveWindow($hwnd, 0, 0, 780, 620, $true) | Out-Null
        [WinTop]::SetWindowPos($hwnd, [WinTop]::HWND_TOPMOST, 0, 0, 0, 0,
            [WinTop]::SWP_NOMOVE -bor [WinTop]::SWP_NOSIZE) | Out-Null
    } else {
        [WinTop]::SetWindowPos($hwnd, [WinTop]::HWND_TOPMOST, 0, 0, 0, 0,
            [WinTop]::SWP_NOMOVE -bor [WinTop]::SWP_NOSIZE) | Out-Null
    }
}

Write-Host "Окно кодов запущено (PID $($proc.Id))."
Write-Host ("Фильтр: " + $(if ($Filter) { $Filter } else { "нет — все аккаунты" }))
if (-not $NoTopMost) { Write-Host "Окно закреплено поверх остальных. Отключить: -NoTopMost" }
Write-Host "Остановить: Ctrl+C в окне кодов  или  Stop-Process -Id $($proc.Id)"
