$sig = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class WinEnum3 {
    public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
}
'@
Add-Type $sig
$out = @()
$cb = [WinEnum3+EnumProc]{
    param($h, $l)
    $sb = New-Object System.Text.StringBuilder 512
    [WinEnum3]::GetWindowTextW($h, $sb, 512) | Out-Null
    $procId = 0
    [WinEnum3]::GetWindowThreadProcessId($h, [ref]$procId) | Out-Null
    if ($sb.ToString() -match "SleepMask|PIC|direct") {
        $script:out += ("h=" + $h + " pid=" + $procId + " title=[" + $sb.ToString() + "]")
    }
    return $true
}
[WinEnum3]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
[System.IO.File]::WriteAllLines($args[0], $out, [System.Text.UTF8Encoding]::new($false))
Write-Output ("found " + $out.Count)
