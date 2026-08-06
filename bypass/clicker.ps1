# clicker.ps1 - waits for the demo MessageBox, then clicks its OK button.
# Reliable dismissal: find the dialog, then EITHER SendMessage(WM_COMMAND,
# IDOK) synchronously OR BM_CLICK its IDOK button via EnumChildWindows.
$sig = @'
[DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindowW(string cls, string title);
[DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
[DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr parent, EnumProc cb, IntPtr l);
public delegate bool EnumProc(IntPtr h, IntPtr l);
[DllImport("user32.dll")] public static extern int GetClassNameW(IntPtr h, System.Text.StringBuilder s, int n);
'@
Add-Type -MemberDefinition $sig -Name C -Namespace N
for ($i = 0; $i -lt 100; $i++) {
    $dlg = [N.C]::FindWindowW([NullString]::Value, 'SleepMask Bypass Demo')
    if ($dlg -ne [IntPtr]::Zero) {
        # method 1: synchronous WM_COMMAND IDOK
        [N.C]::SendMessageW($dlg, 0x0111, [IntPtr]1, [IntPtr]::Zero) | Out-Null
        Start-Sleep -Milliseconds 300
        # method 2: BM_CLICK on the Button child (class "Button")
        $btn = [IntPtr]::Zero
        $cb = [N.C+EnumProc]{ param($h, $l) $sb = New-Object System.Text.StringBuilder 64; [N.C]::GetClassNameW($h, $sb, 64) | Out-Null; if ($sb.ToString() -eq 'Button') { $script:btn = $h; return $false }; return $true }
        [N.C]::EnumChildWindows($dlg, $cb, [IntPtr]::Zero) | Out-Null
        if ($btn -ne [IntPtr]::Zero) {
            [N.C]::SendMessageW($btn, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
            Write-Output "BM_CLICK on button $btn of dialog $dlg"
        } else {
            Write-Output "WM_COMMAND sent to dialog $dlg (no Button child found)"
        }
        exit 0
    }
    Start-Sleep -Milliseconds 200
}
Write-Output "dialog not found within 20s"
exit 1
