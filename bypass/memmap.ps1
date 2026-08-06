# memmap.ps1 - dump memory regions of a target process (VirtualQueryEx)
param([int]$procId)
$code = @"
using System;
using System.Runtime.InteropServices;
public struct MBI {
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public IntPtr RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
}
public class MemMap2 {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint a, bool b, int p);
    [DllImport("kernel32.dll")] public static extern bool VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr len);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
"@
Add-Type -TypeDefinition $code -Language CSharp
$h = [MemMap2]::OpenProcess(0x0400, $false, $procId)  # PROCESS_QUERY_INFORMATION
if ($h -eq [IntPtr]::Zero) { Write-Output "open failed"; exit 1 }
function Prot($p) {
    switch ($p) {
        0x00000010 { return "EXECUTE" }
        0x00000020 { return "EXECUTE_READ" }
        0x00000040 { return "EXECUTE_RW" }
        0x00000080 { return "EXECUTE_WRITECOPY" }
        0x00000002 { return "READONLY" }
        0x00000004 { return "READWRITE" }
        0x00000008 { return "WRITECOPY" }
        0x00000001 { return "NOACCESS" }
        default { return ("0x" + $p.ToString("X")) }
    }
}
function T($t) {
    switch ($t) {
        0x1000000 { return "IMAGE" }
        0x2000000 { return "MAPPED" }
        0x40000   { return "PRIVATE" }
        default   { return ("0x" + $t.ToString("X")) }
    }
}
$addr = [IntPtr]::Zero
$out = @()
while ($true) {
    $mbi = New-Object MBI
    $ok = [MemMap2]::VirtualQueryEx($h, $addr, [ref]$mbi, [IntPtr][System.Runtime.InteropServices.Marshal]::SizeOf([type][MBI]))
    if (-not $ok) { break }
    if ($mbi.State -eq 0x1000) {  # MEM_COMMIT
        $out += ("{0:X16} {1,8:X} {2,-14} {3,-8} {4}" -f $mbi.BaseAddress.ToInt64(), $mbi.RegionSize.ToInt64(), (Prot $mbi.Protect), (T $mbi.Type), $mbi.AllocationBase.ToInt64().ToString("X16"))
    }
    $next = $mbi.BaseAddress.ToInt64() + $mbi.RegionSize.ToInt64()
    if ($next -le $addr.ToInt64()) { break }
    $addr = [IntPtr]$next
}
[MemMap2]::CloseHandle($h) | Out-Null
[System.IO.File]::WriteAllLines($args[0], $out, [System.Text.UTF8Encoding]::new($false))
Write-Output ("wrote " + $out.Count + " regions")
