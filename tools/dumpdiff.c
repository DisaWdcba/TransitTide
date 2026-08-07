// dumpdiff.c — verify memory-vs-disk divergence of a named section at scan time
// usage: dumpdiff <pid> <section-name>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>

#pragma comment(lib, "psapi.lib")

static int ReadFileBytes(const wchar_t* path, BYTE** out, DWORD* outLen) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    DWORD len = GetFileSize(h, NULL);
    BYTE* buf = (BYTE*)malloc(len);
    DWORD rd = 0;
    ReadFile(h, buf, len, &rd, NULL);
    CloseHandle(h);
    *out = buf;
    *outLen = len;
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        printf("usage: dumpdiff <pid> <section-name> [offset-hex]\n");
        return 1;
    }
    DWORD pid = (DWORD)_wtoi(argv[1]);
    char secName[16] = {0};
    WideCharToMultiByte(CP_ACP, 0, argv[2], -1, secName, sizeof(secName), NULL, NULL);
    DWORD off = (argc > 3) ? (DWORD)wcstoul(argv[3], NULL, 16) : 0;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) { printf("open failed %lu\n", GetLastError()); return 1; }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("snapshot failed %lu\n", GetLastError());
        return 1;
    }
    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    int found = 0;
    for (BOOL ok = Module32FirstW(snap, &me); ok; ok = Module32NextW(snap, &me)) {
        wchar_t* bn = wcsrchr(me.szExePath, L'\\');
        if (!bn) continue;
        if (_wcsicmp(bn + 1, L"bypass_mingw.exe") != 0 &&
            _wcsicmp(bn + 1, L"bypass.exe") != 0) continue;
        found = 1;
        ULONGLONG base = (ULONGLONG)me.modBaseAddr;
        wchar_t path[MAX_PATH];
        wcscpy(path, me.szExePath);
        BYTE hdr[0x400];
        SIZE_T got = 0;
        ReadProcessMemory(hProc, (LPCVOID)base, hdr, sizeof(hdr), &got);
        if (got < 0x400 || hdr[0] != 'M' || hdr[1] != 'Z') { printf("bad header\n"); return 1; }
        DWORD peOff = *(DWORD*)(hdr + 0x3C);
        WORD nsec = *(WORD*)(hdr + peOff + 6);
        DWORD optSize = *(WORD*)(hdr + peOff + 20);
        BYTE* secTab = hdr + peOff + 24 + optSize;

        DWORD secRva = 0, secRaw = 0, secRawSize = 0, secVirtSize = 0;
        for (int s = 0; s < nsec; s++) {
            BYTE* sh = secTab + s * 40;
            if (strncmp((char*)sh, secName, 8) == 0) {
                secVirtSize = *(DWORD*)(sh + 8);
                secRva = *(DWORD*)(sh + 12);
                secRaw = *(DWORD*)(sh + 20);
                secRawSize = *(DWORD*)(sh + 16);
                break;
            }
        }
        if (!secRva) { printf("section %s not found\n", secName); return 1; }

        BYTE* disk = NULL;
        DWORD diskLen = 0;
        if (ReadFileBytes(path, &disk, &diskLen)) { printf("disk read failed\n"); return 1; }
        DWORD cmpLen = secRawSize < secVirtSize ? secRawSize : secVirtSize;
        if (secRaw + cmpLen > diskLen) cmpLen = diskLen - secRaw;

        BYTE* mem = (BYTE*)malloc(cmpLen ? cmpLen : 1);
        ReadProcessMemory(hProc, (LPCVOID)(base + secRva + off), mem, cmpLen, &got);

        DWORD diff = 0;
        for (DWORD i = 0; i < cmpLen; i++) {
            if (mem[i] != disk[secRaw + off + i]) diff++;
        }
        printf("[dumpdiff] %ls %s+0x%X RVA=0x%X raw=0x%X size=%lu mem!=disk bytes: %lu / %lu\n",
               bn + 1, secName, off, secRva, secRaw, cmpLen, diff, cmpLen);
        if (diff) {
            printf("[dumpdiff] first divergent offsets:");
            int shown = 0;
            for (DWORD i = 0; i < cmpLen && shown < 6; i++) {
                if (mem[i] != disk[secRaw + off + i]) {
                    printf(" +0x%X(%02X->%02X)", i, disk[secRaw + off + i], mem[i]);
                    shown++;
                }
            }
            printf("\n");
        }
        free(mem);
        free(disk);
        return 0;
    }
    printf("harness module not found\n");
    return 1;
}
