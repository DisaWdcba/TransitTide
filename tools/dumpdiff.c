// dumpdiff.c — verify memory-vs-disk divergence of a named section at scan time
// usage: dumpdiff <pid> <section-name>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <psapi.h>

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
        printf("usage: dumpdiff <pid> <section-name>\n");
        return 1;
    }
    DWORD pid = (DWORD)_wtoi(argv[1]);
    char secName[16] = {0};
    WideCharToMultiByte(CP_ACP, 0, argv[2], -1, secName, sizeof(secName), NULL, NULL);

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) { printf("open failed %lu\n", GetLastError()); return 1; }

    HMODULE mods[256];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
        printf("enum failed %lu\n", GetLastError());
        return 1;
    }
    int nMods = needed / sizeof(HMODULE);

    for (int m = 0; m < nMods; m++) {
        wchar_t path[MAX_PATH] = {0};
        DWORD plen = GetModuleFileNameExW(hProc, mods[m], path, MAX_PATH);
        if (!plen) continue;
        wchar_t* bn = wcsrchr(path, L'\\');
        if (!bn) continue;
        if (_wcsicmp(bn + 1, L"bypass_mingw.exe") != 0 &&
            _wcsicmp(bn + 1, L"bypass.exe") != 0) continue;

        ULONGLONG base = (ULONGLONG)mods[m];
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
        ReadProcessMemory(hProc, (LPCVOID)(base + secRva), mem, cmpLen, &got);

        DWORD diff = 0;
        for (DWORD i = 0; i < cmpLen; i++) {
            if (mem[i] != disk[secRaw + i]) diff++;
        }
        printf("[dumpdiff] %ls %s RVA=0x%X raw=0x%X size=%lu mem!=disk bytes: %lu / %lu\n",
               bn + 1, secName, secRva, secRaw, cmpLen, diff, cmpLen);
        if (diff) {
            printf("[dumpdiff] first divergent offsets:");
            int shown = 0;
            for (DWORD i = 0; i < cmpLen && shown < 6; i++) {
                if (mem[i] != disk[secRaw + i]) {
                    printf(" +0x%X(%02X->%02X)", i, disk[secRaw + i], mem[i]);
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
