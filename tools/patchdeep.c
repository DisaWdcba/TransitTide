// patchdeep.c — patch a function buried deep inside .text (+0x5000-ish)
#include <windows.h>
#include <stdio.h>

__attribute__((section(".text.dp"), noinline)) static int deep(void) {
    return 0x55667788;
}

int main(void) {
    printf("deep=%p pid=%lu\n", (void*)&deep, GetCurrentProcessId());
    DWORD old = 0;
    if (!VirtualProtect((void*)&deep, 16, PAGE_EXECUTE_READWRITE, &old)) {
        printf("VP failed %lu\n", GetLastError());
        return 1;
    }
    unsigned char* p = (unsigned char*)&deep;
    for (int i = 0; i < 4; i++) p[i] = 0x90;
    printf("patched, sleeping 30s\n");
    fflush(stdout);
    Sleep(30000);
    return 0;
}
