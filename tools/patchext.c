// patchext.c — patch a function in a SECOND code section (.payx, RX)
#include <windows.h>
#include <stdio.h>

__asm__(".section .payx,\"ax\"\n\t.text");
__attribute__((section(".payx"), noinline)) static int ext(void) {
    return 0x99AABBCC;
}

int main(void) {
    printf("ext=%p pid=%lu\n", (void*)&ext, GetCurrentProcessId());
    DWORD old = 0;
    if (!VirtualProtect((void*)&ext, 16, PAGE_EXECUTE_READWRITE, &old)) {
        printf("VP failed %lu\n", GetLastError());
        return 1;
    }
    unsigned char* p = (unsigned char*)&ext;
    for (int i = 0; i < 4; i++) p[i] = 0x90;
    printf("patched, sleeping 30s\n");
    fflush(stdout);
    Sleep(30000);
    return 0;
}
