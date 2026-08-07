// patchself.c — textbook in-memory self-modification of .text
#include <windows.h>
#include <stdio.h>

__declspec(noinline) static int target(void) { return 0x11223344; }

int main(void) {
    printf("target=%p pid=%lu\n", (void*)&target, GetCurrentProcessId());
    DWORD old = 0;
    if (!VirtualProtect((void*)&target, 16, PAGE_EXECUTE_READWRITE, &old)) {
        printf("VP failed %lu\n", GetLastError());
        return 1;
    }
    unsigned char* p = (unsigned char*)&target;
    for (int i = 0; i < 4; i++) p[i] = 0x90; // stomp the prologue with NOPs
    printf("patched, sleeping 30s\n");
    fflush(stdout);
    Sleep(30000);
    printf("done\n");
    return 0;
}
