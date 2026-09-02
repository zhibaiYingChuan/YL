#include <windows.h>

__declspec(noreturn) void WINAPI pe_entry(void) {
    static const char message[] = "Hello, PE!\n";
    DWORD written = 0;
    BOOL ok = WriteFile(
        NULL,
        message,
        (DWORD)(sizeof(message) - 1),
        &written,
        NULL);
    ExitProcess(ok && written == sizeof(message) - 1 ? 0 : 1);
}
