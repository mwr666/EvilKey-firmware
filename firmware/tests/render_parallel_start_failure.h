/* Test-only OS shim: fail creation of the second actual worker. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static inline HANDLE ek_test_CreateThread(LPSECURITY_ATTRIBUTES attributes,
    SIZE_T stack_size, LPTHREAD_START_ROUTINE entry, LPVOID argument,
    DWORD flags, LPDWORD id) {
    static unsigned attempts;
    if (++attempts == 2) return NULL;
    return CreateThread(attributes, stack_size, entry, argument, flags, id);
}
#define CreateThread ek_test_CreateThread
