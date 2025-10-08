/*
 * Enumeration BOF Template
 * =========================
 *
 * BOF for system enumeration and reconnaissance
 * Quick information gathering for situational awareness
 *
 * Author: Noctis-MCP
 */

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

// ============================================================================
// BOF API
// ============================================================================

DECLSPEC_IMPORT void BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void* BeaconDataParse(char* buffer, int size);

// ============================================================================
// ENUMERATION FUNCTIONS
// ============================================================================

/**
 * Enumerate running processes
 */
void EnumProcesses() {
    HANDLE hSnapshot = NULL;
    PROCESSENTRY32 pe32;

    BeaconPrintf(0, "\n[*] Enumerating Processes:");
    BeaconPrintf(0, "========================================");

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(1, "[!] CreateToolhelp32Snapshot failed");
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            BeaconPrintf(0, "  [%5d] %s", pe32.th32ProcessID, pe32.szExeFile);
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    BeaconPrintf(0, "========================================\n");
}

/**
 * Get system information
 */
void GetSystemInfo() {
    char computerName[256];
    char userName[256];
    DWORD size = sizeof(computerName);
    OSVERSIONINFOA osvi;

    BeaconPrintf(0, "\n[*] System Information:");
    BeaconPrintf(0, "========================================");

    // Computer name
    if (GetComputerNameA(computerName, &size)) {
        BeaconPrintf(0, "  Computer Name: %s", computerName);
    }

    // User name
    size = sizeof(userName);
    if (GetUserNameA(userName, &size)) {
        BeaconPrintf(0, "  User Name: %s", userName);
    }

    // OS version
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
    if (GetVersionExA(&osvi)) {
        BeaconPrintf(0, "  OS Version: %d.%d (Build %d)",
            osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    }

    // Architecture
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    BeaconPrintf(0, "  Architecture: %s",
        si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86");

    BeaconPrintf(0, "========================================\n");
}

/**
 * Check for security products
 */
void CheckSecurityProducts() {
    const char* securityProcs[] = {
        "MsMpEng.exe",      // Windows Defender
        "AvastSvc.exe",     // Avast
        "avgnt.exe",        // Avira
        "bdagent.exe",      // Bitdefender
        "ccSvcHst.exe",     // Norton
        "MBAMService.exe",  // Malwarebytes
        "SentinelAgent.exe" // SentinelOne
    };

    BeaconPrintf(0, "\n[*] Checking for Security Products:");
    BeaconPrintf(0, "========================================");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    BOOL found = FALSE;

    if (Process32First(hSnapshot, &pe32)) {
        do {
            for (int i = 0; i < sizeof(securityProcs) / sizeof(char*); i++) {
                if (_stricmp(pe32.szExeFile, securityProcs[i]) == 0) {
                    BeaconPrintf(1, "  [!] Detected: %s (PID: %d)",
                        pe32.szExeFile, pe32.th32ProcessID);
                    found = TRUE;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    if (!found) {
        BeaconPrintf(0, "  [+] No common security products detected");
    }

    CloseHandle(hSnapshot);
    BeaconPrintf(0, "========================================\n");
}

// ============================================================================
// BOF ENTRY POINT
// ============================================================================

void go(char* args, int length) {
    BeaconPrintf(0, "[*] Enumeration BOF - System Reconnaissance");

    // System information
    GetSystemInfo();

    // Security products
    CheckSecurityProducts();

    // Process list
    EnumProcesses();

    BeaconPrintf(0, "[+] Enumeration complete");
}
