/*
 * Base BOF Template
 * =================
 *
 * Minimal Beacon Object File template compatible with:
 * - Sliver C2
 * - Cobalt Strike
 * - Adaptix C2
 * - Brute Ratel
 *
 * Author: Noctis-MCP
 */

#include <windows.h>

// ============================================================================
// BOF API DECLARATIONS
// ============================================================================

// Beacon output functions
DECLSPEC_IMPORT void BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void BeaconOutput(int type, char* data, int len);

// Beacon data parsing (for arguments)
DECLSPEC_IMPORT void* BeaconDataParse(char* buffer, int size);
DECLSPEC_IMPORT int BeaconDataInt(void* parser);
DECLSPEC_IMPORT short BeaconDataShort(void* parser);
DECLSPEC_IMPORT int BeaconDataLength(void* parser);
DECLSPEC_IMPORT char* BeaconDataExtract(void* parser, int* size);

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Example helper function
 */
void PrintBanner() {
    BeaconPrintf(0, "====================================");
    BeaconPrintf(0, "  Noctis-MCP BOF Template");
    BeaconPrintf(0, "====================================");
}

// ============================================================================
// BOF ENTRY POINT
// ============================================================================

/**
 * BOF entry point - called by C2 framework
 *
 * Args:
 *   args   - Packed arguments from C2
 *   length - Length of args buffer
 */
void go(char* args, int length) {
    // Print banner
    PrintBanner();

    // Parse arguments (example)
    void* parser = BeaconDataParse(args, length);

    // Example: Extract integer argument
    // int arg1 = BeaconDataInt(parser);
    // BeaconPrintf(0, "[*] Received argument: %d", arg1);

    // Example: Extract string argument
    // int size = 0;
    // char* arg2 = BeaconDataExtract(parser, &size);
    // BeaconPrintf(0, "[*] Received string: %s", arg2);

    // ========================================
    // YOUR CODE HERE
    // ========================================

    BeaconPrintf(0, "[*] BOF execution started");

    // Example: Get computer name
    char computerName[256];
    DWORD nameSize = sizeof(computerName);
    if (GetComputerNameA(computerName, &nameSize)) {
        BeaconPrintf(0, "[+] Computer Name: %s", computerName);
    } else {
        BeaconPrintf(1, "[!] Failed to get computer name");
    }

    // ========================================

    BeaconPrintf(0, "[+] BOF execution complete");
}
