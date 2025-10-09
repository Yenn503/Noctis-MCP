// Noctis API Hashing - Quick Test Sample
// Demonstrates full operation of API hashing system

#include <windows.h>
#include <stdio.h>
#include "api_hashing.h"

// Function typedefs
typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR);
typedef LPVOID(WINAPI* fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* fnVirtualFree)(LPVOID, SIZE_T, DWORD);

int main() {
    printf("========================================\n");
    printf("Noctis API Hashing - Full Test\n");
    printf("========================================\n\n");

    // ================================================================
    // TEST 1: Get Module Handle by Hash
    // ================================================================
    printf("[TEST 1] Get Module Handles by Hash\n");
    printf("------------------------------------\n");

    HMODULE hNtdll = Noctis_GetModuleHandleByHash(HASH_ntdll_dll);
    printf("  ntdll.dll (hash 0x%08X): %s\n",
           HASH_ntdll_dll,
           hNtdll ? "SUCCESS" : "FAILED");
    printf("    Address: 0x%p\n", hNtdll);

    HMODULE hKernel32 = Noctis_GetModuleHandleByHash(HASH_kernel32_dll);
    printf("  kernel32.dll (hash 0x%08X): %s\n",
           HASH_kernel32_dll,
           hKernel32 ? "SUCCESS" : "FAILED");
    printf("    Address: 0x%p\n", hKernel32);

    if (!hNtdll || !hKernel32) {
        printf("\n[FAIL] Module resolution failed!\n");
        return 1;
    }

    printf("\n");

    // ================================================================
    // TEST 2: Get Function Address by Hash
    // ================================================================
    printf("[TEST 2] Get Function Addresses by Hash\n");
    printf("----------------------------------------\n");

    // Test LoadLibraryA
    fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)
        Noctis_GetProcAddressByHash(hKernel32, HASH_LoadLibraryA);
    printf("  LoadLibraryA (hash 0x%08X): %s\n",
           HASH_LoadLibraryA,
           pLoadLibraryA ? "SUCCESS" : "FAILED");
    printf("    Address: 0x%p\n", pLoadLibraryA);

    // Test VirtualAlloc
    fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)
        Noctis_GetProcAddressByHash(hKernel32, HASH_VirtualAlloc);
    printf("  VirtualAlloc (hash 0x%08X): %s\n",
           HASH_VirtualAlloc,
           pVirtualAlloc ? "SUCCESS" : "FAILED");
    printf("    Address: 0x%p\n", pVirtualAlloc);

    // Test VirtualFree
    fnVirtualFree pVirtualFree = (fnVirtualFree)
        Noctis_GetProcAddressByHash(hKernel32, HASH_VirtualFree);
    printf("  VirtualFree (hash 0x%08X): %s\n",
           HASH_VirtualFree,
           pVirtualFree ? "SUCCESS" : "FAILED");
    printf("    Address: 0x%p\n", pVirtualFree);

    if (!pLoadLibraryA || !pVirtualAlloc || !pVirtualFree) {
        printf("\n[FAIL] Function resolution failed!\n");
        return 1;
    }

    printf("\n");

    // ================================================================
    // TEST 3: Actually USE the resolved functions
    // ================================================================
    printf("[TEST 3] Execute Resolved Functions\n");
    printf("------------------------------------\n");

    // Allocate memory using hashed VirtualAlloc
    printf("  Allocating 4096 bytes with VirtualAlloc (by hash)...\n");
    LPVOID pMem = pVirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pMem) {
        printf("    SUCCESS: Allocated at 0x%p\n", pMem);

        // Write test data
        memcpy(pMem, "Noctis-MCP API Hashing Works!", 30);
        printf("    Wrote test data: \"%s\"\n", (char*)pMem);

        // Free memory
        printf("  Freeing memory with VirtualFree (by hash)...\n");
        if (pVirtualFree(pMem, 0, MEM_RELEASE)) {
            printf("    SUCCESS: Memory freed\n");
        } else {
            printf("    FAILED: VirtualFree returned false\n");
        }
    } else {
        printf("    FAILED: VirtualAlloc returned NULL\n");
        return 1;
    }

    printf("\n");

    // ================================================================
    // TEST 4: Compare with standard GetProcAddress
    // ================================================================
    printf("[TEST 4] Verify Hashing Matches Standard Resolution\n");
    printf("----------------------------------------------------\n");

    // Get VirtualAlloc the normal way
    fnVirtualAlloc pVirtualAlloc_Normal = (fnVirtualAlloc)
        GetProcAddress(hKernel32, "VirtualAlloc");

    printf("  VirtualAlloc via GetProcAddress: 0x%p\n", pVirtualAlloc_Normal);
    printf("  VirtualAlloc via API hashing:    0x%p\n", pVirtualAlloc);

    if (pVirtualAlloc == pVirtualAlloc_Normal) {
        printf("    SUCCESS: Addresses match!\n");
    } else {
        printf("    FAILED: Addresses don't match!\n");
        return 1;
    }

    printf("\n");

    // ================================================================
    // TEST 5: Hash Calculation Verification
    // ================================================================
    printf("[TEST 5] Hash Calculation Verification\n");
    printf("---------------------------------------\n");

    // Calculate hash at runtime and compare to precomputed
    DWORD dwRuntimeHash = Noctis_HashDJB2("VirtualAlloc");
    printf("  Runtime hash of \"VirtualAlloc\":  0x%08X\n", dwRuntimeHash);
    printf("  Precomputed HASH_VirtualAlloc:   0x%08X\n", HASH_VirtualAlloc);

    if (dwRuntimeHash == HASH_VirtualAlloc) {
        printf("    SUCCESS: Hashes match!\n");
    } else {
        printf("    FAILED: Hashes don't match!\n");
        return 1;
    }

    printf("\n");

    // ================================================================
    // FINAL RESULTS
    // ================================================================
    printf("========================================\n");
    printf("ALL TESTS PASSED!\n");
    printf("========================================\n");
    printf("\nAPI Hashing is working correctly:\n");
    printf("  - Module resolution: OK\n");
    printf("  - Function resolution: OK\n");
    printf("  - Function execution: OK\n");
    printf("  - Hash verification: OK\n");
    printf("\nNoctis-MCP API Hashing system is OPERATIONAL!\n\n");

    return 0;
}
