#pragma once
#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <Windows.h>
#include <immintrin.h> 

#include "Hashes.h"
#include "DebugMacros.h"
#include "Configuration.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Used Only In HellsHall.c
// 
// Utilized If We Dont Want To Use The Trap Syscall Tampering Method
typedef struct _NT_SYSCALL
{
    DWORD dwSSn;                    // syscall number
    DWORD dwSyscallHash;            // syscall hash value
    PVOID pSyscallAddress;          // syscall address
    PVOID pSyscallInstAddress;      // address of a random 'syscall' instruction in ntdll    

} NT_SYSCALL, * PNT_SYSCALL;

// From HellsAsm.c 
extern VOID SetSSn(IN DWORD dwSSn, IN PVOID pSyscallInstAddress);
extern RunSyscall();


#define SET_SYSCALL(NtSys)(SetSSn((DWORD)NtSys.dwSSn,(PVOID)NtSys.pSyscallInstAddress))


// From HellsHall.c
BOOL InitNtdllConfigStructure(IN HMODULE hNtdllModule);
BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys);


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#ifdef TRAP_SYSCALLS_TAMPERING

#define EFLAGS_TF			0x100

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL InitializeTrapSyscallsVectoredHandler();
BOOL DestroyTrapSyscallsVectoredHandler();

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static ULONG_PTR GenRandomArg()
{
    unsigned __int64 ui64RndValue = 0x00;
    for (int i = 0; i < 0x0A; i++)
    {
        if (_rdrand64_step(&ui64RndValue))
        {
            return (ULONG_PTR)ui64RndValue;
        }
        _mm_pause();
    }
    return 0x00;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

extern BYTE GenRandomByte();
extern FARPROC GetNtProcAddress(IN DWORD dwFunctionHash);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef NTSTATUS(WINAPI* fnSyscallFunction)();

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static DWORD g_dwSyscallHashArray[] =
{
    FNV1A_NtDrawText,
    FNV1A_NtQueryDefaultUILanguage,
    FNV1A_NtGetCurrentProcessorNumber,
    FNV1A_NtOpenEventPair
};


static DWORD FetchRandomSyscallHash()
{
    BYTE bRandomByte = 0x00;

    bRandomByte = GenRandomByte();
    bRandomByte = bRandomByte % _countof(g_dwSyscallHashArray);

    DBG_PRINT_A("[v] Using Dummy Syscall (%d) Hash: 0x%08X", (int)bRandomByte, g_dwSyscallHashArray[bRandomByte]);

    return g_dwSyscallHashArray[bRandomByte];
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


#define INVOKE_SYSCALL(dwSyscallHash, STATUS, ...)                                         \
do {                                                                                       \
    CONTEXT             ThreadCtx               = { 0 };                                   \
    fnSyscallFunction   pRealSyscallAddress     = NULL;                                    \
    fnSyscallFunction   pDummySyscallAddress    = NULL;                                    \
    ULONG_PTR           uArg1                   = GenRandomArg();                          \
    ULONG_PTR           uArg2                   = GenRandomArg();                          \
    ULONG_PTR           uArg3                   = GenRandomArg();                          \
    ULONG_PTR           uArg4                   = GenRandomArg();                          \
    ULONG_PTR           uArg5                   = GenRandomArg();                          \
    ULONG_PTR           uArg6                   = GenRandomArg();                          \
                                                                                           \
    ThreadCtx.ContextFlags = CONTEXT_CONTROL;                                              \
                                                                                           \
    pRealSyscallAddress  = (fnSyscallFunction)GetNtProcAddress(dwSyscallHash);             \
    pDummySyscallAddress = (fnSyscallFunction)GetNtProcAddress(FetchRandomSyscallHash());  \
                                                                                           \
    GetThreadContext((HANDLE)-2, &ThreadCtx);                                              \
    ThreadCtx.EFlags |= EFLAGS_TF;                                                         \
    SetThreadContext((HANDLE)-2, &ThreadCtx);                                              \
                                                                                           \
    pRealSyscallAddress(uArg1, uArg2, uArg3, uArg4, uArg5, uArg6);                         \
                                                                                           \
    STATUS = pDummySyscallAddress(__VA_ARGS__);                                            \
                                                                                           \
} while(0)

#else // !TRAP_SYSCALLS_TAMPERING

#define INVOKE_SYSCALL(dwSyscallHash, STATUS, ...)                                          \
do                                                                                          \
{                                                                                           \
    NT_SYSCALL NtSys = { 0 };                                                               \
                                                                                            \
    if (FetchNtSyscall(dwSyscallHash, &NtSys))                                              \
    {                                                                                       \
        SET_SYSCALL(NtSys);															        \
        STATUS = RunSyscall(__VA_ARGS__);                                                   \
    }                                                                                       \
    else                                                                                    \
		STATUS = MANUAL_SYSCALL_INVOKING_PRBLM;                                             \
                                                                                            \
} while(0)                                                                                  


#endif // TRAP_SYSCALLS_TAMPERING

#endif // !SYSCALLS_H