#pragma once


#ifndef THREAD_STACK_SPPOFING
#define THREAD_STACK_SPPOFING


typedef struct _THREAD_TO_SPOOF 
{
    DWORD dwProcessId;
    DWORD dwThreadId;
    PVOID pvStartAddr;
    ULONG cbTotalRequiredStackSize;
    PVOID pvFakeStackBuffer;

} THREAD_TO_SPOOF, * PTHREAD_TO_SPOOF;


BOOL InitialiseDynamicCallStackSpoofing(IN ULONG ulWaitReason, OUT PTHREAD_TO_SPOOF pThreadToSpoof);

#endif // !THREAD_STACK_SPPOFING
