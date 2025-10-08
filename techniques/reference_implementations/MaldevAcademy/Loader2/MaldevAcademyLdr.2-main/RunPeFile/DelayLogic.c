#include <Windows.h>
#include <stdio.h>

#include "Utilities.h"
#include "DebugMacros.h"

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#define MIN_THREADPOOL_THREADS  4
#define MAX_THREADPOOL_THREADS  6

#define NUM_WORK_ITEMS          6

#define MAX_PRIME_LIMIT         100 * 100000


typedef struct _PRIME_RANGE 
{
    INT iStart;
    INT iEnd;

} PRIME_RANGE, * PPRIME_RANGE;


typedef struct _TIMING_INFO 
{
    ULONGLONG       ullStartTime;
    ULONGLONG       ullMaxDuration;
    volatile LONG   bTimeExpired;

} TIMING_INFO, * PTIMING_INFO;

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

PTP_POOL                g_hPool                     = NULL;
TP_CALLBACK_ENVIRON     g_CallbackEnv               = { 0 };
PTP_CLEANUP_GROUP       g_CleanupGroup              = NULL;
volatile LONG           g_PrimeCounter              = 0x00;
volatile LONG           g_IterationCounter          = 0x00;
TIMING_INFO             g_TimingInfo                = { 0 };
PTP_TIMER               g_hTimer                    = NULL;

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

VOID CALLBACK TimeCheckCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_TIMER Timer) {

    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Timer);

    PTIMING_INFO    pTimingInfo     = (PTIMING_INFO)Context;
    ULONGLONG       ullCurrentTime  = GetTickCount64();
    ULONGLONG       ullElapsed      = ullCurrentTime - pTimingInfo->ullStartTime;

    if (ullElapsed >= pTimingInfo->ullMaxDuration) 
    {
        InterlockedExchange(&pTimingInfo->bTimeExpired, TRUE);
    }
}

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

VOID CALLBACK PrimeCalculatorCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work) 
{

    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Work);

    PPRIME_RANGE    pPrimeRange             = (PPRIME_RANGE)Context;
    INT             iLocalIterations        = 0x00;

    while (InterlockedCompareExchange(&g_TimingInfo.bTimeExpired, TRUE, TRUE) != TRUE) 
    {
        for (int num = pPrimeRange->iStart; num <= pPrimeRange->iEnd; num++) 
        {
            BOOL bIsPrime = TRUE;

            if (InterlockedCompareExchange(&g_TimingInfo.bTimeExpired, TRUE, TRUE) == TRUE) 
                goto _END_OF_FUNC;

            if (num > 2 && num % 2 == 0) 
            {
                bIsPrime = FALSE;
            }
            else 
            {
                for (int div = 2; div * div <= num; div++) 
                {
                    if (num % div == 0) 
                    {
                        bIsPrime = FALSE;
                        break;
                    }
                }
            }

            if (bIsPrime)
                InterlockedIncrement(&g_PrimeCounter);
        }

        iLocalIterations++;
        InterlockedIncrement(&g_IterationCounter);
    }

_END_OF_FUNC:
    LocalFree(pPrimeRange);
}


// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


BOOL StartCountingPrimes(IN DWORD dwSeconds) 
{
    PTP_WORK        pWorkItems[NUM_WORK_ITEMS]  = { 0 };
    INT             iRangeStart                 = 0x00,
                    iRangeEnd                   = 0x00,
                    iTotalNumbers               = MAX_PRIME_LIMIT - 1,
                    iSegment                    = iTotalNumbers / NUM_WORK_ITEMS;
    FILETIME        ftDueTime                   = { 0 };
    ULARGE_INTEGER  ulDueTime                   = { 0 };
    BOOL            bResult                     = FALSE;

    g_TimingInfo.ullStartTime   = GetTickCount64();
    g_TimingInfo.ullMaxDuration = dwSeconds * 1000;
    g_TimingInfo.bTimeExpired   = FALSE;

    if ((g_hPool = CreateThreadpool(NULL)) == NULL) {
        DBG_PRINT_A("[!] CreateThreadpool Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!SetThreadpoolThreadMinimum(g_hPool, MIN_THREADPOOL_THREADS)) {
        DBG_PRINT_A("[!] SetThreadpoolThreadMinimum Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    SetThreadpoolThreadMaximum(g_hPool, MAX_THREADPOOL_THREADS);
    
    InitializeThreadpoolEnvironment(&g_CallbackEnv);

    if ((g_CleanupGroup = CreateThreadpoolCleanupGroup()) == NULL) {
        DBG_PRINT_A("[!] CreateThreadpoolCleanupGroup Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    SetThreadpoolCallbackCleanupGroup(&g_CallbackEnv, g_CleanupGroup, NULL);
    SetThreadpoolCallbackPool(&g_CallbackEnv, g_hPool);

    if ((g_hTimer = CreateThreadpoolTimer(TimeCheckCallback, &g_TimingInfo, &g_CallbackEnv)) == NULL) {
        DBG_PRINT_A("[!] CreateThreadpoolTimer Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    ulDueTime.QuadPart          = (ULONGLONG)(-1 * 10000);
    ftDueTime.dwLowDateTime     = ulDueTime.LowPart;
    ftDueTime.dwHighDateTime    = ulDueTime.HighPart;

    SetThreadpoolTimer(g_hTimer, &ftDueTime, 100, 0);

    for (int i = 0; i < NUM_WORK_ITEMS; i++) 
    {
        
        PPRIME_RANGE pPrimeRange = NULL;
        
        iRangeStart = 2 + i * iSegment;
        if (i == NUM_WORK_ITEMS - 1)
            iRangeEnd = MAX_PRIME_LIMIT;
        else
            iRangeEnd = iRangeStart + iSegment - 1;

        if ((pPrimeRange = (PPRIME_RANGE)LocalAlloc(LPTR, sizeof(PRIME_RANGE))) == NULL) {
            DBG_PRINT_A("[!] LocalAlloc Failed With Error: %lu", GetLastError());
            goto _END_OF_FUNC;
        }

        pPrimeRange->iStart  = iRangeStart;
        pPrimeRange->iEnd    = iRangeEnd;

        if ((pWorkItems[i] = CreateThreadpoolWork(PrimeCalculatorCallback, pPrimeRange, &g_CallbackEnv)) == NULL) 
        {
            DBG_PRINT_A("[!] CreateThreadpoolWork Failed With Error: %lu", GetLastError());
            LocalFree(pPrimeRange);
            goto _END_OF_FUNC;
        }

        SubmitThreadpoolWork(pWorkItems[i]);
    }

    for (int i = 0; i < NUM_WORK_ITEMS; i++) {
        
        if (pWorkItems[i]) 
        {
            WaitForThreadpoolWorkCallbacks(pWorkItems[i], FALSE);
            CloseThreadpoolWork(pWorkItems[i]);
        }
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (g_hTimer) 
    {
        SetThreadpoolTimer(g_hTimer, NULL, 0, 0);
        WaitForThreadpoolTimerCallbacks(g_hTimer, FALSE);
        CloseThreadpoolTimer(g_hTimer);
    }

    if (g_CleanupGroup) 
    {
        CloseThreadpoolCleanupGroupMembers(g_CleanupGroup, FALSE, NULL);
        CloseThreadpoolCleanupGroup(g_CleanupGroup);
    }

    DestroyThreadpoolEnvironment(&g_CallbackEnv);

    if (g_hPool) 
    {
        CloseThreadpool(g_hPool);
    }

    return bResult;
}
