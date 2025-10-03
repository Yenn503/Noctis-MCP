#pragma once
#ifndef QUEUE_H
#define QUEUE_H
#include <Windows.h>


typedef struct _QUEUE_NODE 
{
    LPSTR               pszDllName;
    struct _QUEUE_NODE* pNext;

} QUEUE_NODE, * PQUEUE_NODE;

typedef struct _DLL_QUEUE 
{
    PQUEUE_NODE pHead;
    PQUEUE_NODE pTail;
    SIZE_T      cbCount;

} DLL_QUEUE, * PDLL_QUEUE;


// +-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-+
//
// Global DLL Queue

static DLL_QUEUE g_DllQueue = { NULL, NULL, 0x00 };

// +-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-+

VOID InitializeDllQueue(VOID) 
{
    g_DllQueue.pHead    = NULL;
    g_DllQueue.pTail    = NULL;
    g_DllQueue.cbCount  = 0x00;
}

BOOL IsQueueEmpty(VOID)
{
    return (g_DllQueue.pHead == NULL);
}

SIZE_T GetQueueSize(VOID)
{
    return g_DllQueue.cbCount;
}

// +-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-+


BOOL EnqueueDllName(IN LPSTR pszDllName) 
{
    PQUEUE_NODE pNewNode    = NULL;
    SIZE_T      cbNameLen   = 0x00;
    LPSTR       pszCopy     = NULL;
    
    if (pszDllName == NULL) 
        return FALSE;
    
    while (pszDllName[cbNameLen] != '\0') cbNameLen++;
    
    if ((pNewNode = (PQUEUE_NODE)LocalAlloc(LPTR, sizeof(QUEUE_NODE))) == NULL) 
        return FALSE;
    
    if ((pszCopy = (LPSTR)LocalAlloc(LPTR, cbNameLen + 1)) == NULL) 
    {
        LocalFree(pNewNode);
        return FALSE;
    }
    
    for (SIZE_T i = 0x00; i < cbNameLen; i++) 
    {
        pszCopy[i] = pszDllName[i];
    }
    pszCopy[cbNameLen] = '\0';
    
    pNewNode->pszDllName    = pszCopy;
    pNewNode->pNext         = NULL;
    
    if (g_DllQueue.pHead == NULL) 
    {
        g_DllQueue.pHead = pNewNode;
        g_DllQueue.pTail = pNewNode;
    } 
    else 
    {
        g_DllQueue.pTail->pNext = pNewNode;
        g_DllQueue.pTail        = pNewNode;
    }
    
    g_DllQueue.cbCount++;
    return TRUE;
}


LPSTR DequeueDllName(VOID) 
{
    PQUEUE_NODE pNode       = NULL;
    LPSTR       pszDllName  = NULL;
    
    if (g_DllQueue.pHead == NULL) return NULL;
    
    pNode       = g_DllQueue.pHead;
    pszDllName  = pNode->pszDllName;
    
    g_DllQueue.pHead = pNode->pNext;
    
    if (g_DllQueue.pHead == NULL) 
        g_DllQueue.pTail = NULL;
    
    g_DllQueue.cbCount--;
    
    LocalFree(pNode);
    return pszDllName;
}


VOID DistroyDllQueue(VOID) 
{
    PQUEUE_NODE pCurrent    = NULL;
    PQUEUE_NODE pNext       = NULL;
    
    pCurrent = g_DllQueue.pHead;
    
    while (pCurrent != NULL) 
    {
        pNext = pCurrent->pNext;
        
        if (pCurrent->pszDllName != NULL) 
        {
            LocalFree(pCurrent->pszDllName);
			pCurrent->pszDllName = NULL;
        }
        
        LocalFree(pCurrent);
        
        pCurrent = pNext;
    }
    
    g_DllQueue.pHead    = NULL;
    g_DllQueue.pTail    = NULL;
    g_DllQueue.cbCount  = 0x00;
}


// +-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-+

static INT CompareStringsCI(IN LPSTR pszStr1, IN LPSTR pszStr2)
{
    SIZE_T  i   = 0x00;
	CHAR    c1  = 0x00, 
            c2  = 0x00;

    while (pszStr1[i] != '\0' && pszStr2[i] != '\0')
    {
        c1 = pszStr1[i];
        c2 = pszStr2[i];

        if (c1 >= 'A' && c1 <= 'Z') c1 = c1 + ('a' - 'A');
        if (c2 >= 'A' && c2 <= 'Z') c2 = c2 + ('a' - 'A');

        if (c1 < c2) return -1;
        if (c1 > c2) return 1;

        i++;
    }

    if (pszStr1[i] == '\0' && pszStr2[i] == '\0') return 0;
    if (pszStr1[i] == '\0') return -1;
    return 1;
}

static PQUEUE_NODE SortedMerge(IN PQUEUE_NODE pLeft, IN PQUEUE_NODE pRight)
{
    PQUEUE_NODE pResult = NULL;

    if (pLeft == NULL) return pRight;
    if (pRight == NULL) return pLeft;

    if (CompareStringsCI(pLeft->pszDllName, pRight->pszDllName) <= 0)
    {
        pResult = pLeft;
        pResult->pNext = SortedMerge(pLeft->pNext, pRight);
    }
    else
    {
        pResult = pRight;
        pResult->pNext = SortedMerge(pLeft, pRight->pNext);
    }

    return pResult;
}

static VOID SplitList(IN PQUEUE_NODE pSource, OUT PQUEUE_NODE* ppLeft, OUT PQUEUE_NODE* ppRight)
{
    PQUEUE_NODE pFast = NULL;
    PQUEUE_NODE pSlow = NULL;

    pSlow = pSource;
    pFast = pSource->pNext;

    while (pFast != NULL)
    {
        pFast = pFast->pNext;

        if (pFast != NULL)
        {
            pSlow = pSlow->pNext;
            pFast = pFast->pNext;
        }
    }

    *ppLeft         = pSource;
    *ppRight        = pSlow->pNext;
    pSlow->pNext    = NULL;
}

static PQUEUE_NODE MergeSortList(IN PQUEUE_NODE pHead)
{
    PQUEUE_NODE pLeft   = NULL;
    PQUEUE_NODE pRight  = NULL;

    if (pHead == NULL || pHead->pNext == NULL)
        return pHead;

    SplitList(pHead, &pLeft, &pRight);

    pLeft   = MergeSortList(pLeft);
    pRight  = MergeSortList(pRight);

    return SortedMerge(pLeft, pRight);
}

// +-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-++-+-+

VOID SortDllQueueAlphabetically(VOID)
{
    PQUEUE_NODE pCurrent = NULL;

    if (g_DllQueue.pHead == NULL || g_DllQueue.pHead->pNext == NULL)
        return;

    g_DllQueue.pHead    = MergeSortList(g_DllQueue.pHead);
    pCurrent            = g_DllQueue.pHead;

    while (pCurrent != NULL && pCurrent->pNext != NULL)
        pCurrent = pCurrent->pNext;

    g_DllQueue.pTail = pCurrent;
}



#endif // !QUEUE_H

