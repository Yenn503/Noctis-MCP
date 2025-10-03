// Reed-Solomon Error Correction - Decoder Implementation (No Encoder)
// Refactored From: https://github.com/SRI-CSL/jel/tree/master/rscode
// This File Includes:
// - Galois Field Arithmetic GF(256)
// - Syndrome Calculation
// - Berlekamp-Massey Algorithm (With & Without erasures)
// - Chien Search for Error Location
// - Forney Algorithm for Error Correction
// - Polynomial Operations over GF(256)

#include <Windows.h>
#include <stdio.h>

#include "Reed-Solomon.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BYTE g_bGfExp[RS_FIELD_SIZE * 2]     = { 0 };
static BYTE g_bGfLog[RS_FIELD_SIZE]         = { 0 };
static BOOL g_bTablesInitialized            = FALSE;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static inline BYTE GfAdd(IN BYTE bA, IN BYTE bB)
{
    return bA ^ bB;
}

static inline BYTE GfSub(IN BYTE bA, IN BYTE bB)
{
    return bA ^ bB;
}

static BYTE GfMultiply(IN BYTE bA, IN BYTE bB)
{
    if (bA == 0 || bB == 0) return 0;
    return g_bGfExp[g_bGfLog[bA] + g_bGfLog[bB]];
}

static BYTE GfDivide(IN BYTE bA, IN BYTE bB)
{
    if (bA == 0) return 0;
    if (bB == 0) return 0;

    return g_bGfExp[(g_bGfLog[bA] + RS_FIELD_CHARAC - g_bGfLog[bB]) % RS_FIELD_CHARAC];
}

static BYTE GfPow(IN BYTE bA, IN INT iPower)
{
    if (bA == 0) return 0;

    if (iPower < 0)
        iPower = iPower % RS_FIELD_CHARAC + RS_FIELD_CHARAC;

    return g_bGfExp[(g_bGfLog[bA] * iPower) % RS_FIELD_CHARAC];
}

static BYTE WINAPI GfInverse(IN BYTE bX)
{
    if (bX == 0) return 0;

    return g_bGfExp[RS_FIELD_CHARAC - g_bGfLog[bX]];
}

static DWORD WINAPI GfMultNoLUT(IN DWORD dwX, IN DWORD dwY, IN DWORD dwPrim, IN DWORD dwFieldCharacFull)
{
    DWORD dwR = 0x00;

    while (dwY)
    {
        if (dwY & 1) dwR ^= dwX;
        dwY >>= 1;
        dwX <<= 1;
        if (dwPrim > 0 && (dwX & dwFieldCharacFull)) dwX ^= dwPrim;
    }

    return dwR;
}

static BYTE WINAPI GfPolyEval(IN PBYTE pbPoly, IN DWORD dwLen, IN BYTE bX)
{
    BYTE    bY  = pbPoly[0];
    DWORD   dwI = 0x00;

    for (dwI = 1; dwI < dwLen; dwI++)
    {
        bY = GfMultiply(bY, bX) ^ pbPoly[dwI];
    }

    return bY;
}

static PBYTE WINAPI GfPolyMul(IN PBYTE pbP, IN DWORD dwPLen, IN PBYTE pbQ, IN DWORD dwQLen, OUT PDWORD pdwOutLen) 
{
    PBYTE pbR    = NULL;
    DWORD dwRLen = dwPLen + dwQLen - 1,
          dwI    = 0x00,
          dwJ    = 0x00;
    
    if (!(pbR = (PBYTE)LocalAlloc(LPTR, dwRLen))) {
        printf("[!] LocalAlloc Failed With Error: %ld\n", GetLastError());
        return NULL;
    }
    
    for (dwI = 0; dwI < dwPLen; dwI++) {
        for (dwJ = 0; dwJ < dwQLen; dwJ++) {
            pbR[dwI + dwJ] ^= GfMultiply(pbP[dwI], pbQ[dwJ]);
        }
    }
    
    *pdwOutLen = dwRLen;
    return pbR;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL WINAPI RsInitializeTables(IN DWORD dwPrim, IN DWORD dwGenerator) 
{
    DWORD dwX = 0x01,
          dwI = 0x00;
    
    for (dwI = 0; dwI < RS_FIELD_CHARAC; dwI++) 
    {
        g_bGfExp[dwI] = (BYTE)dwX;
        g_bGfLog[dwX] = (BYTE)dwI;
        dwX = GfMultNoLUT(dwX, dwGenerator, dwPrim, RS_FIELD_SIZE);
    }
    
    for (dwI = RS_FIELD_CHARAC; dwI < RS_FIELD_CHARAC * 2; dwI++) {
        g_bGfExp[dwI] = g_bGfExp[dwI - RS_FIELD_CHARAC];
    }
    
    g_bTablesInitialized = TRUE;
    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static PBYTE WINAPI RsCalcSyndromes(IN PBYTE pbMsg, IN DWORD dwMsgLen, IN DWORD dwNsym, IN DWORD dwFcr, IN DWORD dwGenerator) 
{
    PBYTE   pbSynd  = NULL;
    DWORD   dwI     = 0x00;

    if (!(pbSynd = (PBYTE)LocalAlloc(LPTR, dwNsym + 1))) {
        printf("[!] LocalAlloc Failed With Error: %ld\n", GetLastError());
		return NULL;
    }

    pbSynd[0] = 0x00;

    for (dwI = 0; dwI < dwNsym; dwI++) {
        pbSynd[dwI + 1] = GfPolyEval(pbMsg, dwMsgLen, GfPow((BYTE)dwGenerator, dwI + dwFcr));
    }

    return pbSynd;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static PBYTE WINAPI RsFindErrataLocator(IN PDWORD pdwErrPos, IN DWORD dwErrCount, IN DWORD dwMsgLen, IN DWORD dwGenerator, OUT PDWORD pdwLocLen) 
{
    PBYTE pbLoc     = NULL,
          pbTemp    = NULL;
    DWORD dwI       = 0x00,
          dwLocLen  = 0x01,
          dwTempLen = 0x00;
    
    if (!(pbLoc = (PBYTE)LocalAlloc(LPTR, 1))) {
        printf("[!] LocalAlloc Failed With Error: %ld\n", GetLastError());
		return NULL;
    }
    
    pbLoc[0] = 0x01;
    
    for (dwI = 0; dwI < dwErrCount; dwI++) 
    {
        DWORD   dwPos       = dwMsgLen - 1 - pdwErrPos[dwI];
		BYTE    bRoot[2]    = { 0 };
        
        bRoot[0] = 0x01;
        bRoot[1] = GfPow((BYTE)dwGenerator, dwPos);
        
        if (!(pbTemp = GfPolyMul(pbLoc, dwLocLen, bRoot, 2, &dwTempLen))) {
            printf("[!] GfPolyMul Failed\n");
            LocalFree(pbLoc);
			return NULL;
        }
        
        LocalFree(pbLoc);

        pbLoc       = pbTemp;
        dwLocLen    = dwTempLen;
        pbTemp      = NULL;
    }
    
    *pdwLocLen = dwLocLen;
    
    return pbLoc;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL WINAPI RsFindErrors(IN PBYTE pbErrLoc, IN DWORD dwErrLocLen, IN DWORD dwMsgLen, IN DWORD dwGenerator, OUT PDWORD pdwErrPos, IN OUT PDWORD pdwErrCount)
{
    DWORD dwI     = 0x00,
          dwCount = 0x00;
    
    for (dwI = 0; dwI < dwMsgLen; dwI++) 
    {
        BYTE bX   = GfPow((BYTE)dwGenerator, dwI);
        BYTE bVal = GfPolyEval(pbErrLoc, dwErrLocLen, bX);
        
        if (bVal == 0) 
        {
            DWORD dwPos = dwMsgLen - 1 - dwI;
            if (dwCount < *pdwErrCount) 
                pdwErrPos[dwCount] = dwPos;
            dwCount++;
        }
    }
    
    if (dwCount != dwErrLocLen - 1) {
        printf("[!] Wrong Number Of Roots Found\n");
        return FALSE;
    }
    
    *pdwErrCount = dwCount;
    return TRUE;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


static PBYTE WINAPI RsFindErrorEvaluator(IN PBYTE pbSynd, IN PBYTE pbErrLoc, IN DWORD dwErrLocLen, IN DWORD dwNsym, OUT PDWORD pdwEvalLen)
{
    PBYTE pbResult  = NULL,
          pbTemp    = NULL;
    DWORD dwTempLen = 0x00,
          dwI       = 0x00;
    
    if (!(pbTemp = GfPolyMul(pbSynd + 1, dwNsym, pbErrLoc, dwErrLocLen, &dwTempLen))) {
        printf("[!] GfPolyMul Failed\n");
        goto _END_OF_FUNC;
    }
    
    *pdwEvalLen = min(dwTempLen, dwNsym);
    
    if (!(pbResult = (PBYTE)LocalAlloc(LPTR, *pdwEvalLen))) {
        printf("[!] LocalAlloc Failed With Error: %ld\n", GetLastError());
        goto _END_OF_FUNC;
    }
    
    for (dwI = 0; dwI < *pdwEvalLen; dwI++) {
        pbResult[dwI] = pbTemp[dwI];
    }
    
_END_OF_FUNC:
    if (pbTemp) 
        LocalFree(pbTemp);
    return pbResult;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL RsBerlekampMassey(
    IN CONST    BYTE*   pbSyndromes,
    IN          DWORD   dwSyndromeCount,
    OUT         PBYTE   pbErrorLocator, 
    OUT         PDWORD  pdwErrorLocatorLength,
    OUT         PDWORD  pdwErrorCount
) {

    BYTE  bLambda[RS_FIELD_SIZE]     = { 0 },
          bOldLambda[RS_FIELD_SIZE]  = { 0 },
          bTemp[RS_FIELD_SIZE]       = { 0 };
    DWORD dwLambdaLen                = 0x01,
          dwOldLambdaLen             = 0x01,
          dwL                        = 0x00,
          dwM                        = 0x01,
          dwI                        = 0x00,
          dwJ                        = 0x00,
          dwK                        = 0x00;
    BYTE  bDelta                     = 0x00,
          bGamma                     = 0x01;
    
    bLambda[0]      = 0x01;
    bOldLambda[0]   = 0x01;
    
    for (dwK = 0; dwK < dwSyndromeCount; dwK++) 
    {
        bDelta = pbSyndromes[dwK];
        for (dwJ = 1; dwJ < dwLambdaLen; dwJ++) {
            if (dwJ <= dwK) {
                bDelta ^= GfMultiply(bLambda[dwJ], pbSyndromes[dwK - dwJ]);
            }
        }
        
        dwM++;
        
        if (bDelta != 0) 
        {
            if (2 * dwL <= dwK) 
            {
                DWORD dwTempLen = dwLambdaLen;
                RtlCopyMemory(bTemp, bLambda, dwLambdaLen);
                
                BYTE bScale = GfDivide(bDelta, bGamma);
                
                DWORD dwNewLen = max(dwLambdaLen, dwOldLambdaLen + dwM - 1);
                if (dwNewLen > RS_FIELD_SIZE) {
                    printf("[!] Buffer Overflow\n");
					return FALSE;
                }
                
                for (dwI = 0; dwI < dwOldLambdaLen; dwI++) {
                    DWORD dwPos = dwI + dwM - 1;
                    if (dwPos < RS_FIELD_SIZE) {
                        bLambda[dwPos] ^= GfMultiply(bScale, bOldLambda[dwI]);
                    }
                }
                dwLambdaLen = dwNewLen;
                
                RtlCopyMemory(bOldLambda, bTemp, dwTempLen);
                dwOldLambdaLen = dwTempLen;
                dwL = dwK + 1 - dwL;
                bGamma = bDelta;
                dwM = 0x01;
            }
            else 
            {
                BYTE bScale = GfDivide(bDelta, bGamma);
                DWORD dwNewLen = max(dwLambdaLen, dwOldLambdaLen + dwM - 1);
                
                if (dwNewLen > RS_FIELD_SIZE) {
                    printf("[!] Buffer Overflow\n");
                    return FALSE;
                }
                
                for (dwI = 0; dwI < dwOldLambdaLen; dwI++) {
                    DWORD dwPos = dwI + dwM - 1;
                    if (dwPos < RS_FIELD_SIZE) {
                        bLambda[dwPos] ^= GfMultiply(bScale, bOldLambda[dwI]);
                    }
                }
                dwLambdaLen = dwNewLen;
            }
        }
    }
    
    if (dwL * 2 > dwSyndromeCount) {
        printf("[!] Too Many Errors Found\n");
        return FALSE;
    }
    
    RtlCopyMemory(pbErrorLocator, bLambda, dwLambdaLen);
    *pdwErrorLocatorLength = dwLambdaLen;
    *pdwErrorCount = dwL;

	return TRUE;
}




// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


BOOL RsBerlekampMasseyWithErasures(
    IN CONST    BYTE*   pbSyndromes, 
    IN          DWORD   dwSyndromeCount, 
    IN CONST    BYTE*   pbErasureLocator, 
    IN          DWORD   dwErasureLocatorLength,
    IN          DWORD   dwErasureCount,
    OUT         BYTE*   pbErrorLocator,
    OUT         DWORD*  pdwErrorLocatorLength,
    OUT         DWORD*  pdwTotalErrorCount
) {
    
    BYTE* pbModifiedSyndromes       = NULL,
          *pbWorkingLocator         = NULL;
    DWORD dwAdditionalErrors        = 0x00,
          dwAdditionalLocatorLength = 0x00,
          dwI                       = 0x00,
          dwJ                       = 0x00;
    BOOL  bResult                   = FALSE;

    if (!pbSyndromes || !pbErrorLocator || !pdwErrorLocatorLength || !pdwTotalErrorCount) 
    {
        printf("[!] Invalid Parameters\n");
        return FALSE;
    }

    if (!(pbModifiedSyndromes = (PBYTE)LocalAlloc(LPTR, dwSyndromeCount))) {
        printf("[!] LocalAlloc Failed With Error: %ld\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(pbWorkingLocator = (PBYTE)LocalAlloc(LPTR, RS_FIELD_SIZE))) {
        printf("[!] LocalAlloc Failed With Error: %ld\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (dwErasureCount > 0 && pbErasureLocator) 
    {
        for (dwI = 0; dwI < dwSyndromeCount; dwI++) {
            pbModifiedSyndromes[dwI] = pbSyndromes[dwI];
            for (dwJ = 1; dwJ < dwErasureLocatorLength && dwJ <= dwI; dwJ++) {
                pbModifiedSyndromes[dwI] ^= GfMultiply(pbErasureLocator[dwJ], pbSyndromes[dwI - dwJ]);
            }
        }

        DWORD dwRemainingCapacity = dwSyndromeCount - dwErasureCount;

        if (dwRemainingCapacity > 0) 
        {
            DWORD dwEffectiveSyndromes = dwRemainingCapacity;

            if (!RsBerlekampMassey(pbModifiedSyndromes, dwEffectiveSyndromes, pbWorkingLocator, &dwAdditionalLocatorLength, &dwAdditionalErrors)) {
                printf("[!] RsBerlekampMassey Failed\n");
                goto _END_OF_FUNC;
            }

            DWORD dwMaxAdditionalErrors = dwRemainingCapacity / 2;

            if (dwAdditionalErrors > dwMaxAdditionalErrors) {
                printf("[!] Too Many Additional Errors\n");
                goto _END_OF_FUNC;
            }
        }
        else 
        {
            pbWorkingLocator[0]         = 0x01;
            dwAdditionalLocatorLength   = 0x01;
            dwAdditionalErrors          = 0x00;
        }

        RtlZeroMemory(pbErrorLocator, RS_FIELD_SIZE);
        for (dwI = 0; dwI < dwErasureLocatorLength; dwI++) {
            for (dwJ = 0; dwJ < dwAdditionalLocatorLength; dwJ++) {
                if (dwI + dwJ < RS_FIELD_SIZE) {
                    pbErrorLocator[dwI + dwJ] ^= GfMultiply(pbErasureLocator[dwI], pbWorkingLocator[dwJ]);
                }
            }
        }

        *pdwErrorLocatorLength = dwErasureLocatorLength + dwAdditionalLocatorLength - 1;
        *pdwTotalErrorCount = dwErasureCount + dwAdditionalErrors;

        if (*pdwTotalErrorCount * 2 - dwErasureCount > dwSyndromeCount) {
            printf("[!] Total Error Capacity Exceeded\n");
            goto _END_OF_FUNC;
        }
    }
    else 
    {
        if (!RsBerlekampMassey(pbSyndromes, dwSyndromeCount, pbErrorLocator, pdwErrorLocatorLength, pdwTotalErrorCount)) {
            printf("[!] RsBerlekampMassey Failed\n");
            goto _END_OF_FUNC;
        }
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pbModifiedSyndromes)
        LocalFree(pbModifiedSyndromes);
    if (pbWorkingLocator)
        LocalFree(pbWorkingLocator);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


static BOOL WINAPI RsCorrectErrata(
    IN OUT  PBYTE   pbMsg,
    IN      DWORD   dwMsgLen,
    IN      PBYTE   pbSynd,
    IN      PDWORD  pdwErrPos, 
    IN      DWORD   dwErrCount,
    IN      DWORD   dwNsym,
    IN      DWORD   dwFcr,
    IN      DWORD   dwGenerator
) {
    
    PBYTE pbErrLoc     = NULL,
          pbErrEval    = NULL,
          pbX          = NULL;
    DWORD dwErrLocLen  = 0x00,
          dwErrEvalLen = 0x00,
          dwI          = 0x00,
          dwJ          = 0x00;
    BOOL  bReturn         = FALSE;
    
    if (dwErrCount == 0)
		return TRUE;
    
    if (!(pbErrLoc = RsFindErrataLocator(pdwErrPos, dwErrCount, dwMsgLen, dwGenerator, &dwErrLocLen))) {
        printf("[!] RsFindErrataLocator Failed\n");
        goto _END_OF_FUNC;
    }
    
    if (!(pbErrEval = RsFindErrorEvaluator(pbSynd, pbErrLoc, dwErrLocLen, dwNsym, &dwErrEvalLen))) {
        printf("[!] RsFindErrorEvaluator Failed\n");
        goto _END_OF_FUNC;
    }
    
    if (!(pbX = (PBYTE)LocalAlloc(LPTR, dwErrCount))) {
        printf("[!] LocalAlloc Failed With Error: %ld\n", GetLastError());
        goto _END_OF_FUNC;
    }
    
    for (dwI = 0; dwI < dwErrCount; dwI++) 
    {
        DWORD dwPos = dwMsgLen - 1 - pdwErrPos[dwI];
        pbX[dwI] = GfPow((BYTE)dwGenerator, dwPos);
    }
    
    for (dwI = 0; dwI < dwErrCount; dwI++) 
    {
        BYTE    bXiInv          = GfInverse(pbX[dwI]);
        BYTE    bErrLocPrime    = 0x01;
        BYTE    bY              = 0x00,
                bMagnitude      = 0x00;
        PBYTE   pbEvalRev       = NULL;
        
        for (dwJ = 0; dwJ < dwErrCount; dwJ++) {
            if (dwJ != dwI) {
                bErrLocPrime = GfMultiply(bErrLocPrime, GfSub(1, GfMultiply(bXiInv, pbX[dwJ])));
            }
        }
        
        if (bErrLocPrime == 0) 
        {
            printf("[!] Locator Prime Is Zero\n");
            goto _END_OF_FUNC;
        }
        
        if (!(pbEvalRev = (PBYTE)LocalAlloc(LPTR, dwErrEvalLen))) {
            printf("[!] LocalAlloc Failed With Error: %ld\n", GetLastError());
            goto _END_OF_FUNC;
        }
        
        for (dwJ = 0; dwJ < dwErrEvalLen; dwJ++) {
            pbEvalRev[dwJ] = pbErrEval[dwErrEvalLen - 1 - dwJ];
        }
        
        bY = GfPolyEval(pbEvalRev, dwErrEvalLen, bXiInv);
        
        LocalFree(pbEvalRev);
        
        bMagnitude = GfDivide(bY, bErrLocPrime);
        
        pbMsg[pdwErrPos[dwI]] ^= bMagnitude;
    }
    
    bReturn = TRUE;

_END_OF_FUNC:
    if (pbErrLoc) 
        LocalFree(pbErrLoc);
    if (pbErrEval) 
        LocalFree(pbErrEval);
    if (pbX) 
        LocalFree(pbX);
    return bReturn;
}



// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


BOOL WINAPI RsDecodeMessage(
    IN      PRS_CONTEXT pContext, 
    IN      PBYTE       pbMsgIn,
    IN      DWORD       dwMsgLen, 
    OUT     PBYTE       pbMsgOut, 
    OUT     PBYTE       pbEcc,
    IN OUT  PDWORD      pdwErasePos, 
    IN      DWORD       dwEraseCount, 
    OUT     PDWORD      pdwErrorPos,
    OUT     PDWORD      pdwErrorCount
) {

    PBYTE  pbSynd          = NULL,
           pbErrLoc        = NULL,
           pbErasureLoc    = NULL,
           pbWorkMsg       = NULL;
    DWORD  dwErrLocLen     = 0x00,
           dwErasureLocLen = 0x00,
           dwI             = 0x00,
           dwFoundErrors   = 0x00,
           dwTotalErrors   = 0x00;
    PDWORD pdwAllErrors    = NULL;
    BYTE   bMaxSynd        = 0x00;
    BOOL   bReturn         = FALSE;


    if (!pContext || !pbMsgIn || !pbMsgOut || !pbEcc || dwMsgLen > RS_FIELD_SIZE || dwEraseCount > pContext->dwNsym) {
        printf("[!] Invalid Parameters\n");
        return FALSE;
    }

    if (!(pbWorkMsg = (PBYTE)LocalAlloc(LPTR, dwMsgLen))) {
        printf("[!] LocalAlloc Failed With Error: %ld\n", GetLastError());
        return FALSE;
    }
    
    RtlCopyMemory(pbWorkMsg, pbMsgIn, dwMsgLen);

    pbSynd = RsCalcSyndromes(pbWorkMsg, dwMsgLen, pContext->dwNsym, pContext->dwFcr, pContext->dwGenerator);
    if (!pbSynd) {
        printf("[!] RsCalcSyndromes Failed\n");
        goto _END_OF_FUNC;
    }

    for (dwI = 0; dwI <= pContext->dwNsym; dwI++) {
        if (pbSynd[dwI] > bMaxSynd) bMaxSynd = pbSynd[dwI];
    }

    if (bMaxSynd == 0) 
    {
        RtlCopyMemory(pbMsgOut, pbWorkMsg, dwMsgLen - pContext->dwNsym);
        RtlCopyMemory(pbEcc, pbWorkMsg + (dwMsgLen - pContext->dwNsym), pContext->dwNsym);
        *pdwErrorCount = 0x00;
        bReturn = TRUE;
        goto _END_OF_FUNC;
    }


    if (dwEraseCount > 0) 
    {
        if (!(pbErasureLoc = RsFindErrataLocator(pdwErasePos, dwEraseCount, dwMsgLen, pContext->dwGenerator, &dwErasureLocLen))) {
            printf("[!] RsFindErrataLocator Failed\n");
            goto _END_OF_FUNC;
        }

        if (!(pbErrLoc = (PBYTE)LocalAlloc(LPTR, RS_FIELD_SIZE))) {
            printf("[!] LocalAlloc Failed With Error: %ld\n", GetLastError());
            goto _END_OF_FUNC;
        }

        if (!RsBerlekampMasseyWithErasures(pbSynd + 1, pContext->dwNsym, pbErasureLoc, dwErasureLocLen, dwEraseCount, pbErrLoc, &dwErrLocLen, &dwTotalErrors)) {
            printf("[!] RsBerlekampMasseyWithErasures Failed\n");
            goto _END_OF_FUNC;
        }

        if (!(pdwAllErrors = (PDWORD)LocalAlloc(LPTR, dwTotalErrors * sizeof(DWORD)))) {
            printf("[!] LocalAlloc Failed With Error: %ld\n", GetLastError());
            goto _END_OF_FUNC;
        }

        dwFoundErrors = dwTotalErrors;

        if (!RsFindErrors(pbErrLoc, dwErrLocLen, dwMsgLen, pContext->dwGenerator, pdwAllErrors, &dwFoundErrors)) 
        {
            printf("[!] RsFindErrors Failed\n");
            LocalFree(pdwAllErrors);
            pdwAllErrors = NULL;
            goto _END_OF_FUNC;
        }

        if (dwFoundErrors != dwTotalErrors) 
        {
            printf("[!] Found Errors Count Mismatch (Found: %ld, Expected: %ld)\n", dwFoundErrors, dwTotalErrors);
            LocalFree(pdwAllErrors);
            pdwAllErrors = NULL;
            goto _END_OF_FUNC;
        }

        *pdwErrorCount = dwFoundErrors;

        for (dwI = 0; dwI < dwFoundErrors && dwI < dwMsgLen; dwI++) {
            pdwErrorPos[dwI] = pdwAllErrors[dwI];
        }

        dwTotalErrors = dwFoundErrors;
    }
    else 
    {
        if (!(pbErrLoc = (PBYTE)LocalAlloc(LPTR, RS_FIELD_SIZE))) {
            printf("[!] LocalAlloc Failed With Error: %ld\n", GetLastError());
            goto _END_OF_FUNC;
        }

        if (!RsBerlekampMassey(pbSynd + 1, pContext->dwNsym, pbErrLoc, &dwErrLocLen, &dwTotalErrors)) {
            printf("[!] RsBerlekampMassey Failed\n");
            goto _END_OF_FUNC;
        }

        if (!(pdwAllErrors = (PDWORD)LocalAlloc(LPTR, dwTotalErrors * sizeof(DWORD)))) {
            printf("[!] LocalAlloc Failed With Error: %ld\n",GetLastError());
            goto _END_OF_FUNC;
        }

        dwFoundErrors = dwTotalErrors;
        
        if (!RsFindErrors(pbErrLoc, dwErrLocLen, dwMsgLen, pContext->dwGenerator, pdwAllErrors, &dwFoundErrors)) 
        {
            printf("[!] RsFindErrors Failed\n");
            LocalFree(pdwAllErrors);
            pdwAllErrors = NULL;
            goto _END_OF_FUNC;
        }

        if (dwFoundErrors != dwTotalErrors) 
        {
            printf("[!] Found Errors Count Mismatch (Found: %ld, Expected: %ld)\n", dwFoundErrors, dwTotalErrors);
            LocalFree(pdwAllErrors);
            pdwAllErrors = NULL;
            goto _END_OF_FUNC;
        }


        *pdwErrorCount = dwFoundErrors;

        for (dwI = 0; dwI < dwFoundErrors && dwI < dwMsgLen; dwI++) {
            pdwErrorPos[dwI] = pdwAllErrors[dwI];
        }

        dwTotalErrors = dwFoundErrors;
    }

    if (dwTotalErrors * 2 - dwEraseCount > pContext->dwNsym) 
    {
        printf("[!] Too Many Errors To Correct\n");
        goto _END_OF_FUNC;
    }

    if (!RsCorrectErrata(pbWorkMsg, dwMsgLen, pbSynd, pdwAllErrors, dwTotalErrors, pContext->dwNsym, pContext->dwFcr, pContext->dwGenerator)) {
        printf("[!] RsCorrectErrata Failed\n");
        goto _END_OF_FUNC;
    }

    LocalFree(pbSynd);

    if (!(pbSynd = RsCalcSyndromes(pbWorkMsg, dwMsgLen, pContext->dwNsym, pContext->dwFcr, pContext->dwGenerator))) {
        printf("[!] RsCalcSyndromes Failed\n");
        goto _END_OF_FUNC;
    }

    bMaxSynd = 0;

    for (dwI = 0; dwI <= pContext->dwNsym; dwI++) {
        if (pbSynd[dwI] > bMaxSynd) bMaxSynd = pbSynd[dwI];
    }

    if (bMaxSynd > 0) 
    {
        printf("[!] Verification Failed - Syndromes Still Non-Zero\n");
        goto _END_OF_FUNC;
    }

    RtlCopyMemory(pbMsgOut, pbWorkMsg, dwMsgLen - pContext->dwNsym);
    RtlCopyMemory(pbEcc, pbWorkMsg + (dwMsgLen - pContext->dwNsym), pContext->dwNsym);

    bReturn = TRUE;

_END_OF_FUNC:
    if (pbSynd)
        LocalFree(pbSynd);
    if (pbErrLoc) 
        LocalFree(pbErrLoc);
    if (pbErasureLoc)
        LocalFree(pbErasureLoc);
    if (pbWorkMsg)
        LocalFree(pbWorkMsg);
    if (pdwAllErrors)
        LocalFree(pdwAllErrors);
    return bReturn;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


BOOL WINAPI RsCreateContext(
    OUT PRS_CONTEXT pContext,
    IN  DWORD       dwNsym,
    IN  DWORD       dwFcr,
    IN  DWORD       dwGenerator,
    IN  DWORD       dwPrim
) {
    
    if (!pContext) return FALSE;

    if (!g_bTablesInitialized) {
        if (!RsInitializeTables(dwPrim, dwGenerator)) {
            return FALSE;
        }
    }

    pContext->dwNsym        = dwNsym;
    pContext->dwFcr         = dwFcr;
    pContext->dwGenerator   = dwGenerator;
    pContext->dwPrim        = dwPrim;

    return TRUE;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
