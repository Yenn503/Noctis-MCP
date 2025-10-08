#include <Windows.h>
#include <wincodec.h>
#include <compressapi.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "Reed-Solomon.h"
#include "Extract.h"
#include "DebugMacros.h"

#pragma comment(lib, "WindowsCodecs.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Cabinet.lib")

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Global Variables

const float g_fNormalizationConstant = 0.7071067811865475f;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static WORD Crc16CcittBigEndian(IN PBYTE pbData, IN DWORD dwDataLength, IN WORD wInitialValue) 
{
    
    WORD  wCrc           = wInitialValue,
          wPolynomial    = 0x1021;
    DWORD dwByteIndex    = 0x00,
          dwBitIndex     = 0x00;
    
    for (dwByteIndex = 0; dwByteIndex < dwDataLength; dwByteIndex++) {
        wCrc ^= (WORD)(pbData[dwByteIndex] << 8);
        for (dwBitIndex = 0; dwBitIndex < 8; dwBitIndex++) {
            wCrc = (wCrc & 0x8000) ? (WORD)(((wCrc << 1) ^ wPolynomial) & 0xFFFF) : (WORD)((wCrc << 1) & 0xFFFF);
        }
    }
    
    return wCrc;
}


static WORD Crc16CcittFalse(IN PBYTE pbData, IN DWORD dwDataLength) 
{
    return Crc16CcittBigEndian(pbData, dwDataLength, 0xFFFF);
}


static DWORD Crc32Compute(IN PBYTE pbData, IN DWORD dwDataLength) 
{
    
    static DWORD    adwLookupTable[RS_FIELD_SIZE]   = { 0 };
    static BOOL     bTableInitialized               = FALSE;
    DWORD           dwCrc                           = 0xFFFFFFFF,
                    dwTableIndex                    = 0x00,
                    dwBitIndex                      = 0x00,
                    dwByteIndex                     = 0x00,
                    dwTemp                          = 0x00;
    
    if (!bTableInitialized) 
    {
        for (dwTableIndex = 0; dwTableIndex < RS_FIELD_SIZE; dwTableIndex++)
        {
            dwTemp = dwTableIndex;
            for (dwBitIndex = 0; dwBitIndex < 8; dwBitIndex++)
                dwTemp = (dwTemp & 1) ? (0xEDB88320 ^ (dwTemp >> 1)) : (dwTemp >> 1);
            adwLookupTable[dwTableIndex] = dwTemp;
        }
        bTableInitialized = TRUE;
    }
    
    for (dwByteIndex = 0; dwByteIndex < dwDataLength; dwByteIndex++)
        dwCrc = adwLookupTable[(dwCrc ^ pbData[dwByteIndex]) & 0xFF] ^ (dwCrc >> 8);
    
    return dwCrc ^ 0xFFFFFFFF;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


static BOOL ConvertBitsToBytesMSB(IN PBYTE pbBits, IN DWORD dwBitCount, OUT PBYTE pbOutBytes, IN OUT PDWORD pdwInoutByteCount)
{
    DWORD dwRequiredBytes            = dwBitCount / 8,
          dwByteIndex                = 0x00,
          dwBitIndex                 = 0x00;
    BYTE  bCurrentValue              = 0x00;
    
    if (!pbBits || !pbOutBytes || !pdwInoutByteCount || *pdwInoutByteCount < dwRequiredBytes) {
        DBG_PRINT_A("[!] Invalid Parameters");
        return FALSE;
    }
    
    for (dwByteIndex = 0; dwByteIndex < dwRequiredBytes; dwByteIndex++) 
    {
        bCurrentValue = 0;

        for (dwBitIndex = 0; dwBitIndex < 8; dwBitIndex++) {
            bCurrentValue |= (pbBits[dwByteIndex * 8 + dwBitIndex] & 1) << (7 - dwBitIndex);
        }
        
        pbOutBytes[dwByteIndex] = bCurrentValue;
    }
    
    *pdwInoutByteCount = dwRequiredBytes;
    return TRUE;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL DecodePngToRgbaWic(IN PBYTE pbPngBuffer, IN DWORD dwPngSize, OUT PBYTE* ppbRgba, OUT PDWORD pdwWidth, OUT PDWORD pdwHeight, OUT PDWORD pdwChannels) 
{

    BOOL                    bComInitialized     = FALSE,
                            bOperationSuccess   = FALSE;
    HRESULT                 hrResult            = S_OK;
    UINT                    uImageWidth         = 0x00,
                            uImageHeight        = 0x00,
                            uStride             = 0x00,
                            uBufferSize         = 0x00;
    PBYTE                   pbOutputBuffer      = NULL;
    IWICImagingFactory*     pWicFactory         = NULL;
    IWICStream*             pWicStream          = NULL;
    IWICBitmapDecoder*      pBitmapDecoder      = NULL;
    IWICBitmapFrameDecode*  pFrameDecoder       = NULL;
    IWICFormatConverter*    pFormatConverter    = NULL;

    if (!pbPngBuffer || !dwPngSize || !ppbRgba || !pdwWidth || !pdwHeight || !pdwChannels) {
		DBG_PRINT_A("[!] Invalid Parameters");
        return FALSE;
    }
    
    *ppbRgba    = NULL;
    *pdwWidth   = *pdwHeight = *pdwChannels = 0x00;

    if (SUCCEEDED((hrResult = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))))
    {
        bComInitialized = TRUE;
    }
    else if (hrResult != RPC_E_CHANGED_MODE) 
    {
        DBG_PRINT_A("[!] CoInitializeEx Failed With Error: 0x%0.8X", hrResult);
        goto _END_OF_FUNC;
    }

    if (FAILED(hrResult = CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER, &IID_IWICImagingFactory, (void**)&pWicFactory))) {
        DBG_PRINT_A("[!] CoCreateInstance Failed With Error: 0x%0.8X", hrResult);
        goto _END_OF_FUNC;
    }
    
    if (FAILED(hrResult = pWicFactory->lpVtbl->CreateStream(pWicFactory, &pWicStream))) {
        DBG_PRINT_A("[!] CreateStream Failed With Error: 0x%0.8X", hrResult);
        goto _END_OF_FUNC;
    }
    
    if (FAILED(hrResult = pWicStream->lpVtbl->InitializeFromMemory(pWicStream, (WICInProcPointer)pbPngBuffer, dwPngSize))) {
        DBG_PRINT_A("[!] InitializeFromMemory Failed With Error: 0x%0.8X", hrResult);
        goto _END_OF_FUNC;
    }
    
    if (FAILED(hrResult = pWicFactory->lpVtbl->CreateDecoderFromStream(pWicFactory, (IStream*)pWicStream, NULL, WICDecodeMetadataCacheOnDemand, &pBitmapDecoder))) {
        DBG_PRINT_A("[!] CreateDecoderFromStream Failed With Error: 0x%0.8X", hrResult);
        goto _END_OF_FUNC;
    }
    
    if (FAILED(hrResult = pBitmapDecoder->lpVtbl->GetFrame(pBitmapDecoder, 0, &pFrameDecoder))) {
        DBG_PRINT_A("[!] GetFrame Failed With Error: 0x%0.8X", hrResult);
        goto _END_OF_FUNC;
    }
    
    if (FAILED(hrResult = pWicFactory->lpVtbl->CreateFormatConverter(pWicFactory, &pFormatConverter))) {
        DBG_PRINT_A("[!] CreateFormatConverter Failed With Error: 0x%0.8X", hrResult);
        goto _END_OF_FUNC;
    }
    
    if (FAILED(hrResult = pFormatConverter->lpVtbl->Initialize(pFormatConverter, (IWICBitmapSource*)pFrameDecoder, &GUID_WICPixelFormat32bppRGBA, WICBitmapDitherTypeNone, NULL, 0.0, WICBitmapPaletteTypeCustom))) {
        DBG_PRINT_A("[!] Initialize Converter Failed With Error: 0x%0.8X", hrResult);
        goto _END_OF_FUNC;
    }

    if (FAILED(hrResult = pFormatConverter->lpVtbl->GetSize(pFormatConverter, &uImageWidth, &uImageHeight)) || uImageWidth == 0 || uImageHeight == 0) {
        DBG_PRINT_A("[!] GetSize Failed With Error: 0x%0.8X", hrResult);
        goto _END_OF_FUNC;
    }

    uStride     = uImageWidth * 4;
    uBufferSize = uStride * uImageHeight;
    
    if (!(pbOutputBuffer = (PBYTE)LocalAlloc(LPTR, uBufferSize))) {
        DBG_PRINT_A("[!] LocalAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }
    
    if (FAILED(hrResult = pFormatConverter->lpVtbl->CopyPixels(pFormatConverter, NULL, uStride, uBufferSize, pbOutputBuffer))) {
        DBG_PRINT_A("[!] CopyPixels Failed With Error: 0x%0.8X", hrResult);
        SetLastError(HRESULT_CODE(hrResult));
        goto _END_OF_FUNC;
    }

    *ppbRgba            = pbOutputBuffer;
    *pdwWidth           = (DWORD)uImageWidth;
    *pdwHeight          = (DWORD)uImageHeight;
    *pdwChannels        = 0x04;
    bOperationSuccess   = TRUE;

#define SAFE_RELEASE(x) do { if ((x)) { (x)->lpVtbl->Release(x); (x) = NULL; } } while(0)

_END_OF_FUNC:
    if (pbOutputBuffer && !*ppbRgba) LocalFree(pbOutputBuffer);
    SAFE_RELEASE(pFormatConverter);
    SAFE_RELEASE(pFrameDecoder);
    SAFE_RELEASE(pBitmapDecoder);
    SAFE_RELEASE(pWicStream);
    SAFE_RELEASE(pWicFactory);
    if (bComInitialized) 
        CoUninitialize();
    SetLastError(HRESULT_CODE(hrResult));
    return bOperationSuccess;

#undef SAFE_RELEASE
}



// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL DwtDb1Periodization2D(IN float* pfInput, IN DWORD dwWidth, IN DWORD dwHeight, IN DWORD dwLevels, OUT DWT_COEFFS* pOutputCoeffs) 
{
    DWORD  dwCurrentWidth                = 0x00,
           dwCurrentHeight               = 0x00,
           dwLevel                       = 0x00,
           dwHalfWidth                   = 0x00,
           dwHalfHeight                  = 0x00,
           dwPairCount                   = 0x00,
           dwXIndex                      = 0x00,
           dwYIndex                      = 0x00,
           dwFinalWidth                  = 0x00,
           dwFinalHeight                 = 0x00,
           dwTotalCoefficients           = 0x00,
           dwCopyIndex                   = 0x00;
    float  fValueA                       = 0.0f,
           fValueB                       = 0.0f,
           fLastValue                    = 0.0f,
           fFirstValue                   = 0.0f;
    float* pfWorkBuffer                  = NULL;
    float* pfRowBuffer                   = NULL;
    float* pfColumnBuffer                = NULL;

    if (!pfInput || !pOutputCoeffs || dwLevels < 1 || (dwWidth >> dwLevels) == 0 || (dwHeight >> dwLevels) == 0) 
    {
		DBG_PRINT_A("[!] Invalid Parameters");
        return FALSE;
    }
    
    pfWorkBuffer    = (float*)LocalAlloc(LPTR, (SIZE_T)dwWidth * dwHeight * sizeof(float));
    pfRowBuffer     = (float*)LocalAlloc(LPTR, (SIZE_T)max(dwWidth, dwHeight) * sizeof(float));
    pfColumnBuffer  = (float*)LocalAlloc(LPTR, (SIZE_T)max(dwWidth, dwHeight) * sizeof(float));

    if (!pfWorkBuffer || !pfRowBuffer || !pfColumnBuffer) 
    {
        DBG_PRINT_A("[!] LocalAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    RtlCopyMemory(pfWorkBuffer, pfInput, (SIZE_T)dwWidth * dwHeight * sizeof(float));

    dwCurrentWidth  = dwWidth;
    dwCurrentHeight = dwHeight;
    
    for (dwLevel = 0; dwLevel < dwLevels; dwLevel++) 
    {
        dwHalfWidth = (dwCurrentWidth >> 1);
        dwHalfHeight = (dwCurrentHeight >> 1);

        for (dwYIndex = 0; dwYIndex < dwCurrentHeight; dwYIndex++) 
        {
            dwPairCount = (dwCurrentWidth >> 1);

            for (dwXIndex = 0; dwXIndex < dwPairCount; dwXIndex++) 
            {
                fValueA = pfWorkBuffer[dwYIndex * dwWidth + (dwXIndex << 1)];
                fValueB = pfWorkBuffer[dwYIndex * dwWidth + (dwXIndex << 1) + 1];
                pfRowBuffer[dwXIndex] = (fValueA + fValueB) * g_fNormalizationConstant;
                pfRowBuffer[dwHalfWidth + dwXIndex] = (fValueA - fValueB) * g_fNormalizationConstant;
            }
            
            if (dwCurrentWidth & 1) 
            {
                fLastValue = pfWorkBuffer[dwYIndex * dwWidth + (dwCurrentWidth - 1)];
                fFirstValue = pfWorkBuffer[dwYIndex * dwWidth + 0];
                if (dwPairCount < dwHalfWidth) {
                    pfRowBuffer[dwPairCount] = (fLastValue + fFirstValue) * g_fNormalizationConstant;
                    pfRowBuffer[dwHalfWidth + dwPairCount] = (fLastValue - fFirstValue) * g_fNormalizationConstant;
                }
            }
            
            RtlCopyMemory(&pfWorkBuffer[dwYIndex * dwWidth], pfRowBuffer, (SIZE_T)dwCurrentWidth * sizeof(float));
        }
        
        for (dwXIndex = 0; dwXIndex < dwCurrentWidth; dwXIndex++) 
        {
            dwPairCount = (dwCurrentHeight >> 1);
            
            for (dwYIndex = 0; dwYIndex < dwPairCount; dwYIndex++) {
                fValueA = pfWorkBuffer[(dwYIndex << 1) * dwWidth + dwXIndex];
                fValueB = pfWorkBuffer[((dwYIndex << 1) + 1) * dwWidth + dwXIndex];
                pfColumnBuffer[dwYIndex] = (fValueA + fValueB) * g_fNormalizationConstant;
                pfColumnBuffer[dwHalfHeight + dwYIndex] = (fValueA - fValueB) * g_fNormalizationConstant;
            }
            
            if (dwCurrentHeight & 1) 
            {
                fLastValue = pfWorkBuffer[(dwCurrentHeight - 1) * dwWidth + dwXIndex];
                fFirstValue = pfWorkBuffer[0 * dwWidth + dwXIndex];
                if (dwPairCount < dwHalfHeight) {
                    pfColumnBuffer[dwPairCount] = (fLastValue + fFirstValue) * g_fNormalizationConstant;
                    pfColumnBuffer[dwHalfHeight + dwPairCount] = (fLastValue - fFirstValue) * g_fNormalizationConstant;
                }
            }
            
            for (dwYIndex = 0; dwYIndex < dwCurrentHeight; dwYIndex++) {
                pfWorkBuffer[dwYIndex * dwWidth + dwXIndex] = pfColumnBuffer[dwYIndex];
            }
        }

        dwCurrentWidth  = dwHalfWidth;
        dwCurrentHeight = dwHalfHeight;
    }

    dwFinalWidth                            = (dwWidth >> dwLevels);
    dwFinalHeight                           = (dwHeight >> dwLevels);
    dwTotalCoefficients                     = dwFinalWidth * dwFinalHeight;
    pOutputCoeffs->dwCoefficientCount       = dwTotalCoefficients;
    pOutputCoeffs->pfApproximationCoeffs    = (float*)LocalAlloc(LPTR, dwTotalCoefficients * sizeof(float));
    pOutputCoeffs->pfHorizontalCoeffs       = (float*)LocalAlloc(LPTR, dwTotalCoefficients * sizeof(float));
    pOutputCoeffs->pfVerticalCoeffs         = (float*)LocalAlloc(LPTR, dwTotalCoefficients * sizeof(float));
    pOutputCoeffs->pfDiagonalCoeffs         = (float*)LocalAlloc(LPTR, dwTotalCoefficients * sizeof(float));
    
    if (!pOutputCoeffs->pfApproximationCoeffs || !pOutputCoeffs->pfHorizontalCoeffs || !pOutputCoeffs->pfVerticalCoeffs || !pOutputCoeffs->pfDiagonalCoeffs) {
        DBG_PRINT_A("[!] LocalAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    for (dwCopyIndex = 0; dwCopyIndex < dwFinalHeight; dwCopyIndex++) 
    {
        RtlCopyMemory(pOutputCoeffs->pfApproximationCoeffs + dwCopyIndex * dwFinalWidth, &pfWorkBuffer[dwCopyIndex * dwWidth + 0], dwFinalWidth * sizeof(float));
        RtlCopyMemory(pOutputCoeffs->pfHorizontalCoeffs + dwCopyIndex * dwFinalWidth, &pfWorkBuffer[(dwCopyIndex + dwFinalHeight) * dwWidth + 0], dwFinalWidth * sizeof(float));
        RtlCopyMemory(pOutputCoeffs->pfVerticalCoeffs + dwCopyIndex * dwFinalWidth, &pfWorkBuffer[dwCopyIndex * dwWidth + dwFinalWidth], dwFinalWidth * sizeof(float));
        RtlCopyMemory(pOutputCoeffs->pfDiagonalCoeffs + dwCopyIndex * dwFinalWidth, &pfWorkBuffer[(dwCopyIndex + dwFinalHeight) * dwWidth + dwFinalWidth], dwFinalWidth * sizeof(float));
    }

    LocalFree(pfColumnBuffer);
    LocalFree(pfRowBuffer);
    LocalFree(pfWorkBuffer);
    return TRUE;

_END_OF_FUNC:
    if (pfColumnBuffer) 
        LocalFree(pfColumnBuffer);
    if (pfRowBuffer)
        LocalFree(pfRowBuffer);
    if (pfWorkBuffer)
        LocalFree(pfWorkBuffer);
    if (pOutputCoeffs) 
    {
        if (pOutputCoeffs->pfApproximationCoeffs) 
            LocalFree(pOutputCoeffs->pfApproximationCoeffs);
        if (pOutputCoeffs->pfHorizontalCoeffs)
            LocalFree(pOutputCoeffs->pfHorizontalCoeffs);
        if (pOutputCoeffs->pfVerticalCoeffs)
            LocalFree(pOutputCoeffs->pfVerticalCoeffs);
        if (pOutputCoeffs->pfDiagonalCoeffs)
            LocalFree(pOutputCoeffs->pfDiagonalCoeffs);
    }
    return FALSE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL QimDecodeCoeffs(IN const float* pfCoeffs, IN DWORD dwCoefficientCount, IN float fQuantizationStep, OUT PBYTE pbOutputBits, OUT float* pfOutputScores) 
{
    const float fDecisionThreshold0      = fQuantizationStep * 0.25f,
                fDecisionThreshold1      = fQuantizationStep * 0.75f;
    DWORD       dwIndex                  = 0x00;
    float       fCurrentCoeff            = 0.0f,
                fBaseValue               = 0.0f,
                fRemainder               = 0.0f,
                fScore                   = 0.0f;
    
    if (!pfCoeffs || !pbOutputBits || !pfOutputScores || fQuantizationStep <= 0.0f) {
		DBG_PRINT_A("[!] Invalid Parameters");
        return FALSE;
    }
    
    for (dwIndex = 0; dwIndex < dwCoefficientCount; dwIndex++) 
    {
        fCurrentCoeff   = pfCoeffs[dwIndex];
        fBaseValue      = floorf(fCurrentCoeff / fQuantizationStep) * fQuantizationStep;
        fRemainder      = fCurrentCoeff - fBaseValue;
        fRemainder      = fmodf(fRemainder, fQuantizationStep);
        
        if (fRemainder < 0.0f) 
        {
            fRemainder += fQuantizationStep;
        }
        
        fScore                      = fabsf(fRemainder - fDecisionThreshold1) - fabsf(fRemainder - fDecisionThreshold0);
        pfOutputScores[dwIndex]     = fScore;
        pbOutputBits[dwIndex]       = (fScore < 0.0f) ? 1 : 0;
    }
    
    return TRUE;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


static BOOL BuildBitStreamFromLevelAcrossRgb(
    IN  PBYTE   pbRgbaData, 
    IN  DWORD   dwWidth, 
    IN  DWORD   dwHeight,
    IN  DWORD   dwChannels, 
    IN  DWORD   dwLevel, 
    IN  float   fQuantizationStep, 
    OUT PBYTE*  ppbOutputBits,
    OUT float** ppfOutputScores,
    OUT PDWORD  pdwOutputBitCount

) {
    const float*      apfDetailBands[3]       = { 0 };
    DWORD             dwCoeffsPerBand         = 0x00,
                      dwTotalBits             = 0x00,
                      dwBitOffset             = 0x00,
                      dwChannelIndex          = 0x00,
                      dwPixelIndex            = 0x00,
                      dwBandIndex             = 0x00;
    PBYTE             pbBitstream             = NULL;
    float*            pfScores                = NULL;
    float*            pfChannelBuffer         = NULL;
    DWT_COEFFS        dwtCoeffs               = { 0 };
    
    if (!pbRgbaData || dwChannels < 3 || !ppbOutputBits || !ppfOutputScores || !pdwOutputBitCount) {
		DBG_PRINT_A("[!] Invalid Parameters");
        return FALSE;
    }
    
    dwCoeffsPerBand = (dwWidth >> dwLevel) * (dwHeight >> dwLevel);
    if (dwCoeffsPerBand == 0) {
		DBG_PRINT_A("[!] Invalid Level For Image Dimensions");
        return FALSE;
    }
    
    dwTotalBits     = dwCoeffsPerBand * 3 * 3; 
    pbBitstream     = (PBYTE)LocalAlloc(LPTR, dwTotalBits);
    pfScores        = (float*)LocalAlloc(LPTR, dwTotalBits * sizeof(float));
    pfChannelBuffer = (float*)LocalAlloc(LPTR, (SIZE_T)dwWidth * dwHeight * sizeof(float));
    
    if (!pbBitstream || !pfScores || !pfChannelBuffer) 
    {
        DBG_PRINT_A("[!] LocalAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }
    
    dwBitOffset = 0x00;
    
    for (dwChannelIndex = 0; dwChannelIndex < 3; dwChannelIndex++) 
    {
        
        for (dwPixelIndex = 0; dwPixelIndex < dwWidth * dwHeight; dwPixelIndex++) {
            pfChannelBuffer[dwPixelIndex] = (float)pbRgbaData[dwPixelIndex * dwChannels + dwChannelIndex];
        }
        
        ZeroMemory(&dwtCoeffs, sizeof(dwtCoeffs));

        if (!DwtDb1Periodization2D(pfChannelBuffer, dwWidth, dwHeight, dwLevel, &dwtCoeffs)) {
            DBG_PRINT_A("[!] DWT Failed For Channel: %lu", dwChannelIndex);
            goto _END_OF_FUNC;
        }
        
        apfDetailBands[0] = dwtCoeffs.pfHorizontalCoeffs;
        apfDetailBands[1] = dwtCoeffs.pfVerticalCoeffs;
        apfDetailBands[2] = dwtCoeffs.pfDiagonalCoeffs;
        
        for (dwBandIndex = 0; dwBandIndex < 3; dwBandIndex++) 
        {
            if (!QimDecodeCoeffs(apfDetailBands[dwBandIndex], dwtCoeffs.dwCoefficientCount, fQuantizationStep, pbBitstream + dwBitOffset, pfScores + dwBitOffset)) {
                DBG_PRINT_A("[!] QIM Decode Failed For Band: %lu Channel: %lu", dwBandIndex, dwChannelIndex);
                goto _END_OF_FUNC;
            }
            dwBitOffset += dwtCoeffs.dwCoefficientCount;
        }
        
        if (dwtCoeffs.pfApproximationCoeffs) 
            LocalFree(dwtCoeffs.pfApproximationCoeffs);
        if (dwtCoeffs.pfHorizontalCoeffs)
            LocalFree(dwtCoeffs.pfHorizontalCoeffs);
        if (dwtCoeffs.pfVerticalCoeffs)
            LocalFree(dwtCoeffs.pfVerticalCoeffs);
        if (dwtCoeffs.pfDiagonalCoeffs)
            LocalFree(dwtCoeffs.pfDiagonalCoeffs);
    }
    
    *ppbOutputBits      = pbBitstream;
    *ppfOutputScores    = pfScores;
    *pdwOutputBitCount  = dwTotalBits;

    LocalFree(pfChannelBuffer);
    
    return TRUE;

_END_OF_FUNC:
    if (pfChannelBuffer)
        LocalFree(pfChannelBuffer);
    if (pfScores)
        LocalFree(pfScores);
    if (pbBitstream)
        LocalFree(pbBitstream);
    return FALSE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


static BOOL RepDecodeSoftScores(IN const float* pfRepeatedScores, IN DWORD dwScoreCount, IN DWORD dwRepetitionFactor, IN BOOL bInvertDecision, OUT PBYTE pbOutputBits, IN OUT PDWORD pdwInoutBitCount)
{
    DWORD  dwOutputBitCount   = 0x00,
           dwBitIndex         = 0x00,
           dwRepIndex         = 0x00;
    double dScoreSum          = 0.0;
    
    if (!pfRepeatedScores || !pbOutputBits || !pdwInoutBitCount || dwRepetitionFactor < 1) 
    {
		DBG_PRINT_A("[!] Invalid Parameters");
        return FALSE;
    }
    
    dwOutputBitCount = dwScoreCount / dwRepetitionFactor;

    if (*pdwInoutBitCount < dwOutputBitCount) 
    {
        *pdwInoutBitCount = dwOutputBitCount;
		DBG_PRINT_A("[!] Insufficient Output Buffer Size");
        return FALSE;
    }
    
    for (dwBitIndex = 0; dwBitIndex < dwOutputBitCount; dwBitIndex++) {
        dScoreSum = 0.0;
        for (dwRepIndex = 0; dwRepIndex < dwRepetitionFactor; dwRepIndex++) {
            dScoreSum += pfRepeatedScores[dwBitIndex * dwRepetitionFactor + dwRepIndex];
        }
        
        pbOutputBits[dwBitIndex] = bInvertDecision ? (dScoreSum > 0.0 ? 1 : 0) : (dScoreSum < 0.0 ? 1 : 0);

    }
    
    *pdwInoutBitCount = dwOutputBitCount;
    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


static BOOL ScoresToHardBits(IN const float* pfScores, IN DWORD dwScoreCount, IN BOOL bInvertDecision, OUT PBYTE pbOutputBits) 
{
    DWORD dwScoreIndex                   = 0x00;
    
    if (!pfScores || !pbOutputBits) {
        DBG_PRINT_A("[!] Invalid Parameters");
        return FALSE;
    }
    
    for (dwScoreIndex = 0; dwScoreIndex < dwScoreCount; dwScoreIndex++) {
        pbOutputBits[dwScoreIndex] = bInvertDecision ? (pfScores[dwScoreIndex] > 0.0f ? 1 : 0) : (pfScores[dwScoreIndex] < 0.0f ? 1 : 0);
    }
    
    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


static int FindMarkerExact(IN PBYTE pbHardBits, IN DWORD dwBitCount) 
{
    
    static const BYTE abExpectedMarker[MARKER_LEN] = {
        1,1,1,1,1,1,1,1, 0,0,0,0,0,0,0,0, 1,1,1,1,1,1,1,1, 0,0,0,0,0,0,0,0
    };

    DWORD   dwSearchIndex       = 0x00,
            dwMarkerBitIndex    = 0x00;
    BOOL    bMarkerFound        = TRUE;

    if (!pbHardBits || dwBitCount < MARKER_LEN) {
        DBG_PRINT_A("[!] Invalid Parameters");
        return -1;
    }

    for (dwSearchIndex = 0; dwSearchIndex + MARKER_LEN <= dwBitCount; dwSearchIndex++) 
    {
        
        bMarkerFound = TRUE;
        
        for (dwMarkerBitIndex = 0; dwMarkerBitIndex < MARKER_LEN; dwMarkerBitIndex++) 
        {
            if (pbHardBits[dwSearchIndex + dwMarkerBitIndex] != abExpectedMarker[dwMarkerBitIndex]) {
                bMarkerFound = FALSE;
                break;
            }
        }
        
        if (bMarkerFound) return (int)dwSearchIndex;
    }

    return -1;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ParseHeaderPython(IN PBYTE pbHeaderBits, OUT STEG_HEADER* pHeaderOutput) 
{
	BYTE        abHeaderBytes[HEADER_BYTES_LEN] = { 0 };
    DWORD       dwByteCount                     = sizeof(abHeaderBytes);
    WORD        wStoredCrc                      = 0x00,
                wCalculatedCrc                  = 0x00;
    STEG_HEADER HdrData                         = { 0 };

    union { DWORD u; float f; } FloatConverter;
    
    if (!pbHeaderBits || !pHeaderOutput) {
		DBG_PRINT_A("[!] Invalid Parameters");
        return FALSE;
    }
    
    if (!ConvertBitsToBytesMSB(pbHeaderBits, HEADER_BITS_LEN, abHeaderBytes, &dwByteCount)) 
    {
		DBG_PRINT_A("[!] ConvertBitsToBytesMSB Failed");
        return FALSE;
    }

    if (dwByteCount != HEADER_BYTES_LEN) 
    {
        DBG_PRINT_A("[!] Header Byte Count Mismatch: Got %lu Expected %d", dwByteCount, HEADER_BYTES_LEN);
        return FALSE;
    }
    
    wStoredCrc      = (WORD)(abHeaderBytes[HEADER_BYTES_LEN - 2] | (abHeaderBytes[HEADER_BYTES_LEN - 1] << 8));
    wCalculatedCrc  = Crc16CcittFalse(abHeaderBytes, HEADER_BYTES_LEN - 2);
    
    if (wStoredCrc != wCalculatedCrc) 
    {
        DBG_PRINT_A("[!] Header CRC Mismatch: Stored 0x%04X Calculated 0x%04X", wStoredCrc, wCalculatedCrc);
        SetLastError(ERROR_CRC);
        return FALSE;
    }
    
    HdrData.bVersion                = abHeaderBytes[0];
    HdrData.bRepetitionMeta         = abHeaderBytes[1];
    HdrData.bEccSymbolCount         = abHeaderBytes[2];
    HdrData.bLevelData              = abHeaderBytes[3];
    FloatConverter.u                = (DWORD)abHeaderBytes[4] | ((DWORD)abHeaderBytes[5] << 8) | ((DWORD)abHeaderBytes[6] << 16) | ((DWORD)abHeaderBytes[7] << 24);
    HdrData.fQuantizationStepData   = FloatConverter.f;
    HdrData.dwMetaLengthBits        = (DWORD)abHeaderBytes[8] | ((DWORD)abHeaderBytes[9] << 8) | ((DWORD)abHeaderBytes[10] << 16) | ((DWORD)abHeaderBytes[11] << 24);
    HdrData.dwDataLengthBits        = (DWORD)abHeaderBytes[12] | ((DWORD)abHeaderBytes[13] << 8) | ((DWORD)abHeaderBytes[14] << 16) | ((DWORD)abHeaderBytes[15] << 24);
    HdrData.dwDataCrc32             = (DWORD)abHeaderBytes[16] | ((DWORD)abHeaderBytes[17] << 8) | ((DWORD)abHeaderBytes[18] << 16) | ((DWORD)abHeaderBytes[19] << 24);
    HdrData.wHeaderCrc16            = wStoredCrc;
    
    if (HdrData.bVersion != FORMAT_VERSION) {
        DBG_PRINT_A("[!] Invalid Version: %u Expected %u", HdrData.bVersion, FORMAT_VERSION);
        return FALSE;
    }
    
    if (HdrData.bLevelData < 1 || HdrData.bLevelData > 6) {
        DBG_PRINT_A("[!] Invalid Level Data: %u", HdrData.bLevelData);
        return FALSE;
    }
    
    if (HdrData.fQuantizationStepData <= 0.0f || !isfinite(HdrData.fQuantizationStepData)) {
        DBG_PRINT_A("[!] Invalid QStep Data: %.2f", (double)HdrData.fQuantizationStepData);
        return FALSE;
    }
    
    if ((HdrData.dwMetaLengthBits % 8) != 0 && HdrData.dwMetaLengthBits != 0) {
        DBG_PRINT_A("[!] Invalid Meta Length Bits: %lu Not Byte Aligned", HdrData.dwMetaLengthBits);
        return FALSE;
    }
    
    if ((HdrData.dwDataLengthBits % 8) != 0 || HdrData.dwDataLengthBits == 0) {
        DBG_PRINT_A("[!] Invalid Data Length Bits: %lu Not Byte Aligned Or Zero", HdrData.dwDataLengthBits);
        return FALSE;
    }
    
    *pHeaderOutput = HdrData;

    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL TryDecodeHeader(
    IN  PBYTE           pbRgbaData, 
    IN  DWORD           dwWidth, 
    IN  DWORD           dwHeight,
    IN  DWORD           dwChannels, 
    IN  DWORD           dwLevel,
    IN  float           fQuantizationStep, 
    IN  BOOL            bInvertDecision,
    OUT STEG_HEADER*    pHeaderOutput, 
    OUT PBOOL           pbOutputInvert OPTIONAL
) {
    
    BYTE            abHeaderBits[HEADER_BITS_LEN]  = { 0 };
    DWORD           dwBitstreamLength              = 0x00,
                    dwMarkerIndex                  = 0x00,
                    dwRequiredScores               = 0x00,
                    dwOutputLength                 = HEADER_BITS_LEN;
    INT             iMarkerPosition                = 0x00;
    BOOL            bOperationSuccess              = FALSE;
    PBYTE           pbBitstream                    = NULL;
    float*          pfScores                       = NULL;
    PBYTE           pbHardBits                     = NULL;
    STEG_HEADER     HdrData                        = { 0 };
    
    if (!BuildBitStreamFromLevelAcrossRgb(pbRgbaData, dwWidth, dwHeight, dwChannels, dwLevel, fQuantizationStep, &pbBitstream, &pfScores, &dwBitstreamLength)) {
        DBG_PRINT_A("[!] BuildBitStreamFromLevelAcrossRgb Failed");
        goto _END_OF_FUNC;
    }
    
    if (!(pbHardBits = (PBYTE)LocalAlloc(LPTR, dwBitstreamLength))) {
        DBG_PRINT_A("[!] LocalAlloc Failed With Error: %lu", GetLastError());
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        goto _END_OF_FUNC;
    }
    
    if (!ScoresToHardBits(pfScores, dwBitstreamLength, bInvertDecision, pbHardBits)) {
        DBG_PRINT_A("[!] ScoresToHardBits Failed ");
        goto _END_OF_FUNC;
    }
    
    iMarkerPosition = FindMarkerExact(pbHardBits, dwBitstreamLength);

    if (iMarkerPosition < 0) 
    {
        DBG_PRINT_A("[!] Marker Not Found In Bitstream");
        goto _END_OF_FUNC;
    }

    dwMarkerIndex    = (DWORD)iMarkerPosition + MARKER_LEN;
    dwRequiredScores = HEADER_BITS_LEN * REP_HEADER;
    
    if (dwMarkerIndex + dwRequiredScores > dwBitstreamLength) {
        DBG_PRINT_A("[!] Insufficient Bits After Marker: Need %lu Have %lu", dwRequiredScores, dwBitstreamLength - dwMarkerIndex);
        goto _END_OF_FUNC;
    }
    
    if (!RepDecodeSoftScores(pfScores + dwMarkerIndex, dwRequiredScores, REP_HEADER, bInvertDecision, abHeaderBits, &dwOutputLength)) {
        DBG_PRINT_A("[!] RepDecodeSoftScores Failed");
        goto _END_OF_FUNC;
    }
    

    if (!ParseHeaderPython(abHeaderBits, &HdrData)) {
        DBG_PRINT_A("[!] ParseHeaderPython Failed");
        goto _END_OF_FUNC;
    }
    
    *pHeaderOutput      = HdrData;
    if (pbOutputInvert) 
        *pbOutputInvert = bInvertDecision;
    bOperationSuccess = TRUE;

_END_OF_FUNC:
    if (pbHardBits)
        LocalFree(pbHardBits);
    if (pfScores) 
        LocalFree(pfScores);
    if (pbBitstream) 
        LocalFree(pbBitstream);
    return bOperationSuccess;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL XpressHuffmanDecompress(IN PBYTE pbCompressedData, IN DWORD dwCompressedSize, OUT PBYTE* ppbDecompressedData, OUT PDWORD pdwDecompressedSize) 
{
    COMPRESSOR_HANDLE   hDecompressor                 = NULL;
    SIZE_T              szBufferGuess                 = 0x00;
    SIZE_T              szActualOutputSize            = 0x00;
    DWORD               dwErrorCode                   = 0x00;
    PBYTE               pbOutputBuffer                = NULL;
    
    if (!pbCompressedData || !dwCompressedSize || !ppbDecompressedData || !pdwDecompressedSize) {
		DBG_PRINT_A("[!] Invalid Parameters");
        return FALSE;
    }
    
    *ppbDecompressedData = NULL;
    *pdwDecompressedSize = 0;
    
    if (!CreateDecompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, NULL, &hDecompressor)) {
        DBG_PRINT_A("[!] CreateDecompressor Failed With Error: 0x%0.8X", GetLastError());
        return FALSE;
    }
    
    szBufferGuess = max((SIZE_T)dwCompressedSize * 8, (SIZE_T)64 * 1024);
    
    for (;;) 
    {
        if (pbOutputBuffer) {
            LocalFree(pbOutputBuffer);
            pbOutputBuffer = NULL;
        }
        
        if (!(pbOutputBuffer = (PBYTE)LocalAlloc(LPTR, szBufferGuess))) {
            DBG_PRINT_A("[!] LocalAlloc Failed With Error: 0x%0.8X", GetLastError());
            CloseDecompressor(hDecompressor);
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        
        if (Decompress(hDecompressor, pbCompressedData, (SIZE_T)dwCompressedSize, pbOutputBuffer, szBufferGuess, &szActualOutputSize)) {
            *ppbDecompressedData = pbOutputBuffer;
            *pdwDecompressedSize = (DWORD)szActualOutputSize;
            CloseDecompressor(hDecompressor);
            return TRUE;
        }
        
        dwErrorCode = GetLastError();
        if (dwErrorCode == ERROR_INSUFFICIENT_BUFFER) {
            szBufferGuess <<= 1;
            continue;
        }
        
        DBG_PRINT_A("[!] Decompress Failed With Error: 0x%0.8X", dwErrorCode);
        LocalFree(pbOutputBuffer);
        CloseDecompressor(hDecompressor);
        return FALSE;
    }

    return FALSE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


static BOOL StripRsParity(IN PBYTE pbEncodedData, IN DWORD dwEncodedLength, IN DWORD dwEccByteCount, OUT PBYTE pbMessageData, IN OUT PDWORD pdwMessageLength) 
{
    
    DWORD dwActualDataLength             = 0x00;
    
    if (!pbEncodedData || !pbMessageData || !pdwMessageLength) {
		DBG_PRINT_A("[!] Invalid Parameters");
        return FALSE;
    }
    
    if (dwEncodedLength < dwEccByteCount) {
        DBG_PRINT_A("[!] Encoded Length %lu Less Than ECC Bytes %lu", dwEncodedLength, dwEccByteCount);
        return FALSE;
    }
    
    dwActualDataLength = dwEncodedLength - dwEccByteCount;
    
    if (*pdwMessageLength < dwActualDataLength) 
    {
		DBG_PRINT_A("[!] Insufficient Output Buffer Size: Need %lu Have %lu", dwActualDataLength, *pdwMessageLength);
        *pdwMessageLength = dwActualDataLength;
        return FALSE;
    }
    
    RtlCopyMemory(pbMessageData, pbEncodedData, dwActualDataLength);
    *pdwMessageLength = dwActualDataLength;
    return TRUE;
}




// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


static BOOL ReedSolomonDecodeChunked(IN const BYTE* pbEncodedData, IN DWORD dwEncodedLength, IN DWORD dwSymbolCount, OUT BYTE* pbDecodedData, IN OUT DWORD* pdwDecodedLength) 
{
    const DWORD   dwCodewordLength                      = RS_FIELD_CHARAC,
                  dwPaddingBytes                        = 0x00;
    DWORD         dwMessageLength                       = RS_FIELD_CHARAC - dwSymbolCount,
                  dwFullBlocks                          = 0x00,
                  dwRemainderBytes                      = 0x00,
                  dwExpectedOutputLength                = 0x00,
                  dwInputOffset                         = 0x00,
                  dwOutputOffset                        = 0x00,
                  dwChunkIndex                          = 0x00,
                  dwErrorPositions[RS_FIELD_CHARAC]     = { 0 },
                  dwErrorCount                          = RS_FIELD_CHARAC,
                  dwCurrentBlockLength                  = 0x00,
                  dwPaddingLength                       = 0x00;
    BOOL          bDecodeSuccess                        = FALSE;
    BYTE          abCodeword[RS_FIELD_CHARAC]           = { 0 },
                  abMessageOutput[RS_FIELD_CHARAC]      = { 0 },
                  abEccOutput[RS_FIELD_CHARAC]          = { 0 };
	RS_CONTEXT    rsContext                             = { 0 };
    
    if (!pbEncodedData || !pbDecodedData || !pdwDecodedLength) 
    {
		DBG_PRINT_A("[!] Invalid Parameters");
        return FALSE;
    }
    
    if (!RsCreateContext(&rsContext, dwSymbolCount, 0, RS_GENERATOR, RS_PRIM_POLY)) {
		DBG_PRINT_A("[!] RsCreateContext Failed ");
        return FALSE;
    }
    
    dwFullBlocks            = dwEncodedLength / dwCodewordLength;
    dwRemainderBytes        = dwEncodedLength % dwCodewordLength;
    dwExpectedOutputLength  = dwFullBlocks * dwMessageLength;
    
    if (dwRemainderBytes > dwSymbolCount) {
        dwExpectedOutputLength += (dwRemainderBytes - dwSymbolCount);
    }
    
    if (*pdwDecodedLength < dwExpectedOutputLength) {
        *pdwDecodedLength = dwExpectedOutputLength;
		DBG_PRINT_A("[!] Insufficient Output Buffer Size: Need %lu Have %lu", dwExpectedOutputLength, *pdwDecodedLength);
        return FALSE;
    }
    
    dwInputOffset   = 0;
    dwOutputOffset  = 0;
    
    for (dwChunkIndex = 0; dwChunkIndex < dwFullBlocks; dwChunkIndex++) 
    {
        ZeroMemory(abMessageOutput, sizeof(abMessageOutput));
        ZeroMemory(abEccOutput, sizeof(abEccOutput));
        ZeroMemory(dwErrorPositions, sizeof(dwErrorPositions));
        dwErrorCount = RS_FIELD_CHARAC;
        
        RtlCopyMemory(abCodeword, pbEncodedData + dwInputOffset, dwCodewordLength);
        
        bDecodeSuccess = RsDecodeMessage(
            &rsContext,
            abCodeword,
            dwCodewordLength,
            abMessageOutput, 
            abEccOutput,
            NULL, 0x00,  // no Erasures
            dwErrorPositions,
            &dwErrorCount
        );
        
        if (!bDecodeSuccess) 
        {
            DBG_PRINT_A("[!] RsDecodeMessage Failed For Block %lu... Copying Uncorrected Block", dwChunkIndex);
            RtlCopyMemory(pbDecodedData + dwOutputOffset, pbEncodedData + dwInputOffset, dwMessageLength);
        } 
        else 
        {
            RtlCopyMemory(pbDecodedData + dwOutputOffset, abMessageOutput, dwMessageLength);
        }
        
        dwInputOffset  += dwCodewordLength;
        dwOutputOffset += dwMessageLength;
    }
    
    if (dwRemainderBytes > dwSymbolCount) 
    {
        dwCurrentBlockLength    = dwRemainderBytes;
        dwPaddingLength         = dwCodewordLength - dwCurrentBlockLength;
        
        ZeroMemory(abCodeword, sizeof(abCodeword));
        ZeroMemory(abMessageOutput, sizeof(abMessageOutput));
        ZeroMemory(abEccOutput, sizeof(abEccOutput));
        ZeroMemory(dwErrorPositions, sizeof(dwErrorPositions));
        dwErrorCount = RS_FIELD_CHARAC;
        
        RtlCopyMemory(abCodeword + dwPaddingLength, pbEncodedData + dwInputOffset, dwCurrentBlockLength);
        
        bDecodeSuccess = RsDecodeMessage(
            &rsContext,
            abCodeword, 
            dwCodewordLength,
            abMessageOutput, 
            abEccOutput,
            NULL, 0x00,  // no Erasures
            dwErrorPositions, 
            &dwErrorCount
        );
        
        if (!bDecodeSuccess) 
        {
            DBG_PRINT_A("[!] RsDecodeMessage Failed For Last Block Copying Uncorrected");
            RtlCopyMemory(pbDecodedData + dwOutputOffset, pbEncodedData + dwInputOffset, dwCurrentBlockLength - dwSymbolCount);
        } 
        else 
        {
            RtlCopyMemory(pbDecodedData + dwOutputOffset, abMessageOutput + dwPaddingLength, dwCurrentBlockLength - dwSymbolCount);
        }
        
        dwOutputOffset += (dwCurrentBlockLength - dwSymbolCount);
    }
    
    *pdwDecodedLength = dwOutputOffset;
    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


BOOL ExtractPeFromPngAligned(IN PBYTE pbPngData, IN DWORD dwPngLength, OUT PBYTE* ppbOutputPe, OUT PDWORD pdwOutputPeLength) 
{
    
    DWORD       dwImageWidth                   = 0x00,
                dwImageHeight                  = 0x00,
                dwImageChannels                = 0x00,
                dwBitstreamLength              = 0x00,
                dwBitIndex                     = 0x00,
                dwRequiredBits                 = 0x00,
                dwMetaRepetitionLength         = 0x00,
                dwMetaOutputLength             = 0x00,
                dwCompressedEccLength          = 0x00,
                dwTempLength                   = 0x00,
                dwCompressedLength             = 0x00,
                dwPeLength                     = 0x00,
                dwCalculatedCrc                = 0x00;
    BOOL        bInvertDecision                = FALSE,
                bOperationSuccess              = FALSE;
    PBYTE       pbRgbaData                     = NULL;
    PBYTE       pbBitstream                    = NULL;
    float*      pfScores                       = NULL;
    PBYTE       pbMetadataBits                 = NULL;
    PBYTE       pbDataScoreBits                = NULL;
    PBYTE       pbCompressedEcc                = NULL;
    PBYTE       pbCompressed                   = NULL;
    PBYTE       pbPeData                       = NULL;
    STEG_HEADER HdrData                        = { 0 };

    if (!pbPngData || !dwPngLength || !ppbOutputPe || !pdwOutputPeLength) 
    {
		DBG_PRINT_A("[!] Invalid Parameters");
        return FALSE;
    }

    *ppbOutputPe = NULL;
    *pdwOutputPeLength = 0;

    if (!DecodePngToRgbaWic(pbPngData, dwPngLength, &pbRgbaData, &dwImageWidth, &dwImageHeight, &dwImageChannels)) 
    {
		DBG_PRINT_A("[!] DecodePngToRgbaWic Failed ");
        return FALSE;
    }
    
    bOperationSuccess =
        TryDecodeHeader(pbRgbaData, dwImageWidth, dwImageHeight, dwImageChannels, LEVEL_PILOT, QSTEP_PILOT, FALSE, &HdrData, &bInvertDecision)  ||
        TryDecodeHeader(pbRgbaData, dwImageWidth, dwImageHeight, dwImageChannels, LEVEL_PILOT, QSTEP_PILOT, TRUE, &HdrData, &bInvertDecision)   ||
        TryDecodeHeader(pbRgbaData, dwImageWidth, dwImageHeight, dwImageChannels, LEVEL_DATA, QSTEP_DATA, FALSE, &HdrData, &bInvertDecision)    ||
        TryDecodeHeader(pbRgbaData, dwImageWidth, dwImageHeight, dwImageChannels, LEVEL_DATA, QSTEP_DATA, TRUE, &HdrData, &bInvertDecision);

    if (!bOperationSuccess) 
    {
        DBG_PRINT_A("[!] Header Parse/CRC Failed At All Strategies");
        goto _END_OF_FUNC;
    }

    if (!BuildBitStreamFromLevelAcrossRgb(pbRgbaData, dwImageWidth, dwImageHeight, dwImageChannels, HdrData.bLevelData, HdrData.fQuantizationStepData, &pbBitstream, &pfScores, &dwBitstreamLength)) {
        DBG_PRINT_A("[!] BuildBitStreamFromLevelAcrossRgb Failed");
        goto _END_OF_FUNC;
    }
    
    LocalFree(pbBitstream);
    pbBitstream     = NULL;
    dwBitIndex      = HEADER_DUP_AT_L2 ? HEADER_PILOT_BITS_LEN : 0;
    dwRequiredBits  = dwBitIndex + HdrData.dwMetaLengthBits * (DWORD)HdrData.bRepetitionMeta + HdrData.dwDataLengthBits;

    if (dwRequiredBits > dwBitstreamLength) 
    {
        DBG_PRINT_A("[!] Insufficient Bits In Data Stream: Need %lu Have %lu", dwRequiredBits, dwBitstreamLength);
        goto _END_OF_FUNC;
    }

    if (HdrData.dwMetaLengthBits) 
    {
        dwMetaRepetitionLength  = HdrData.dwMetaLengthBits * (DWORD)HdrData.bRepetitionMeta;
        pbMetadataBits          = (PBYTE)LocalAlloc(LPTR, HdrData.dwMetaLengthBits);
        dwMetaOutputLength      = HdrData.dwMetaLengthBits;
        
        if (!pbMetadataBits) 
        {
            DBG_PRINT_A("[!] LocalAlloc Failed With Error: %lu", GetLastError());
            goto _END_OF_FUNC;
        }

        if (!RepDecodeSoftScores(pfScores + dwBitIndex, dwMetaRepetitionLength, HdrData.bRepetitionMeta, bInvertDecision, pbMetadataBits, &dwMetaOutputLength)) 
        {
            DBG_PRINT_A("[!] RepDecodeSoftScores Failed ");
            LocalFree(pbMetadataBits);
			pbMetadataBits = NULL;
            goto _END_OF_FUNC;
        }
        
        LocalFree(pbMetadataBits);
		pbMetadataBits = NULL;
        dwBitIndex += dwMetaRepetitionLength;
    }

    if (!(pbDataScoreBits = (PBYTE)LocalAlloc(LPTR, HdrData.dwDataLengthBits))) {
        DBG_PRINT_A("[!] LocalAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ScoresToHardBits(pfScores + dwBitIndex, HdrData.dwDataLengthBits, bInvertDecision, pbDataScoreBits)) 
    {
        DBG_PRINT_A("[!] ScoresToHardBits Failed");
        LocalFree(pbDataScoreBits);
		pbDataScoreBits = NULL;
        goto _END_OF_FUNC;
    }

    LocalFree(pfScores);
    pfScores = NULL;

    dwCompressedEccLength = HdrData.dwDataLengthBits / 8;
    
    if (!(pbCompressedEcc = (PBYTE)LocalAlloc(LPTR, dwCompressedEccLength))) {
        DBG_PRINT_A("[!] LocalAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    dwTempLength = dwCompressedEccLength;
    if (!ConvertBitsToBytesMSB(pbDataScoreBits, HdrData.dwDataLengthBits, pbCompressedEcc, &dwTempLength)) {
        DBG_PRINT_A("[!] ConvertBitsToBytesMSB Failed");
        goto _END_OF_FUNC;
    }


    LocalFree(pbDataScoreBits);
	pbDataScoreBits = NULL;

    dwCompressedLength = dwCompressedEccLength >= HdrData.bEccSymbolCount ? dwCompressedEccLength - HdrData.bEccSymbolCount : 0;
    
    if (!(pbCompressed = (PBYTE)LocalAlloc(LPTR, dwCompressedLength ? dwCompressedLength : 1))) 
    {
        DBG_PRINT_A("[!] LocalAlloc Failed With Error: 0x%0.8X", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ReedSolomonDecodeChunked(pbCompressedEcc, dwCompressedEccLength, HdrData.bEccSymbolCount, pbCompressed, &dwCompressedLength)) {
        DBG_PRINT_A("[!] ReedSolomonDecodeChunked Failed");
        goto _END_OF_FUNC;
    }

    LocalFree(pbCompressedEcc);
	pbCompressedEcc = NULL;

    dwCalculatedCrc = Crc32Compute(pbCompressed, dwCompressedLength);
    if (dwCalculatedCrc != HdrData.dwDataCrc32) {
        DBG_PRINT_A("[!] CRC Mismatch On RS-Decoded Data: Expected 0x%08lX Got 0x%08lX", (unsigned long)HdrData.dwDataCrc32, (unsigned long)dwCalculatedCrc);
        goto _END_OF_FUNC;
    }

    if (!XpressHuffmanDecompress(pbCompressed, dwCompressedLength, &pbPeData, &dwPeLength)) {
        DBG_PRINT_A("[!] XpressHuffmanDecompress Failed ");
        goto _END_OF_FUNC;
    }

    LocalFree(pbCompressed);
    LocalFree(pbRgbaData);

    *ppbOutputPe        = pbPeData;
    *pdwOutputPeLength  = dwPeLength;
    
    return TRUE;

_END_OF_FUNC:
    if (pbRgbaData) 
        LocalFree(pbRgbaData);
    if (pbBitstream) 
        LocalFree(pbBitstream);
    if (pfScores)
        LocalFree(pfScores);
    if (pbDataScoreBits) 
        LocalFree(pbDataScoreBits);
    if (pbCompressedEcc) 
        LocalFree(pbCompressedEcc);
    if (pbCompressed)
        LocalFree(pbCompressed);
    return FALSE;
}

