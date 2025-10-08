#include <Windows.h>
#include <d3d11.h>
#include <d3d11_4.h>


#include "DebugMacros.h"
#include "GpuManipulation.h"

#pragma comment(lib, "d3d11.lib")


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Constants definitions

#ifndef ERROR_GPU_EXCEPTION
#define ERROR_GPU_EXCEPTION 0x20001000L
#endif

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Implementations

BOOL WINAPI InitializeD3D11Device(OUT ID3D11Device** ppDevice, OUT ID3D11DeviceContext** ppContext, OPTIONAL DWORD dwAdapterIndex)
{
    BOOL                    bResult             = FALSE;
    HRESULT                 hrResult            = E_FAIL;
    D3D_FEATURE_LEVEL       FeatureLevel        = (D3D_FEATURE_LEVEL)0x00;
    D3D_FEATURE_LEVEL       FeatureLevels[  ]   =
    {
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0
    };
    UINT                    uFeatureLevelCount  = ARRAYSIZE(FeatureLevels);
    UINT                    uCreateFlags        = 0x00;
    ID3D11Multithread*      Multithread         = NULL;       

    // Validate parameters
    if (ppDevice == NULL || ppContext == NULL)
    {
        DBG_PRINT_A("[!] InitializeD3D11Device: Invalid Parameters");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // Initialize output parameters
    *ppDevice   = NULL;
    *ppContext  = NULL;

#ifdef _DEBUG
    // uCreateFlags |= D3D11_CREATE_DEVICE_DEBUG;
#endif


    // Create D3D11 device and context
    hrResult = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, uCreateFlags, FeatureLevels, uFeatureLevelCount, D3D11_SDK_VERSION, ppDevice, &FeatureLevel, ppContext);

    if (FAILED(hrResult))
    {
        DBG_PRINT_A("[!] D3D11CreateDevice Failed With Error: 0x%08X", hrResult);
        DBG_PRINT_A("[i] Attempting WARP Instead ...");
        SetLastError(hrResult);

        hrResult = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_WARP, NULL, uCreateFlags, FeatureLevels, uFeatureLevelCount, D3D11_SDK_VERSION, ppDevice, &FeatureLevel, ppContext);
        if (FAILED(hrResult))
        {
            DBG_PRINT_A("[!] D3D11CreateDevice Failed With Error: 0x%08X", hrResult);
            SetLastError(hrResult);
            goto _END_OF_FUNC;
        }
    }

    if (SUCCEEDED((*ppContext)->QueryInterface(IID_PPV_ARGS(&Multithread))))
    {
        Multithread->SetMultithreadProtected(TRUE);

        if (!Multithread->GetMultithreadProtected())
        {
            DBG_PRINT_A("[-] Failed To Enable Multithread Protection On D3D11 Device Context");
            Multithread->Release();
			goto _END_OF_FUNC;
		}
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (!bResult)
    {
        if (*ppContext != NULL)
        {
            (*ppContext)->Release();
            *ppContext = NULL;
        }

        if (*ppDevice != NULL)
        {
            (*ppDevice)->Release();
            *ppDevice = NULL;
        }
    }

    return bResult;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL WINAPI CreateVramBlob(IN ID3D11Device* pDevice, IN DWORD dwSizeInBytes, OUT PVRAM_BLOB pVramBlob)
{
    BOOL                bResult         = FALSE;
    HRESULT             hrResult        = E_FAIL;
    D3D11_BUFFER_DESC   bufferDesc      = { 0 };

    if (pDevice == NULL || pVramBlob == NULL || dwSizeInBytes == 0 || dwSizeInBytes > 0x7FFFFFFF)
    {
        DBG_PRINT_A("[!] CreateVramBlob: Invalid Parameters");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    RtlZeroMemory(pVramBlob, sizeof(VRAM_BLOB));
    RtlZeroMemory(&bufferDesc, sizeof(D3D11_BUFFER_DESC));

    bufferDesc.ByteWidth            = dwSizeInBytes;
    bufferDesc.Usage                = D3D11_USAGE_DEFAULT;      // GPU local memory
    bufferDesc.BindFlags            = 0x00;                     // Raw buffer for copies
    bufferDesc.CPUAccessFlags       = 0x00;                     // No CPU access
    bufferDesc.MiscFlags            = 0x00;
    bufferDesc.StructureByteStride  = 0x00;

    // Create the GPU buffer
    hrResult = pDevice->CreateBuffer(&bufferDesc, NULL, &pVramBlob->pGpuBuffer);
    if (FAILED(hrResult))
    {
        DBG_PRINT_A("[!] CreateBuffer Failed With Error: 0x%08X", hrResult);
        SetLastError(hrResult);
        goto _END_OF_FUNC;
    }

    // Fill in the structure
    pVramBlob->dwSizeInBytes    = dwSizeInBytes;
    pVramBlob->dwFlags          = 0x00;
    pVramBlob->pvReserved       = NULL;

    bResult = TRUE;

_END_OF_FUNC:
    if (!bResult)
    {
        if (pVramBlob != NULL && pVramBlob->pGpuBuffer != NULL)
        {
            pVramBlob->pGpuBuffer->Release();
            pVramBlob->pGpuBuffer = NULL;
        }
    }

    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL WINAPI DestroyVramBlob(IN OUT PVRAM_BLOB pVramBlob)
{
    if (pVramBlob == NULL)
    {
        DBG_PRINT_A("[!] DestroyVramBlob: Invalid Parameters");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // Release GPU buffer if allocated
    if (pVramBlob->pGpuBuffer != NULL)
    {
        pVramBlob->pGpuBuffer->Release();
        pVramBlob->pGpuBuffer = NULL;
    }

    RtlZeroMemory(pVramBlob, sizeof(VRAM_BLOB));

    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL WINAPI UploadToVram(IN ID3D11DeviceContext* pContext, IN PCVRAM_BLOB pVramBlob, IN LPCVOID pvHostData)
{
    if (pContext == NULL || pVramBlob == NULL || pvHostData == NULL || pVramBlob->pGpuBuffer == NULL || pVramBlob->dwSizeInBytes == 0)
    {
        DBG_PRINT_A("[!] UploadToVram: Invalid Parameters");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    __try
    {
        pContext->UpdateSubresource(pVramBlob->pGpuBuffer, 0x00, NULL, pvHostData, 0x00, 0x00);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DBG_PRINT_A("[!] UpdateSubresource Triggered An Exception: 0x%0.8X", GetExceptionCode());
		return FALSE;
    }

    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL WINAPI DownloadFromVram(IN ID3D11Device* pDevice, IN ID3D11DeviceContext* pContext, IN PCVRAM_BLOB pVramBlob, OUT PVOID pvHostBuffer)
{
    BOOL                        bResult                 = FALSE;
    HRESULT                     hrResult                = E_FAIL;
    ID3D11Buffer*               pStagingBuffer          = NULL;
    D3D11_BUFFER_DESC           StagingDesc             = { 0 };
    D3D11_MAPPED_SUBRESOURCE    MappedResource          = { 0 };

    // Validate parameters
    if (pDevice == NULL || pContext == NULL || pVramBlob == NULL || pvHostBuffer == NULL || pVramBlob->pGpuBuffer == NULL || pVramBlob->dwSizeInBytes == 0)
    {
        DBG_PRINT_A("[!] DownloadFromVram: Invalid Parameters");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // Create staging buffer for CPU readback
    RtlZeroMemory(&StagingDesc, sizeof(D3D11_BUFFER_DESC));
    StagingDesc.ByteWidth           = pVramBlob->dwSizeInBytes;
    StagingDesc.Usage               = D3D11_USAGE_STAGING;
    StagingDesc.BindFlags           = 0x00;
    StagingDesc.CPUAccessFlags      = D3D11_CPU_ACCESS_READ;
    StagingDesc.MiscFlags           = 0x00;
    StagingDesc.StructureByteStride = 0x00;

    hrResult = pDevice->CreateBuffer(&StagingDesc, NULL, &pStagingBuffer);
    if (FAILED(hrResult))
    {
        DBG_PRINT_A("[!] CreateBuffer Failed With Error: 0x%08X", hrResult);
        SetLastError(hrResult);
        return FALSE;
    }

    // Copy from GPU buffer to staging buffer
    __try
    {
        pContext->CopyResource(pStagingBuffer, pVramBlob->pGpuBuffer);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DBG_PRINT_A("[!] CopyResource Triggered An Exception: 0x%0.8X", GetExceptionCode());
        return FALSE;
    }

    // Map staging buffer and copy to host memory
    RtlZeroMemory(&MappedResource, sizeof(D3D11_MAPPED_SUBRESOURCE));

    hrResult = pContext->Map(pStagingBuffer, 0, D3D11_MAP_READ, 0, &MappedResource);

    if (FAILED(hrResult))
    {
        DBG_PRINT_A("[!] Map Failed With Error: 0x%08X", hrResult);
        SetLastError(hrResult);
        goto _END_OF_FUNC;
    }

    // Copy data to output buffer
    __try
    {
        RtlCopyMemory(pvHostBuffer, MappedResource.pData, pVramBlob->dwSizeInBytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DBG_PRINT_A("[!] RtlCopyMemory Triggered An Exception: 0x%0.8X", GetExceptionCode());
        return FALSE;
    }

    // Unmap the staging buffer
    pContext->Unmap(pStagingBuffer, 0);

	bResult = TRUE;

_END_OF_FUNC:
    if (pStagingBuffer != NULL)
    {
        pStagingBuffer->Release();
        pStagingBuffer = NULL;
    }

    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL WINAPI CopyVramToVram(IN ID3D11DeviceContext* pContext, IN PCVRAM_BLOB pDestBlob, IN PCVRAM_BLOB pSrcBlob)
{
    if (pContext == NULL || pDestBlob == NULL || pSrcBlob == NULL || pDestBlob->pGpuBuffer == NULL || pSrcBlob->pGpuBuffer == NULL)
    {
        DBG_PRINT_A("[!] CopyVramToVram: Invalid Parameters");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (pDestBlob->dwSizeInBytes != pSrcBlob->dwSizeInBytes)
    {
        DBG_PRINT_A("[!] CopyVramToVram: Invalid Parameters");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // Perform GPU to GPU copy
    __try
    {
        pContext->CopyResource(pDestBlob->pGpuBuffer, pSrcBlob->pGpuBuffer);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DBG_PRINT_A("[!] CopyResource Triggered An Exception: 0x%0.8X", GetExceptionCode());
        return FALSE;
    }

    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

