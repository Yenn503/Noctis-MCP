#pragma once


#ifndef _GPU_MANIPULATION_
#define _GPU_MANIPULATION_
#include <Windows.h>
#include <d3d11.h>


typedef struct _VRAM_BLOB {
    ID3D11Buffer*   pGpuBuffer;
    DWORD           dwSizeInBytes;
    DWORD           dwFlags;
    PVOID           pvReserved;
} VRAM_BLOB, * PVRAM_BLOB;

typedef const VRAM_BLOB* PCVRAM_BLOB;


#ifdef __cplusplus
extern "C" {
#endif

    BOOL WINAPI InitializeD3D11Device(OUT ID3D11Device** ppDevice, OUT ID3D11DeviceContext** ppContext, OPTIONAL DWORD dwAdapterIndex);

    BOOL WINAPI CreateVramBlob(IN ID3D11Device* pDevice, IN DWORD dwSizeInBytes, OUT PVRAM_BLOB pVramBlob);

    BOOL WINAPI DestroyVramBlob(IN OUT PVRAM_BLOB pVramBlob);

    BOOL WINAPI UploadToVram(IN ID3D11DeviceContext* pContext, IN PCVRAM_BLOB pVramBlob, IN LPCVOID pvHostData);

    BOOL WINAPI DownloadFromVram(IN ID3D11Device* pDevice, IN ID3D11DeviceContext* pContext, IN PCVRAM_BLOB pVramBlob, OUT PVOID pvHostBuffer);

    BOOL WINAPI CopyVramToVram(IN ID3D11DeviceContext* pContext, IN PCVRAM_BLOB pDestBlob, IN PCVRAM_BLOB pSrcBlob);

    VOID WINAPI CleanupGpuVectoredHandler(VOID);

#ifdef __cplusplus
}
#endif


#endif // !_GPU_MANIPULATION_
