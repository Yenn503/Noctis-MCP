#pragma once
#include <Windows.h>
#include <immintrin.h> 

#include "Structures.h"
#include "Utilities.h"
#include "DebugMacros.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static DWORD WINAPI ComputeFnv1aCharacterHash(IN LPCVOID pvString, IN BOOL bIsUnicode)
{
    DWORD   dwFnvHash       = 0x811C9DC5,
            dwCharValue     = 0x00;
    LPCSTR  pszAnsiPtr      = (LPCSTR)pvString;
    LPCWSTR pwszUnicodePtr  = (LPCWSTR)pvString;
    
    if (bIsUnicode)
    {
        while (*pwszUnicodePtr)
        {
            dwCharValue = (DWORD)*pwszUnicodePtr;
            
            dwFnvHash ^= dwCharValue;
            dwFnvHash *= 0x01000193;
            
            pwszUnicodePtr++;
        }
    }
    else
    {
        while (*pszAnsiPtr)
        {
            dwCharValue = (DWORD)((BYTE)*pszAnsiPtr);
            
            dwFnvHash ^= dwCharValue;
            dwFnvHash *= 0x01000193;
            
            pszAnsiPtr++;
        }
    }
    
    return dwFnvHash;
}


DWORD WINAPI HashStringFnv1aCharA(IN LPCSTR pszString, IN BOOL bCaseInsensitive)
{
    LPSTR   pszLowerBuffer  = NULL;
    DWORD   dwLength        = 0x00,
            dwHash          = 0x00;

    if (!pszString) return 0x00;
    
    while (pszString[dwLength]) dwLength++;
    
    if (bCaseInsensitive)
    {
        if (!(pszLowerBuffer = (LPSTR)LocalAlloc(LPTR, dwLength + 1))) return 0;
        
        for (int i = 0; i < dwLength; i++)
        {
            if (pszString[i] >= 'A' && pszString[i] <= 'Z')
                pszLowerBuffer[i] = pszString[i] + 32;
            else
                pszLowerBuffer[i] = pszString[i];
        }
        
        dwHash = ComputeFnv1aCharacterHash((LPCVOID)pszLowerBuffer, FALSE);
        LocalFree(pszLowerBuffer);
        return dwHash;
    }
    
    return ComputeFnv1aCharacterHash((LPCVOID)pszString, FALSE);
}


DWORD WINAPI HashStringFnv1aCharW(IN LPCWSTR pwszString, IN BOOL bCaseInsensitive)
{
    LPWSTR  pwszLowerBuffer = NULL;
    DWORD   dwLength        = 0x00,
            dwHash          = 0x00;
    
    if (!pwszString) return 0x00;
    
    while (pwszString[dwLength]) dwLength++;
    
    if (bCaseInsensitive)
    {
        if (!(pwszLowerBuffer = (LPWSTR)LocalAlloc(LPTR, (dwLength + 1) * sizeof(WCHAR)))) return 0;
        
        for (int i = 0; i < dwLength; i++)
        {
            if (pwszString[i] >= L'A' && pwszString[i] <= L'Z')
                pwszLowerBuffer[i] = pwszString[i] + 32;
            else
                pwszLowerBuffer[i] = pwszString[i];
        }
        
        dwHash = ComputeFnv1aCharacterHash((LPCVOID)pwszLowerBuffer, TRUE);
        LocalFree(pwszLowerBuffer);
        return dwHash;
    }

    return ComputeFnv1aCharacterHash((LPCVOID)pwszString, TRUE);
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


BYTE GenRandomByte()
{
    unsigned short usRndValue = 0x00;

    for (int i = 0; i < 0x0A; i++)
    {
        if (_rdrand16_step(&usRndValue))
        {
            return (BYTE)(usRndValue & 0xFF);
        }
        _mm_pause();
    }

    return (BYTE)((rand() << 16) | rand());
}



// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


VOID RtlInitAnsiString(OUT PANSI_STRING DestinationString, IN LPSTR SourceString) 
{

    SIZE_T cbLength = 0x00;

    if (SourceString != NULL) {
        while (SourceString[cbLength] != '\0') 
        {
            cbLength++;
            if (cbLength >= MAXUSHORT) 
            {
                cbLength = MAXUSHORT - 1;
                break;
            }
        }
    }

    DestinationString->Buffer           = (PCHAR)SourceString;
    DestinationString->Length           = (USHORT)cbLength;
    DestinationString->MaximumLength    = (USHORT)(cbLength + 1);
}


VOID RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN LPWSTR SourceString)
{
    SIZE_T cbLength = 0x00;

    if (SourceString != NULL)
    {
        while (SourceString[cbLength] != L'\0')
        {
            cbLength++;
            if (cbLength >= (MAXUSHORT / sizeof(WCHAR)))
            {
                cbLength = (MAXUSHORT / sizeof(WCHAR)) - 1;
                break;
            }
        }
    }

    DestinationString->Buffer           = (PWCHAR)SourceString;
    DestinationString->Length           = (USHORT)(cbLength * sizeof(WCHAR));
    DestinationString->MaximumLength    = (USHORT)((cbLength + 1) * sizeof(WCHAR));
}

NTSTATUS RtlAnsiStringToUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCANSI_STRING SourceString, IN BOOLEAN AllocateDestinationString) 
{
    
    ULONG       cbUnicodeLength     = 0x00;
    ULONG       cbMaxUnicodeLength  = 0x00;
    PWCHAR      pwszBuffer          = NULL;

    if (SourceString == NULL || DestinationString == NULL) 
        return STATUS_INVALID_PARAMETER;
    
    cbUnicodeLength     = SourceString->Length * sizeof(WCHAR);
    cbMaxUnicodeLength  = cbUnicodeLength + sizeof(WCHAR); 
    
    if (AllocateDestinationString) 
    {
        if ((pwszBuffer = (PWCHAR)LocalAlloc(LPTR, cbMaxUnicodeLength)) == NULL) 
        {
			DBG_PRINT_A("[!] LocalAlloc Failed With Error: %lu", GetLastError());
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        DestinationString->Buffer           = pwszBuffer;
        DestinationString->MaximumLength    = (USHORT)cbMaxUnicodeLength;
    } 
    else 
    {
        if (DestinationString->MaximumLength < cbMaxUnicodeLength) 
            return STATUS_BUFFER_TOO_SMALL;
        
        pwszBuffer = DestinationString->Buffer;
    }
    
    for (ULONG i = 0; i < SourceString->Length; i++)
    {
        pwszBuffer[i] = (WCHAR)(UCHAR)SourceString->Buffer[i];
    }
    
    pwszBuffer[SourceString->Length]    = L'\0';
    DestinationString->Length           = (USHORT)cbUnicodeLength;
    
    return STATUS_SUCCESS;
}


NTSTATUS RtlFreeUnicodeString(IN OUT PUNICODE_STRING UnicodeString)
{
    if (UnicodeString == NULL) 
        return STATUS_INVALID_PARAMETER;

    if (UnicodeString->Buffer != NULL) 
    {
        LocalFree(UnicodeString->Buffer);
        UnicodeString->Buffer = NULL;
    }

    UnicodeString->Length           = 0x00;
    UnicodeString->MaximumLength    = 0x00;

    return STATUS_SUCCESS;
}



// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


BOOL GetResourceDataPayload(IN HMODULE hModule, IN WORD wResourceType, IN WORD wResourceId, OUT PVOID* ppResourceRawData, OUT PDWORD pdwResourceDataSize) 
{
    if (!ppResourceRawData || !pdwResourceDataSize)
        return FALSE;
    
    *ppResourceRawData      = NULL;
    *pdwResourceDataSize    = 0x00;
    
    ULONG_PTR               pBaseAddr       = (ULONG_PTR)hModule;
    PIMAGE_DOS_HEADER       pImgDosHdr      = (PIMAGE_DOS_HEADER)pBaseAddr;
    PIMAGE_NT_HEADERS       pImgNTHdr       = (PIMAGE_NT_HEADERS)(pBaseAddr + pImgDosHdr->e_lfanew);
    PIMAGE_OPTIONAL_HEADER  pImgOptionalHdr = &pImgNTHdr->OptionalHeader;
    PIMAGE_DATA_DIRECTORY   pDataDir        = &pImgOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    
    if (pDataDir->VirtualAddress == 0 || pDataDir->Size == 0) return FALSE;
    
    PIMAGE_RESOURCE_DIRECTORY       pResourceDir    = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress);
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry  = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir + 1);
    
    // Level 1: Find Resource Type
    DWORD dwTypeEntries = pResourceDir->NumberOfNamedEntries + pResourceDir->NumberOfIdEntries;
    
    for (DWORD i = 0; i < dwTypeEntries; i++) 
    {
        if (!pResourceEntry[i].DataIsDirectory)
            continue;
            
        // Check if this is the resource type we want 
        if (pResourceEntry[i].Id != wResourceType && wResourceType != 0)
            continue;
        
        // Level 2: Find Resource ID
        PIMAGE_RESOURCE_DIRECTORY       pResourceDir2   = (PIMAGE_RESOURCE_DIRECTORY) (pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry[i].OffsetToDirectory & 0x7FFFFFFF));
        PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir2 + 1);
        DWORD                           dwNameEntries   = pResourceDir2->NumberOfNamedEntries + pResourceDir2->NumberOfIdEntries;

        for (DWORD j = 0; j < dwNameEntries; j++) 
        {
            if (!pResourceEntry2[j].DataIsDirectory)
                continue;
                
            if (pResourceEntry2[j].Id != wResourceId)
                continue;
            
            PIMAGE_RESOURCE_DIRECTORY       pResourceDir3   = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry2[j].OffsetToDirectory & 0x7FFFFFFF));
            PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir3 + 1);
            
            if (pResourceDir3->NumberOfNamedEntries + pResourceDir3->NumberOfIdEntries > 0) 
            {
                PIMAGE_RESOURCE_DATA_ENTRY pResource = (PIMAGE_RESOURCE_DATA_ENTRY)(pBaseAddr + pDataDir->VirtualAddress + pResourceEntry3->OffsetToData);
                
                *ppResourceRawData      = (PVOID)(pBaseAddr + pResource->OffsetToData);
                *pdwResourceDataSize    = pResource->Size;

                return TRUE;
            }
        }
    }
    
    return FALSE;
}


/*
Possible Resource Types (wResourceType):

* RT_RCDATA (10): Generic binary data, often used for embedded files, payloads, or custom data
* RT_ICON (3): Individual icon images
* RT_GROUP_ICON (14): Icon group (collection of icons at different resolutions)
* RT_BITMAP (2): Bitmap images
* RT_STRING (6): String tables
* RT_VERSION (16): Version information
* RT_MANIFEST (24): Application manifest (XML)
* RT_DIALOG (5): Dialog box templates
* RT_MENU (4): Menu templates

*/