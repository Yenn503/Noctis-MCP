// Reference code for Noctis-MCP AI intelligence system

#include <Windows.h>
#include <stdio.h>

#include "Extract.h"


static BOOL ReadFileFromDiskA(IN LPCSTR pszFilePath, OUT PBYTE* ppbBuffer, OUT PDWORD pdwFileSize)
{
    HANDLE  hFile                   = INVALID_HANDLE_VALUE;
    DWORD   dwFileSize              = 0x00,
            dwBytesRead             = 0x00;
    PBYTE   pbBuffer                = NULL;
    BOOL    bOperationSuccess       = FALSE;
    
    if (!pszFilePath || !ppbBuffer || !pdwFileSize) return FALSE;
    
    *ppbBuffer      = NULL;
    *pdwFileSize    = 0x00;
    
    hFile = CreateFileA(
        pszFilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) 
    {
        printf("[!] CreateFileA Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }
    
    if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
        printf("[!] GetFileSize Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }
    
    if (dwFileSize == 0x00) {
        printf("[!] File Is Empty\n");
        goto _END_OF_FUNC;
    }
    
    if (!(pbBuffer = (PBYTE)LocalAlloc(LPTR, dwFileSize))) {
        printf("[!] LocalAlloc Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }
    
    if (!ReadFile(hFile, pbBuffer, dwFileSize, &dwBytesRead, NULL)) {
        printf("[!] ReadFile Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }
    
    if (dwBytesRead != dwFileSize) {
        printf("[!] Partial Read: Expected %lu Got %lu\n", dwFileSize, dwBytesRead);
        goto _END_OF_FUNC;
    }
    
    *ppbBuffer          = pbBuffer;
    *pdwFileSize        = dwFileSize;
    bOperationSuccess   = TRUE;

_END_OF_FUNC:
    if (!bOperationSuccess && pbBuffer) 
        LocalFree(pbBuffer);
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    return bOperationSuccess;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL WriteFileToDiskA(IN LPCSTR pszFilePath, IN PBYTE pbBuffer, IN DWORD dwBufferSize)
{
    HANDLE  hFile                   = INVALID_HANDLE_VALUE;
    DWORD   dwBytesWritten          = 0x00;
    BOOL    bOperationSuccess       = FALSE;
    
    if (!pszFilePath || !pbBuffer || !dwBufferSize) return FALSE;
    
    hFile = CreateFileA(
        pszFilePath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) 
    {
        printf("[!] CreateFileA Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }
    
    if (!WriteFile(hFile, pbBuffer, dwBufferSize, &dwBytesWritten, NULL)) {
        printf("[!] WriteFile Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }
    
    if (dwBytesWritten != dwBufferSize) {
        printf("[!] Partial Write: Expected %lu Wrote %lu\n", dwBufferSize, dwBytesWritten);
        goto _END_OF_FUNC;
    }
    
    bOperationSuccess = TRUE;

_END_OF_FUNC:
    if (hFile != INVALID_HANDLE_VALUE) 
        CloseHandle(hFile);
    if (!bOperationSuccess) 
        DeleteFileA(pszFilePath);
    return bOperationSuccess;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ProcessMultiPartFiles(IN LPCSTR pszBasePattern, OUT PBYTE* ppbCombinedData, OUT PDWORD pdwCombinedSize)
{
    CHAR        szPartFile[MAX_PATH]       = { 0 };
    CHAR        szBaseName[MAX_PATH]       = { 0 };
    CHAR        szDirectory[MAX_PATH]      = { 0 };
    CHAR        szFileName[MAX_PATH]       = { 0 };
    CHAR        szExtension[MAX_PATH]      = { 0 };
    LPSTR       pszLastSlash               = NULL;
    LPSTR       pszPartPos                 = NULL;
    LPSTR       pszExtPos                  = NULL;
    DWORD       dwPartNumber               = 0x01;
    DWORD       dwTotalSize                = 0x00;
    DWORD       dwCurrentOffset            = 0x00;
    DWORD       dwPartSize                 = 0x00;
    DWORD       dwExtractedSize            = 0x00;
    PBYTE       pbPartData                 = NULL;
    PBYTE       pbExtractedData            = NULL;
    PBYTE       pbCombinedData             = NULL;
    PBYTE       pbTempBuffer               = NULL;
    BOOL        bMoreParts                 = TRUE;
    
    if (!pszBasePattern || !ppbCombinedData || !pdwCombinedSize) return FALSE;
    
    *ppbCombinedData = NULL;
    *pdwCombinedSize = 0x00;
    
    strcpy_s(szBaseName, MAX_PATH, pszBasePattern);
    pszLastSlash = strrchr(szBaseName, '\\');
    if (!pszLastSlash) {
        pszLastSlash = strrchr(szBaseName, '/');
    }
    
    if (pszLastSlash) 
    {
        *pszLastSlash = '\0';
        strcpy_s(szDirectory, MAX_PATH, szBaseName);
        strcpy_s(szFileName, MAX_PATH, pszLastSlash + 1);
    } 
    else 
    {
        szDirectory[0] = '\0';
        strcpy_s(szFileName, MAX_PATH, szBaseName);
    }
    
    pszPartPos = strstr(szFileName, "_part");
    
    if (!pszPartPos) {
        printf("[!] Invalid Multi-Part Pattern: Missing '_part' Marker\n");
        return FALSE;
    }
    
    pszExtPos = pszPartPos + 7;
    if (strlen(pszExtPos) > 0) 
    {
        strcpy_s(szExtension, MAX_PATH, pszExtPos);
    }
    *pszPartPos = '\0';
    
    dwPartNumber = 0x01;
    while (bMoreParts && dwPartNumber <= 99) // Max 99 parts
    {
        if (szDirectory[0] != '\0') 
            sprintf_s(szPartFile, MAX_PATH, "%s\\%s_part%02lu%s", szDirectory, szFileName, dwPartNumber, szExtension);
        else 
            sprintf_s(szPartFile, MAX_PATH, "%s_part%02lu%s", szFileName, dwPartNumber, szExtension);
        
        if (!ReadFileFromDiskA(szPartFile, &pbPartData, &dwPartSize)) 
        {
            if (dwPartNumber == 0x01) {
                printf("[!] Failed To Read First Part File: %s\n", szPartFile);
                return FALSE;
            }
            bMoreParts = FALSE;
            break;
        }
        
        printf("[*] Processing Part %02lu: %s\n", dwPartNumber, szPartFile);

        // Extract PE data from this PNG part
        if (!ExtractPeFromPngAligned(pbPartData, dwPartSize, &pbExtractedData, &dwExtractedSize)) {
            printf("[!] Failed To Extract Data From Part %02lu\n", dwPartNumber);
            LocalFree(pbPartData);
            return FALSE;
        }

        printf("[+] Extracted %lu bytes from Part %02lu\n", dwExtractedSize, dwPartNumber);

        dwTotalSize += dwExtractedSize;
        LocalFree(pbPartData);
        LocalFree(pbExtractedData);
        pbPartData = NULL;
        pbExtractedData = NULL;
        dwPartNumber++;
    }
    
    if (dwTotalSize == 0x00) {
        printf("[!] No Valid Part Files Found\n");
        return FALSE;
    }
    
    printf("[+] Total Parts Found: %lu\n", dwPartNumber - 1);
    printf("[+] Total Combined Size: %lu bytes\n", dwTotalSize);
    
    if (!(pbCombinedData = (PBYTE)LocalAlloc(LPTR, dwTotalSize))) {
        printf("[!] LocalAlloc Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }
    
    dwCurrentOffset = 0x00;
    for (DWORD i = 0x01; i < dwPartNumber; i++)
    {
        if (szDirectory[0] != '\0') 
            sprintf_s(szPartFile, MAX_PATH, "%s\\%s_part%02lu%s", szDirectory, szFileName, i, szExtension);
        else 
            sprintf_s(szPartFile, MAX_PATH, "%s_part%02lu%s", szFileName, i, szExtension);
        
        if (!ReadFileFromDiskA(szPartFile, &pbPartData, &dwPartSize)) {
            printf("[!] Failed To Read Part %02lu On Second Pass\n", i);
            LocalFree(pbCombinedData);
            return FALSE;
        }
        
        if (!ExtractPeFromPngAligned(pbPartData, dwPartSize, &pbExtractedData, &dwExtractedSize)) {
            printf("[!] Failed To Extract Data From Part %02lu On Second Pass\n", i);
            LocalFree(pbPartData);
            LocalFree(pbCombinedData);
            return FALSE;
        }

        RtlCopyMemory(pbCombinedData + dwCurrentOffset, pbExtractedData, dwExtractedSize);
        dwCurrentOffset += dwExtractedSize;

        LocalFree(pbPartData);
        LocalFree(pbExtractedData);
        pbPartData = NULL;
        pbExtractedData = NULL;
    }
    
    *ppbCombinedData = pbCombinedData;
    *pdwCombinedSize = dwTotalSize;
    
    return TRUE;
}
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ParseCommandLineArgs(IN int argc, IN char* argv[], OUT LPSTR* ppszInputFile, OUT LPSTR* ppszOutputFile)
{
    INT     iArgIndex               = 0x00;
    BOOL    bInputFound             = FALSE,
            bOutputFound            = FALSE,
            bIsMultiPart            = FALSE;
    LPSTR   pszInputFile            = NULL,
            pszOutputFile           = NULL;
    DWORD   dwPathLength            = 0x00;
    CHAR    szCurrentDir[MAX_PATH]  = { 0 };
    CHAR    szFullPath[MAX_PATH]    = { 0 };
    
    if (argc < 2 || !argv || !ppszInputFile || !ppszOutputFile) return FALSE;
    
    *ppszInputFile  = NULL;
    *ppszOutputFile = NULL;
    
    if (!GetCurrentDirectoryA(MAX_PATH, szCurrentDir)) {
        printf("[!] GetCurrentDirectoryA Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }
    
    for (iArgIndex = 1; iArgIndex < argc; iArgIndex++)
    {
        if (!argv[iArgIndex]) {
            continue;
        }
        
        if (strcmp(argv[iArgIndex], "--i") == 0)
        {
            if (iArgIndex + 1 >= argc) {
                printf("[!] Missing Input File After --i Flag\n");
                return FALSE;
            }
            
            iArgIndex++;
            pszInputFile = argv[iArgIndex];
            bInputFound = TRUE;
        }
        else if (strcmp(argv[iArgIndex], "--o") == 0)
        {
            if (iArgIndex + 1 >= argc) {
                printf("[!] Missing Output File After --o Flag\n");
                return FALSE;
            }
            
            iArgIndex++;
            pszOutputFile = argv[iArgIndex];
            bOutputFound = TRUE;
        }
        else if (!bInputFound && !bOutputFound)
        {
            pszInputFile = argv[iArgIndex];
            bInputFound = TRUE;
        }
        else if (bInputFound && !bOutputFound)
        {
            pszOutputFile = argv[iArgIndex];
            bOutputFound = TRUE;
        }
    }
    
    if (!bInputFound || !bOutputFound) {
        printf("[!] Both Input And Output Files Required\n");
        printf("[*] Usage: %s --i <input_file> --o <output_file>\n", argv[0]);
        printf("[*] Or:    %s <input_file> <output_file>\n", argv[0]);
        printf("[*] Multi-part: %s --i file_part01.ext --o output.bin\n", argv[0]);
        return FALSE;
    }
    
    if (strstr(pszInputFile, "_part") != NULL) {
        bIsMultiPart = TRUE;
        printf("[*] Multi-Part File Pattern Detected\n");
    }
    
    if (strchr(pszInputFile, '\\') == NULL && strchr(pszInputFile, '/') == NULL)
    {
        sprintf_s(szFullPath, MAX_PATH, "%s\\%s", szCurrentDir, pszInputFile);
        dwPathLength = (DWORD)strlen(szFullPath) + 1;
        
        if (!(*ppszInputFile = (LPSTR)LocalAlloc(LPTR, dwPathLength))) {
            printf("[!] LocalAlloc Failed With Error: %lu\n", GetLastError());
            return FALSE;
        }
        
        strcpy_s(*ppszInputFile, dwPathLength, szFullPath);
    }
    else
    {
        dwPathLength = (DWORD)strlen(pszInputFile) + 1;
        
        if (!(*ppszInputFile = (LPSTR)LocalAlloc(LPTR, dwPathLength))) {
            printf("[!] LocalAlloc Failed With Error: %lu\n", GetLastError());
            return FALSE;
        }
        
        strcpy_s(*ppszInputFile, dwPathLength, pszInputFile);
    }
    
    if (strchr(pszOutputFile, '\\') == NULL && strchr(pszOutputFile, '/') == NULL)
    {
        sprintf_s(szFullPath, MAX_PATH, "%s\\%s", szCurrentDir, pszOutputFile);
        dwPathLength = (DWORD)strlen(szFullPath) + 1;
        
        if (!(*ppszOutputFile = (LPSTR)LocalAlloc(LPTR, dwPathLength))) {
            printf("[!] LocalAlloc Failed With Error: %lu\n", GetLastError());
            if (*ppszInputFile) {
                LocalFree(*ppszInputFile);
                *ppszInputFile = NULL;
            }
            return FALSE;
        }
        
        strcpy_s(*ppszOutputFile, dwPathLength, szFullPath);
    }
    else
    {
        dwPathLength = (DWORD)strlen(pszOutputFile) + 1;
        
        if (!(*ppszOutputFile = (LPSTR)LocalAlloc(LPTR, dwPathLength))) {
            printf("[!] LocalAlloc Failed With Error: %lu\n", GetLastError());
            if (*ppszInputFile) {
                LocalFree(*ppszInputFile);
                *ppszInputFile = NULL;
            }
            return FALSE;
        }
        
        strcpy_s(*ppszOutputFile, dwPathLength, pszOutputFile);
    }
    
    return TRUE;
}
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

int main(int argc, char* argv[])
{
    LPSTR   pszInputFile    = NULL;
    LPSTR   pszOutputFile   = NULL;
    PBYTE   pbInputData     = NULL;
    PBYTE   pbOutputData    = NULL;
    DWORD   dwInputSize     = 0x00;
    DWORD   dwOutputSize    = 0x00;
    INT     iResult         = -1;
    
    if (!ParseCommandLineArgs(argc, argv, &pszInputFile, &pszOutputFile)) {
        return -1;
    }
    
    printf("[*] Input File:  %s\n", pszInputFile);
    printf("[*] Output File: %s\n", pszOutputFile);
    
    if (strstr(pszInputFile, "_part") != NULL) 
    {
        printf("[*] Multi-Part Pattern Detected, Processing Parts...\n");
        
        if (!ProcessMultiPartFiles(pszInputFile, &pbOutputData, &dwOutputSize)) {
            printf("[!] Failed To Process Multi-Part Files\n");
            goto _END_OF_FUNC;
        }
        
        printf("[+] Total Extracted Size: %lu Bytes\n", dwOutputSize);
    }
    else 
    {
        if (!ReadFileFromDiskA(pszInputFile, &pbInputData, &dwInputSize)) {
            printf("[!] Failed To Read Input File\n");
            goto _END_OF_FUNC;
        }
        
        printf("[+] Input PNG Size: %lu Bytes\n", dwInputSize);
        
        if (!ExtractPeFromPngAligned(pbInputData, dwInputSize, &pbOutputData, &dwOutputSize)) {
            printf("[!] ExtractPeFromPngAligned Failed\n");
            goto _END_OF_FUNC;
        }
        
        printf("[+] Extracted PE Size: %lu Bytes\n", dwOutputSize);
    }
    
    if (!WriteFileToDiskA(pszOutputFile, pbOutputData, dwOutputSize)) {
        printf("[!] Failed To Write Output File\n");
        goto _END_OF_FUNC;
    }
    
    printf("[+] Successfully Wrote %lu Bytes To %s\n", dwOutputSize, pszOutputFile);
    
    iResult = 0;
    
_END_OF_FUNC:
    if (pbInputData)
        LocalFree(pbInputData);
    if (pbOutputData)
        LocalFree(pbOutputData);
    if (pszInputFile)
        LocalFree(pszInputFile);
    if (pszOutputFile)
        LocalFree(pszOutputFile);
    
    return iResult;
}