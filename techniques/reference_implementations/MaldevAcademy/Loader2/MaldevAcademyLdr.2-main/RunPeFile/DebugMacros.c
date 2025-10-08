#include <Windows.h>

#include "DebugMacros.h"


#ifdef _DEBUG

__declspec(noinline) LPCSTR ExtractFileName(IN LPCSTR lpszFilePath)
{
    LPCSTR lpszFileName = lpszFilePath;

    for (LPCSTR lpch = lpszFilePath; *lpch; ++lpch)
    {
        if (*lpch == '\\' || *lpch == '/')
            lpszFileName = lpch + 1;
    }

    return lpszFileName;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define DBG_STR_MAX_LEN     0x1000
#define GET_FILENAME(STR)   ExtractFileName(STR)

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

__declspec(noinline) void DbgPrintA(const char* file, int line, const char* fmt, ...)
{
    HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    CHAR* szBuffer = (CHAR*)LocalAlloc(LPTR, DBG_STR_MAX_LEN);
    CHAR* szFinal = (CHAR*)LocalAlloc(LPTR, DBG_STR_MAX_LEN);

    if (!szBuffer || !szFinal)
    {
        if (szBuffer) LocalFree(szBuffer);
        if (szFinal) LocalFree(szFinal);
        return;
    }

    va_list args;
    va_start(args, fmt);
    int nLength = wvsprintfA(szBuffer, fmt, args);
    va_end(args);

    int nFinalLen = wsprintfA(szFinal, "%s [%s:%d]\n", szBuffer, ExtractFileName(file), line);

    OutputDebugStringA(szFinal);

    DWORD dwWritten = 0;
    DWORD dwMode = 0;

    if (GetConsoleMode(hOutput, &dwMode))
        WriteConsoleA(hOutput, szFinal, nFinalLen, &dwWritten, NULL);
    else
        WriteFile(hOutput, szFinal, nFinalLen, &dwWritten, NULL);

    LocalFree(szBuffer);
    LocalFree(szFinal);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

__declspec(noinline) void DbgPrintW(const char* file, int line, const wchar_t* fmt, ...)
{
    HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    WCHAR* szBuffer = (WCHAR*)LocalAlloc(LPTR, DBG_STR_MAX_LEN * sizeof(WCHAR));
    WCHAR* szFinal = (WCHAR*)LocalAlloc(LPTR, DBG_STR_MAX_LEN * sizeof(WCHAR));

    if (!szBuffer || !szFinal)
    {
        if (szBuffer) LocalFree(szBuffer);
        if (szFinal) LocalFree(szFinal);
        return;
    }

    va_list args;
    va_start(args, fmt);
    int nLength = wvsprintfW(szBuffer, fmt, args);
    va_end(args);

    int nFinalLen = wsprintfW(szFinal, L"%s [%S:%d]\n", szBuffer, ExtractFileName(file), line);

    OutputDebugStringW(szFinal);

    DWORD dwWritten = 0;
    DWORD dwMode = 0;
    if (GetConsoleMode(hOutput, &dwMode))
        WriteConsoleW(hOutput, szFinal, nFinalLen, &dwWritten, NULL);
    else
        WriteFile(hOutput, szFinal, nFinalLen * sizeof(WCHAR), &dwWritten, NULL);

    LocalFree(szBuffer);
    LocalFree(szFinal);
}

#endif // _DEBUG
