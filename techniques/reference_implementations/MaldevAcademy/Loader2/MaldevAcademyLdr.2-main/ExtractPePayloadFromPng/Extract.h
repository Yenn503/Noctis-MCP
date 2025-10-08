#pragma once
#ifndef EXTRACT_H_
#define EXTRACT_H_

#include <Windows.h>


BOOL ExtractPeFromPngAligned(IN PBYTE pbPngData, IN DWORD dwPngLength, OUT PBYTE* ppbOutputPe, OUT PDWORD pdwOutputPeLength);

#endif // !EXTRACT_H_
