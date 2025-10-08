#pragma once
#ifndef UNPACK_AND_HIDE_H_
#define UNPACK_AND_HIDE_H_

#include <Windows.h>


#define FAILED_EXECUTION    ((DWORD)0xFFFFFFFF)


DWORD WINAPI ExecutePePayload(IN ULONG_PTR uRawPeAddress, IN SIZE_T cbPeSize);



#endif // !UNPACK_AND_HIDE_H_
