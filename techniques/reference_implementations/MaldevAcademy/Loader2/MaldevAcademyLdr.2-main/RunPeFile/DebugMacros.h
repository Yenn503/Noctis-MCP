#pragma once
#ifndef DEBUG_MACROS_H
#define DEBUG_MACROS_H
#include <Windows.h>


/*
	This is defined by the compiler automatically in 'Debug' mode. However, one can define it manually in 'Release' mode to enable debug prints.
*/
//\
#define _DEBUG


#ifdef _DEBUG

#ifdef __cplusplus
extern "C" {
#endif

	void DbgPrintA(const char* file, int line, const char* fmt, ...);
	void DbgPrintW(const char* file, int line, const wchar_t* fmt, ...);

#ifdef __cplusplus
}
#endif

#define DBG_PRINT_A(fmt, ...) DbgPrintA(__FILE__, __LINE__, fmt, __VA_ARGS__)
#define DBG_PRINT_W(fmt, ...) DbgPrintW(__FILE__, __LINE__, fmt, __VA_ARGS__)

#else // !_DEBUG

#define DBG_PRINT_A(fmt, ...) do { if(0) { (void)(fmt); } } while(0)
#define DBG_PRINT_W(fmt, ...) do { if(0) { (void)(fmt); } } while(0)

#endif // _DEBUG




#endif // DEBUG_MACROS_H
