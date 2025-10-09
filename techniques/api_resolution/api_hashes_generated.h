// ================================================================
// NTDLL Functions
// ================================================================

#define HASH_NtAllocateVirtualMemory             0x6793C34C
#define HASH_NtWriteVirtualMemory                0x95F3A792
#define HASH_NtReadVirtualMemory                 0xC24062E3
#define HASH_NtProtectVirtualMemory              0x082962C8
#define HASH_NtFreeVirtualMemory                 0x471AA7E9
#define HASH_NtQueryVirtualMemory                0xE39D8E5D
#define HASH_NtCreateSection                     0xD02E20D0
#define HASH_NtMapViewOfSection                  0x231F196A
#define HASH_NtUnmapViewOfSection                0x595014AD
#define HASH_NtOpenSection                       0x17CFA34E
#define HASH_NtCreateThread                      0x376E0713
#define HASH_NtCreateThreadEx                    0xCB0C2130
#define HASH_NtOpenThread                        0xFB8A31D1
#define HASH_NtResumeThread                      0x2C7B3D30
#define HASH_NtSuspendThread                     0x50FEBD61
#define HASH_NtTerminateThread                   0xAC3C9DC8
#define HASH_NtQueueApcThread                    0xD4612238
#define HASH_NtOpenProcess                       0x5003C058
#define HASH_NtTerminateProcess                  0x1703AB2F
#define HASH_NtQuerySystemInformation            0xEE4F73A8
#define HASH_NtDelayExecution                    0x0A49084A
#define HASH_NtWaitForSingleObject               0x4C6DC63C
#define HASH_NtWaitForMultipleObjects            0x3D456539
#define HASH_NtSignalAndWaitForSingleObject      0x7BDD15CD
#define HASH_NtCreateKey                         0x5DBF4A84
#define HASH_NtOpenKey                           0x4BB73E02
#define HASH_NtSetValueKey                       0xF52D5359
#define HASH_NtQueryValueKey                     0xB4C18A83
#define HASH_NtDeleteKey                         0xF71037E3
#define HASH_NtDeleteValueKey                    0x1B63A200
#define HASH_NtEnumerateKey                      0x6A5E8ED6
#define HASH_NtCreateFile                        0x15A5ECDB
#define HASH_NtOpenFile                          0xC29C5019
#define HASH_NtReadFile                          0x2E979AE3
#define HASH_NtWriteFile                         0xD69326B2
#define HASH_NtClose                             0x8B8E133D
#define HASH_NtSetTimer                          0x461D2D14
#define HASH_NtCancelTimer                       0x053B70AE
#define HASH_NtCreateTimer                       0xCB60E3FC
#define HASH_NtTraceEvent                        0x1E2085F8
#define HASH_NtTraceControl                      0x7EB77B17
#define HASH_RtlRegisterWait                     0xE4DA1C11
#define HASH_RtlDeregisterWait                   0xC0D8989A
#define HASH_RtlCreateTimer                      0xA5DE7C4C
#define HASH_RtlDeleteTimer                      0xD7203D6B
#define HASH_RtlCreateTimerQueue                 0xF78FB211
#define HASH_RtlDeleteTimerQueue                 0x9561FE90

// ================================================================
// KERNEL32 Functions
// ================================================================

#define HASH_LoadLibraryA                        0x5FBFF0FB
#define HASH_LoadLibraryW                        0x5FBFF111
#define HASH_LoadLibraryExA                      0x4F803C78
#define HASH_LoadLibraryExW                      0x4F803C8E
#define HASH_GetProcAddress                      0xCF31BB1F
#define HASH_GetModuleHandleA                    0x5A153F58
#define HASH_GetModuleHandleW                    0x5A153F6E
#define HASH_GetModuleHandleExA                  0x34629615
#define HASH_GetModuleHandleExW                  0x3462962B
#define HASH_FreeLibrary                         0x30EECE3C
#define HASH_VirtualAlloc                        0x382C0F97
#define HASH_VirtualAllocEx                      0xF36E5AB4
#define HASH_VirtualProtect                      0x844FF18D
#define HASH_VirtualProtectEx                    0xD812922A
#define HASH_VirtualFree                         0x668FCF2E
#define HASH_VirtualFreeEx                       0x49C05C0B
#define HASH_VirtualQuery                        0x395269C2
#define HASH_VirtualQueryEx                      0xD793EB9F
#define HASH_HeapAlloc                           0x1FFD670E
#define HASH_HeapFree                            0x374893C5
#define HASH_HeapReAlloc                         0x1E31C125
#define HASH_GetProcessHeap                      0xC6580D02
#define HASH_HeapCreate                          0x24BD1D77
#define HASH_HeapDestroy                         0xEC0FB46D
#define HASH_CreateThread                        0x7F08F451
#define HASH_CreateRemoteThread                  0xAA30775D
#define HASH_CreateRemoteThreadEx                0xF82BCBFA
#define HASH_ResumeThread                        0x74162A6E
#define HASH_SuspendThread                       0x8BF7525F
#define HASH_TerminateThread                     0x87AE6A46
#define HASH_GetCurrentThread                    0xE03908C0
#define HASH_GetCurrentThreadId                  0xD29E428D
#define HASH_GetThreadContext                    0xEBA2CFC2
#define HASH_SetThreadContext                    0x7E20964E
#define HASH_CreateProcessA                      0xAEB52E19
#define HASH_CreateProcessW                      0xAEB52E2F
#define HASH_OpenProcess                         0x7136FDD6
#define HASH_GetCurrentProcess                   0xCA8D7527
#define HASH_GetCurrentProcessId                 0xA3BF64B4
#define HASH_TerminateProcess                    0x60AF076D
#define HASH_Sleep                               0x0E19E5FE
#define HASH_SleepEx                             0xFC2B66DB
#define HASH_WaitForSingleObject                 0xECCDA1BA
#define HASH_WaitForSingleObjectEx               0x56BD0197
#define HASH_WaitForMultipleObjects              0x6DA077F7
#define HASH_CreateThreadpool                    0x085C062B
#define HASH_CreateThreadpoolTimer               0x0B49144C
#define HASH_SetThreadpoolTimer                  0x3B944C24
#define HASH_CloseThreadpoolTimer                0xE85797AE
#define HASH_CreateThreadpoolWork                0x462ABFEE
#define HASH_SubmitThreadpoolWork                0x3E07D80E
#define HASH_CloseThreadpoolWork                 0x6BE55F10
#define HASH_CreateFileA                         0xEB96C5FA
#define HASH_CreateFileW                         0xEB96C610
#define HASH_ReadFile                            0x71019921
#define HASH_WriteFile                           0x663CECB0
#define HASH_CloseHandle                         0x3870CA07
#define HASH_GetFileSize                         0x7891C520
#define HASH_SetFilePointer                      0x53EF6BF2
#define HASH_GetStdHandle                        0xF178843C
#define HASH_WriteConsoleA                       0xEE4211A4
#define HASH_WriteConsoleW                       0xEE4211BA
#define HASH_ReadConsoleA                        0xEB798E95
#define HASH_ReadConsoleW                        0xEB798EAB

// ================================================================
// ADVAPI32 Functions
// ================================================================

#define HASH_RegCreateKeyA                       0x369A66A1
#define HASH_RegCreateKeyW                       0x369A66B7
#define HASH_RegCreateKeyExA                     0x46CEB39E
#define HASH_RegCreateKeyExW                     0x46CEB3B4
#define HASH_RegOpenKeyA                         0xA2AE42DF
#define HASH_RegOpenKeyW                         0xA2AE42F5
#define HASH_RegOpenKeyExA                       0x074A975C
#define HASH_RegOpenKeyExW                       0x074A9772
#define HASH_RegSetValueA                        0xEFD3E2ED
#define HASH_RegSetValueW                        0xEFD3E303
#define HASH_RegSetValueExA                      0x345872EA
#define HASH_RegSetValueExW                      0x34587300
#define HASH_RegQueryValueA                      0x70EFAE97
#define HASH_RegQueryValueW                      0x70EFAEAD
#define HASH_RegQueryValueExA                    0x6B95D114
#define HASH_RegQueryValueExW                    0x6B95D12A
#define HASH_RegDeleteKeyA                       0xFA08FFE0
#define HASH_RegDeleteKeyW                       0xFA08FFF6
#define HASH_RegDeleteValueA                     0xB9A29E54
#define HASH_RegDeleteValueW                     0xB9A29E6A
#define HASH_RegCloseKey                         0x736B3702
#define HASH_OpenProcessToken                    0xC57BD097
#define HASH_OpenThreadToken                     0xD7B785F0
#define HASH_AdjustTokenPrivileges               0xCE4CD9CB
#define HASH_LookupPrivilegeValueA               0xBBAE6E84
#define HASH_LookupPrivilegeValueW               0xBBAE6E9A
#define HASH_DuplicateToken                      0xCA0C2181
#define HASH_DuplicateTokenEx                    0x7D9A8F1E
#define HASH_SetThreadToken                      0x575B17CA

// ================================================================
// AMSI/Security Functions
// ================================================================

#define HASH_AmsiScanBuffer                      0x29FCD18E
#define HASH_AmsiScanString                      0x51990E2B
#define HASH_AmsiInitialize                      0x8C6AB501
#define HASH_AmsiUninitialize                    0x91646C04
#define HASH_AddVectoredExceptionHandler         0x37D1F0D7
#define HASH_RemoveVectoredExceptionHandler      0xC88FFB7C
#define HASH_SetUnhandledExceptionFilter         0x252C3659

// ================================================================
// Module Names
// ================================================================

#define HASH_ntdll_dll                           0x22D3B5ED
#define HASH_kernel32_dll                        0x7040EE75
#define HASH_kernelbase_dll                      0xA721952B
#define HASH_advapi32_dll                        0x67208A49
#define HASH_user32_dll                          0x5A6BD3F3
#define HASH_gdi32_dll                           0x2722E788
#define HASH_win32u_dll                          0x34C755B7
#define HASH_amsi_dll                            0xDAF90FD9
#define HASH_bcrypt_dll                          0x730076C3
#define HASH_crypt32_dll                         0x12956686
#define HASH_ws2_32_dll                          0x9AD10B0F
#define HASH_wininet_dll                         0x8DBD9C6D
#define HASH_winhttp_dll                         0x920E337D

// ================================================================
// Special Hashes
// ================================================================

#define HASH_text_section                        0x0B80C0D8
#define HASH_data_section                        0x0B77E92D
#define HASH_rdata_section                       0x7B73BCFF
