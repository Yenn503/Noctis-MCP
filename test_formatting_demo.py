#!/usr/bin/env python3
"""
Demo script to showcase the improved MCP tool output formatting
"""

import sys
sys.path.insert(0, '/workspace')

from noctis_mcp_client.noctis_mcp import (
    _format_search_results,
    _format_technique_analysis,
    _format_code_generation,
    _format_technique_comparison,
    _format_rag_stats,
    _format_general,
    _format_error
)

# Sample data for demonstrations
def demo_search_results():
    data = {
        'results': [
            {
                'source': 'github',
                'title': 'Advanced Process Injection with Direct Syscalls',
                'url': 'https://github.com/example/syscall-injection',
                'relevance_score': 0.92,
                'content': 'This repository demonstrates advanced process injection techniques using direct system calls to bypass EDR hooks. The implementation includes NTDLL unhooking, Heaven\'s Gate for WoW64 processes, and custom syscall stubs generated at runtime. Tested against Windows Defender, CrowdStrike Falcon, and SentinelOne with high success rates.'
            },
            {
                'source': 'arxiv',
                'title': 'Evasion Techniques Against Modern Endpoint Detection Systems',
                'url': 'https://arxiv.org/abs/12345',
                'relevance_score': 0.87,
                'content': 'This paper presents a comprehensive analysis of evasion techniques effective against modern EDR solutions. We demonstrate that direct system calls, combined with API hashing and string encryption, can significantly reduce detection rates.'
            },
            {
                'source': 'knowledge_base',
                'title': 'Direct System Calls - Comprehensive Guide',
                'url': '',
                'relevance_score': 0.85,
                'content': 'Direct system calls allow bypassing user-mode hooks placed by security software. By calling kernel functions directly, malware can evade detection mechanisms that monitor API calls through standard Windows APIs.'
            }
        ],
        'total_results': 3
    }
    
    print("\n" + "="*80)
    print("DEMO 1: SEARCH RESULTS FORMATTING")
    print("="*80)
    print(_format_search_results(data))


def demo_technique_analysis():
    data = {
        'technique_id': 'syscalls',
        'name': 'Direct System Calls',
        'conceptual_knowledge': 'Direct system calls enable malware to bypass user-mode API hooks by directly invoking kernel functions. This technique is highly effective against EDR solutions that rely on hooking Windows APIs like NtAllocateVirtualMemory or NtCreateThread. By resolving syscall numbers at runtime and executing them directly, the malware can perform sensitive operations without triggering hooks.',
        'github_implementations': [
            {
                'repo': 'SysWhispers3',
                'url': 'https://github.com/klezVirus/SysWhispers3',
                'stars': 1247,
                'description': 'Red Team tool for generating direct syscall stubs with various evasion features including randomization and egg hunting'
            },
            {
                'repo': 'InlineWhispers',
                'url': 'https://github.com/outflanknl/InlineWhispers',
                'stars': 892,
                'description': 'Tool for integrating direct syscalls inline within your malware code'
            }
        ],
        'research_papers': [
            {
                'title': 'Bypassing User-Mode Hooks: A Study of Direct Syscall Implementations',
                'url': 'https://arxiv.org/example',
                'year': '2023',
                'summary': 'Comprehensive analysis of direct syscall techniques and their effectiveness against commercial EDR products'
            }
        ],
        'blog_posts': [
            {
                'title': 'Direct Syscalls: A Beginner\'s Guide',
                'url': 'https://blog.example.com/syscalls',
                'author': 'John Doe'
            }
        ],
        'effectiveness_vs_av': {
            'Windows Defender': 8.5,
            'CrowdStrike Falcon': 7.8,
            'SentinelOne': 8.2,
            'Carbon Black': 7.5,
            'Microsoft Defender ATP': 8.0
        },
        'recommended_combinations': [
            'API Hashing + Syscalls',
            'String Encryption + Syscalls',
            'NTDLL Unhooking + Syscalls'
        ],
        'opsec_considerations': 'While direct syscalls are effective, they can be detected through syscall monitoring and behavioral analysis. Consider combining with other evasion techniques and implementing anti-analysis checks.'
    }
    
    print("\n" + "="*80)
    print("DEMO 2: TECHNIQUE ANALYSIS FORMATTING")
    print("="*80)
    print(_format_technique_analysis(data))


def demo_code_generation():
    data = {
        'target_av': 'CrowdStrike Falcon',
        'target_os': 'Windows 10/11',
        'architecture': 'x64',
        'techniques_used': [
            'Direct System Calls',
            'Process Injection (Remote Thread)',
            'NTDLL Unhooking',
            'API Hashing',
            'String Encryption (AES-256)'
        ],
        'opsec_score': 8.7,
        'files_saved': {
            'source_file': '/workspace/output/payload.c',
            'header_file': '/workspace/output/payload.h',
            'output_directory': '/workspace/output'
        },
        'mitre_ttps': [
            'T1055.002 - Process Injection: Portable Executable Injection',
            'T1106 - Native API',
            'T1027 - Obfuscated Files or Information',
            'T1140 - Deobfuscate/Decode Files or Information'
        ],
        'dependencies': [
            'Windows.h',
            'winnt.h',
            'winternl.h',
            'ntstatus.h',
            'wincrypt.h',
            'stdio.h',
            'stdlib.h',
            'string.h'
        ],
        'rag_intelligence_used': {
            'github_patterns': 12,
            'research_insights': 5,
            'blog_recommendations': 3
        },
        'warnings': [
            'Code uses advanced evasion techniques - ensure proper authorization before use',
            'Some techniques may trigger behavioral analysis on sophisticated EDR platforms',
            'Test in isolated environment before operational use'
        ],
        'source_code': '''#include <windows.h>
#include <winternl.h>
#include "payload.h"

// Direct syscall stub for NtAllocateVirtualMemory
NTSTATUS NtAllocateVirtualMemory_Syscall(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    // Syscall implementation
    __asm {
        mov r10, rcx
        mov eax, 0x18
        syscall
        ret
    }
}

// Main injection function
BOOL InjectShellcode(HANDLE hProcess, LPVOID shellcode, SIZE_T size) {
    LPVOID remoteBuffer = NULL;
    SIZE_T bufferSize = size;
    
    // Allocate memory using direct syscall
    NTSTATUS status = NtAllocateVirtualMemory_Syscall(
        hProcess,
        &remoteBuffer,
        0,
        &bufferSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    
    // Write shellcode and execute
    // ... rest of implementation
    
    return TRUE;
}'''
    }
    
    print("\n" + "="*80)
    print("DEMO 3: CODE GENERATION FORMATTING")
    print("="*80)
    print(_format_code_generation(data))


def demo_technique_comparison():
    data = {
        'comparison_table': {
            'Direct Syscalls': {
                'effectiveness': 8.5,
                'stealth': 9.0,
                'complexity': 7.0,
                'stability': 8.0
            },
            'API Hashing': {
                'effectiveness': 7.0,
                'stealth': 8.0,
                'complexity': 5.0,
                'stability': 9.0
            },
            'Process Hollowing': {
                'effectiveness': 7.5,
                'stealth': 6.5,
                'complexity': 8.0,
                'stability': 7.0
            }
        },
        'winner_by_criteria': {
            'effectiveness': 'Direct Syscalls',
            'stealth': 'Direct Syscalls',
            'complexity': 'API Hashing',
            'stability': 'API Hashing'
        },
        'recommendation': 'For maximum effectiveness against CrowdStrike Falcon, use Direct Syscalls combined with API Hashing. While syscalls have higher complexity, they provide superior stealth and effectiveness. Consider combining techniques for a layered defense approach.'
    }
    
    print("\n" + "="*80)
    print("DEMO 4: TECHNIQUE COMPARISON FORMATTING")
    print("="*80)
    print(_format_technique_comparison(data))


def demo_rag_stats():
    data = {
        'enabled': True,
        'embedding_model': 'sentence-transformers/all-MiniLM-L6-v2',
        'vector_db': 'ChromaDB',
        'knowledge_base': 247,
        'github_repos': 156,
        'research_papers': 89,
        'blog_posts': 45,
        'detection_intel': 23
    }
    
    print("\n" + "="*80)
    print("DEMO 5: RAG STATS FORMATTING")
    print("="*80)
    print(_format_rag_stats(data))


def demo_general_response():
    data = {
        'success': True,
        'operation': 'compile_code',
        'binary_path': '/workspace/output/payload.exe',
        'size_bytes': 45056,
        'compilation_time': 2.34,
        'warnings': [
            'Function pointer cast may cause alignment issues',
            'Unused variable detected: temp_buffer'
        ],
        'optimizations_applied': {
            'string_encryption': True,
            'api_hashing': True,
            'dead_code_elimination': True
        }
    }
    
    print("\n" + "="*80)
    print("DEMO 6: GENERAL RESPONSE FORMATTING")
    print("="*80)
    print(_format_general(data))


def demo_error():
    error_msg = "Failed to connect to Noctis API server at http://localhost:8888. Please ensure the server is running by executing: python server/noctis_server.py --port 8888"
    
    print("\n" + "="*80)
    print("DEMO 7: ERROR MESSAGE FORMATTING")
    print("="*80)
    print(_format_error(error_msg))


if __name__ == "__main__":
    print("\n")
    print("╔" + "═"*78 + "╗")
    print("║" + " MCP TOOL OUTPUT FORMATTING DEMONSTRATION ".center(78) + "║")
    print("║" + " Enhanced with clean spacing and visual hierarchy ".center(78) + "║")
    print("╚" + "═"*78 + "╝")
    
    demos = [
        ("Search Results", demo_search_results),
        ("Technique Analysis", demo_technique_analysis),
        ("Code Generation", demo_code_generation),
        ("Technique Comparison", demo_technique_comparison),
        ("RAG Statistics", demo_rag_stats),
        ("General Response", demo_general_response),
        ("Error Messages", demo_error)
    ]
    
    print("\nAvailable demonstrations:")
    for i, (name, _) in enumerate(demos, 1):
        print(f"  {i}. {name}")
    print(f"  {len(demos)+1}. Show all")
    print("  0. Exit")
    
    choice = input("\nSelect demo (0-{}): ".format(len(demos)+1))
    
    try:
        choice_num = int(choice)
        if choice_num == 0:
            print("Exiting...")
        elif choice_num == len(demos) + 1:
            for name, func in demos:
                func()
        elif 1 <= choice_num <= len(demos):
            demos[choice_num-1][1]()
        else:
            print("Invalid choice")
    except ValueError:
        print("Invalid input")
