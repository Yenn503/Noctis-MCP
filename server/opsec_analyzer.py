#!/usr/bin/env python3
"""
OPSEC Analyzer for Malware Code
================================

Analyzes C/C++ malware code for operational security issues and detection vectors.

This module provides:
- Suspicious string detection
- Windows API import analysis
- Entropy and obfuscation checking
- Detection probability scoring
- Actionable recommendations

Author: Noctis-MCP Community
License: MIT
"""

import re
import math
import logging
from typing import Dict, List, Tuple, Set, Optional
from dataclasses import dataclass, field
from collections import Counter


# Setup logging
logger = logging.getLogger(__name__)


@dataclass
class OpsecIssue:
    """Represents a single OPSEC issue"""
    severity: str  # critical, high, medium, low, info
    category: str  # string, api, entropy, pattern, etc.
    description: str
    location: Optional[str] = None
    recommendation: Optional[str] = None
    confidence: float = 1.0  # 0.0 to 1.0


@dataclass
class OpsecReport:
    """Complete OPSEC analysis report"""
    overall_score: float  # 0-10, higher is better
    risk_level: str  # excellent, good, moderate, poor, critical
    issues: List[OpsecIssue] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert report to dictionary"""
        return {
            'overall_score': round(self.overall_score, 2),
            'risk_level': self.risk_level,
            'total_issues': len(self.issues),
            'issues_by_severity': self._count_by_severity(),
            'issues': [self._issue_to_dict(issue) for issue in self.issues],
            'statistics': self.statistics,
            'recommendations': self.recommendations
        }
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count issues by severity"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for issue in self.issues:
            counts[issue.severity] = counts.get(issue.severity, 0) + 1
        return counts
    
    def _issue_to_dict(self, issue: OpsecIssue) -> Dict:
        """Convert issue to dictionary"""
        return {
            'severity': issue.severity,
            'category': issue.category,
            'description': issue.description,
            'location': issue.location,
            'recommendation': issue.recommendation,
            'confidence': round(issue.confidence, 2)
        }


class StringScanner:
    """Scans code for suspicious strings"""
    
    # Suspicious strings that indicate malicious behavior
    SUSPICIOUS_STRINGS = {
        # Network indicators
        'http://': ('high', 'Cleartext HTTP URL detected'),
        'https://': ('medium', 'HTTPS URL detected'),
        'ftp://': ('high', 'FTP URL detected'),
        'smtp://': ('high', 'SMTP URL detected'),
        '.onion': ('critical', 'Tor hidden service domain'),
        
        # File paths that are IOCs
        'C:\\Windows\\System32': ('medium', 'System32 path reference'),
        'C:\\Windows\\Temp': ('medium', 'Temp directory reference'),
        'C:\\ProgramData': ('medium', 'ProgramData directory reference'),
        '%APPDATA%': ('medium', 'AppData environment variable'),
        '%TEMP%': ('medium', 'Temp environment variable'),
        
        # Registry keys
        'HKEY_LOCAL_MACHINE': ('medium', 'Registry key reference'),
        'HKEY_CURRENT_USER': ('medium', 'Registry key reference'),
        'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run': ('high', 'Persistence registry key'),
        
        # Common malware strings
        'cmd.exe': ('high', 'Command shell reference'),
        'powershell': ('high', 'PowerShell reference'),
        'wscript': ('high', 'Windows Script Host reference'),
        'cscript': ('high', 'Windows Script Host reference'),
        'regsvr32': ('high', 'DLL registration utility'),
        'rundll32': ('high', 'DLL execution utility'),
        
        # Process names
        'explorer.exe': ('medium', 'Explorer process name'),
        'svchost.exe': ('medium', 'Service host process name'),
        'lsass.exe': ('high', 'LSASS process name (credential theft)'),
        'winlogon.exe': ('high', 'Winlogon process name'),
        
        # Anti-analysis
        'VMware': ('high', 'VM detection string'),
        'VirtualBox': ('high', 'VM detection string'),
        'QEMU': ('high', 'VM detection string'),
        'Sandbox': ('high', 'Sandbox detection string'),
        'sample': ('low', 'Sample/test file indicator'),
        'malware': ('critical', 'Malware string literal'),
    }
    
    # Sensitive API/function names in strings
    SENSITIVE_FUNCTIONS = {
        'VirtualAlloc', 'VirtualProtect', 'CreateRemoteThread', 'WriteProcessMemory',
        'OpenProcess', 'CreateProcess', 'ShellExecute', 'WinExec',
        'URLDownloadToFile', 'InternetOpen', 'HttpSendRequest',
        'CryptEncrypt', 'CryptDecrypt', 'RegSetValue', 'RegCreateKey'
    }
    
    def scan(self, code: str) -> List[OpsecIssue]:
        """Scan code for suspicious strings"""
        issues = []
        
        # Find all string literals
        string_pattern = r'\"([^\"\\]*(\\.[^\"\\]*)*)\"|\'([^\'\\]*(\\.[^\'\\]*)*)\''
        strings = re.findall(string_pattern, code)
        
        # Check each string
        for match in strings:
            string_content = match[0] if match[0] else match[2]
            
            # Check against suspicious strings
            for suspicious, (severity, description) in self.SUSPICIOUS_STRINGS.items():
                if suspicious.lower() in string_content.lower():
                    issues.append(OpsecIssue(
                        severity=severity,
                        category='string',
                        description=f'{description}: "{string_content[:50]}"',
                        recommendation='Consider encrypting, obfuscating, or removing this string'
                    ))
            
            # Check for sensitive function names
            for func in self.SENSITIVE_FUNCTIONS:
                if func in string_content:
                    issues.append(OpsecIssue(
                        severity='medium',
                        category='string',
                        description=f'Sensitive function name in string: "{func}"',
                        recommendation='Avoid hardcoding function names, use dynamic resolution'
                    ))
        
        return issues


class ImportAnalyzer:
    """Analyzes Windows API imports"""
    
    # Suspicious Windows APIs categorized by behavior
    SUSPICIOUS_APIS = {
        # Memory manipulation
        'VirtualAlloc': ('high', 'memory_allocation', 'Allocates memory (common in shellcode loaders)'),
        'VirtualAllocEx': ('high', 'memory_allocation', 'Allocates memory in remote process'),
        'VirtualProtect': ('high', 'memory_protection', 'Changes memory protection (shellcode execution)'),
        'VirtualProtectEx': ('high', 'memory_protection', 'Changes memory protection in remote process'),
        
        # Process manipulation
        'CreateRemoteThread': ('critical', 'process_injection', 'Creates thread in remote process (injection)'),
        'CreateRemoteThreadEx': ('critical', 'process_injection', 'Creates thread in remote process'),
        'QueueUserAPC': ('high', 'process_injection', 'APC injection technique'),
        'SetThreadContext': ('high', 'process_injection', 'Thread context manipulation'),
        'WriteProcessMemory': ('critical', 'process_injection', 'Writes to remote process memory'),
        'ReadProcessMemory': ('high', 'process_inspection', 'Reads from remote process memory'),
        'OpenProcess': ('medium', 'process_access', 'Opens handle to process'),
        
        # Process creation
        'CreateProcessA': ('medium', 'process_creation', 'Creates new process'),
        'CreateProcessW': ('medium', 'process_creation', 'Creates new process'),
        'WinExec': ('high', 'process_creation', 'Executes program (deprecated, suspicious)'),
        'ShellExecuteA': ('high', 'process_creation', 'Executes program via shell'),
        'ShellExecuteW': ('high', 'process_creation', 'Executes program via shell'),
        
        # DLL loading
        'LoadLibraryA': ('medium', 'dll_loading', 'Loads DLL'),
        'LoadLibraryW': ('medium', 'dll_loading', 'Loads DLL'),
        'LoadLibraryExA': ('medium', 'dll_loading', 'Loads DLL with options'),
        'LoadLibraryExW': ('medium', 'dll_loading', 'Loads DLL with options'),
        'GetProcAddress': ('medium', 'api_resolution', 'Resolves function address (dynamic loading)'),
        
        # Registry manipulation
        'RegCreateKeyA': ('medium', 'registry', 'Creates registry key'),
        'RegCreateKeyW': ('medium', 'registry', 'Creates registry key'),
        'RegSetValueA': ('medium', 'registry', 'Sets registry value'),
        'RegSetValueW': ('medium', 'registry', 'Sets registry value'),
        'RegOpenKeyA': ('low', 'registry', 'Opens registry key'),
        'RegOpenKeyW': ('low', 'registry', 'Opens registry key'),
        
        # Network
        'InternetOpenA': ('high', 'network', 'Initializes WinINet (network communication)'),
        'InternetOpenW': ('high', 'network', 'Initializes WinINet'),
        'InternetOpenUrlA': ('high', 'network', 'Opens URL'),
        'InternetOpenUrlW': ('high', 'network', 'Opens URL'),
        'HttpSendRequestA': ('high', 'network', 'Sends HTTP request'),
        'HttpSendRequestW': ('high', 'network', 'Sends HTTP request'),
        'URLDownloadToFileA': ('critical', 'network', 'Downloads file from URL'),
        'URLDownloadToFileW': ('critical', 'network', 'Downloads file from URL'),
        'send': ('medium', 'network', 'Sends data over socket'),
        'recv': ('medium', 'network', 'Receives data from socket'),
        'connect': ('medium', 'network', 'Connects to remote host'),
        
        # Crypto
        'CryptEncrypt': ('medium', 'cryptography', 'Encrypts data'),
        'CryptDecrypt': ('medium', 'cryptography', 'Decrypts data'),
        'CryptAcquireContext': ('low', 'cryptography', 'Acquires crypto context'),
        
        # Anti-debugging
        'IsDebuggerPresent': ('high', 'anti_debug', 'Checks for debugger'),
        'CheckRemoteDebuggerPresent': ('high', 'anti_debug', 'Checks for remote debugger'),
        'OutputDebugStringA': ('medium', 'anti_debug', 'Debug output (anti-debug technique)'),
        'NtQueryInformationProcess': ('high', 'anti_debug', 'Queries process info (anti-debug)'),
        
        # Service manipulation
        'CreateServiceA': ('high', 'service', 'Creates Windows service'),
        'CreateServiceW': ('high', 'service', 'Creates Windows service'),
        'StartServiceA': ('medium', 'service', 'Starts Windows service'),
        'StartServiceW': ('medium', 'service', 'Starts Windows service'),
    }
    
    def analyze(self, code: str) -> List[OpsecIssue]:
        """Analyze Windows API imports"""
        issues = []
        
        # Find all function calls (basic pattern)
        # Matches: FunctionName( or FunctionName (
        function_pattern = r'\b([A-Z][a-zA-Z0-9_]*)\s*\('
        functions = re.findall(function_pattern, code)
        
        # Track unique functions and their frequency
        function_counts = Counter(functions)
        
        # Check against suspicious APIs
        for func, count in function_counts.items():
            if func in self.SUSPICIOUS_APIS:
                severity, category, description = self.SUSPICIOUS_APIS[func]
                
                # Higher usage = higher suspicion
                confidence = min(1.0, 0.7 + (count * 0.1))
                
                issues.append(OpsecIssue(
                    severity=severity,
                    category='api_call',
                    description=f'{func}: {description} (called {count}x)',
                    recommendation=self._get_api_recommendation(func, category),
                    confidence=confidence
                ))
        
        return issues
    
    def _get_api_recommendation(self, func: str, category: str) -> str:
        """Get recommendation for API usage"""
        recommendations = {
            'memory_allocation': 'Consider using indirect syscalls or API hashing',
            'memory_protection': 'Use syscalls to bypass EDR hooks',
            'process_injection': 'High-risk technique - use advanced methods (APC, thread hijacking)',
            'process_creation': 'Consider using WMI or COM objects instead',
            'dll_loading': 'Use API hashing or direct syscalls',
            'registry': 'Registry modifications are highly monitored',
            'network': 'Encrypt traffic, use domain fronting or C2 infrastructure',
            'cryptography': 'Ensure proper key management',
            'anti_debug': 'Combine multiple techniques for robustness',
            'service': 'Service creation triggers alerts, consider alternatives',
        }
        return recommendations.get(category, 'Use evasion techniques to hide this behavior')


class EntropyChecker:
    """Checks code entropy and obfuscation"""
    
    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of string"""
        if not data:
            return 0.0
        
        # Count character frequencies
        frequencies = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in frequencies.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze(self, code: str) -> List[OpsecIssue]:
        """Analyze code entropy"""
        issues = []
        
        # Calculate overall entropy
        total_entropy = self.calculate_entropy(code)
        
        # Check string literals for high entropy (encrypted/encoded data)
        string_pattern = r'\"([^\"\\]*(\\.[^\"\\]*)*)\"|\'([^\'\\]*(\\.[^\'\\]*)*)\''
        strings = re.findall(string_pattern, code)
        
        high_entropy_strings = []
        for match in strings:
            string_content = match[0] if match[0] else match[2]
            if len(string_content) > 20:  # Only check longer strings
                entropy = self.calculate_entropy(string_content)
                if entropy > 4.5:  # High entropy threshold
                    high_entropy_strings.append((string_content[:50], entropy))
        
        if high_entropy_strings:
            issues.append(OpsecIssue(
                severity='medium',
                category='entropy',
                description=f'Found {len(high_entropy_strings)} high-entropy strings (possible encrypted data)',
                recommendation='High entropy strings may indicate encryption/encoding (good for OPSEC)',
                confidence=0.8
            ))
        
        # Check for obfuscation patterns
        if total_entropy > 5.0:
            issues.append(OpsecIssue(
                severity='info',
                category='entropy',
                description=f'High overall entropy ({total_entropy:.2f}) - code appears obfuscated',
                recommendation='Good OPSEC - obfuscation helps evade detection',
                confidence=0.7
            ))
        elif total_entropy < 3.5:
            issues.append(OpsecIssue(
                severity='low',
                category='entropy',
                description=f'Low entropy ({total_entropy:.2f}) - code is very readable',
                recommendation='Consider adding obfuscation for better evasion',
                confidence=0.9
            ))
        
        return issues


class PatternDetector:
    """Detects common malware patterns"""
    
    SUSPICIOUS_PATTERNS = [
        (r'#include\s*<windows\.h>', 'low', 'Windows API usage'),
        (r'#pragma\s+comment\s*\(\s*lib\s*,\s*["\']ws2_32\.lib["\']\s*\)', 'medium', 'Winsock library (networking)'),
        (r'typedef\s+\w+\s*\(\s*\*\s*\w+\s*\)', 'medium', 'Function pointer typedef (dynamic loading)'),
        (r'__declspec\s*\(\s*dllexport\s*\)', 'low', 'DLL export declaration'),
        (r'asm\s*\{|\basm\b|__asm__', 'high', 'Inline assembly (shellcode/syscalls)'),
        (r'\\x[0-9a-fA-F]{2}', 'high', 'Hex-encoded bytes (possible shellcode)'),
        (r'\\[0-7]{3}', 'medium', 'Octal-encoded bytes'),
        (r'0x[0-9a-fA-F]{8,}', 'low', 'Large hex constants'),
    ]
    
    def detect(self, code: str) -> List[OpsecIssue]:
        """Detect suspicious patterns"""
        issues = []
        
        for pattern, severity, description in self.SUSPICIOUS_PATTERNS:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                issues.append(OpsecIssue(
                    severity=severity,
                    category='pattern',
                    description=f'{description} (found {len(matches)}x)',
                    recommendation='Consider if this pattern is necessary',
                    confidence=0.8
                ))
        
        return issues


class OpsecAnalyzer:
    """
    Main OPSEC analyzer for malware code
    
    Analyzes code for detection vectors and operational security issues.
    """
    
    def __init__(self):
        self.string_scanner = StringScanner()
        self.import_analyzer = ImportAnalyzer()
        self.entropy_checker = EntropyChecker()
        self.pattern_detector = PatternDetector()
    
    def analyze(self, code: str) -> OpsecReport:
        """
        Perform complete OPSEC analysis
        
        Args:
            code: C/C++ source code to analyze
        
        Returns:
            OpsecReport with findings and score
        """
        logger.info("Starting OPSEC analysis")
        
        # Collect all issues
        issues = []
        issues.extend(self.string_scanner.scan(code))
        issues.extend(self.import_analyzer.analyze(code))
        issues.extend(self.entropy_checker.analyze(code))
        issues.extend(self.pattern_detector.detect(code))
        
        # Calculate score
        score = self._calculate_score(issues)
        risk_level = self._determine_risk_level(score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(issues)
        
        # Gather statistics
        statistics = self._gather_statistics(code, issues)
        
        report = OpsecReport(
            overall_score=score,
            risk_level=risk_level,
            issues=issues,
            statistics=statistics,
            recommendations=recommendations
        )
        
        logger.info(f"OPSEC analysis complete: Score {score}/10, Risk: {risk_level}")
        
        return report
    
    def _calculate_score(self, issues: List[OpsecIssue]) -> float:
        """Calculate overall OPSEC score (0-10, higher is better)"""
        if not issues:
            return 10.0  # Perfect score if no issues
        
        # Severity weights (how much they reduce the score)
        severity_weights = {
            'critical': 2.0,
            'high': 1.5,
            'medium': 1.0,
            'low': 0.5,
            'info': 0.0  # Info doesn't reduce score
        }
        
        # Calculate total penalty
        penalty = sum(severity_weights.get(issue.severity, 0) * issue.confidence 
                     for issue in issues)
        
        # Start from 10, subtract penalties
        score = max(0.0, 10.0 - penalty)
        
        return score
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score"""
        if score >= 8.0:
            return 'excellent'
        elif score >= 6.0:
            return 'good'
        elif score >= 4.0:
            return 'moderate'
        elif score >= 2.0:
            return 'poor'
        else:
            return 'critical'
    
    def _generate_recommendations(self, issues: List[OpsecIssue]) -> List[str]:
        """Generate top recommendations"""
        recommendations = set()
        
        # Add specific recommendations from issues
        for issue in issues:
            if issue.severity in ['critical', 'high'] and issue.recommendation:
                recommendations.add(issue.recommendation)
        
        # Add general recommendations
        critical_count = sum(1 for i in issues if i.severity == 'critical')
        high_count = sum(1 for i in issues if i.severity == 'high')
        
        if critical_count > 0:
            recommendations.add(f'Address {critical_count} critical issues immediately')
        if high_count > 5:
            recommendations.add('Consider using more evasion techniques')
        
        # Top recommendations
        general_recs = [
            'Use API hashing to hide imported functions',
            'Implement direct syscalls to bypass EDR hooks',
            'Encrypt all strings and configuration data',
            'Add anti-debugging and VM detection',
            'Use polymorphic or metamorphic techniques',
            'Implement domain generation algorithm (DGA) for C2',
            'Use certificate pinning for network communications',
            'Implement process hollowing or injection for stealth'
        ]
        
        # Add a few general ones if not enough specific
        while len(recommendations) < 5 and general_recs:
            recommendations.add(general_recs.pop(0))
        
        return list(recommendations)[:8]  # Top 8
    
    def _gather_statistics(self, code: str, issues: List[OpsecIssue]) -> Dict:
        """Gather code statistics"""
        return {
            'code_size': len(code),
            'lines_of_code': len(code.split('\n')),
            'total_issues': len(issues),
            'critical_issues': sum(1 for i in issues if i.severity == 'critical'),
            'high_issues': sum(1 for i in issues if i.severity == 'high'),
            'medium_issues': sum(1 for i in issues if i.severity == 'medium'),
            'low_issues': sum(1 for i in issues if i.severity == 'low'),
            'entropy': self.entropy_checker.calculate_entropy(code)
        }


# ============================================================================
# TESTING
# ============================================================================

def test_opsec_analyzer():
    """Test OPSEC analyzer"""
    
    test_code = """
#include <windows.h>
#include <stdio.h>

// Suspicious test code
int main() {
    // Memory allocation for shellcode
    void* mem = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    // Process injection
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1234);
    WriteProcessMemory(hProcess, mem, "\\x90\\x90\\x90", 3, NULL);
    CreateRemoteThread(hProcess, NULL, 0, mem, NULL, 0, NULL);
    
    // Network connection
    InternetOpenA("Mozilla", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    
    // Registry persistence
    RegSetValueA(HKEY_CURRENT_USER, "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
                 "Malware", REG_SZ, "C:\\\\Windows\\\\Temp\\\\malware.exe", 0);
    
    return 0;
}
"""
    
    print("[*] Testing OPSEC Analyzer...")
    analyzer = OpsecAnalyzer()
    report = analyzer.analyze(test_code)
    
    print(f"\n[*] OPSEC Score: {report.overall_score}/10")
    print(f"[*] Risk Level: {report.risk_level.upper()}")
    print(f"[*] Total Issues: {len(report.issues)}")
    print(f"\n[*] Issues by Severity:")
    for severity, count in report.to_dict()['issues_by_severity'].items():
        if count > 0:
            print(f"    {severity.upper()}: {count}")
    
    print(f"\n[*] Top Recommendations:")
    for i, rec in enumerate(report.recommendations[:5], 1):
        print(f"    {i}. {rec}")
    
    return report


if __name__ == "__main__":
    test_opsec_analyzer()

