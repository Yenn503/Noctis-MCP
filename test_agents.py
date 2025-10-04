#!/usr/bin/env python3
"""
Test script for Noctis Agent System
=====================================

Tests all agent endpoints to ensure they work correctly.
"""

import requests
import json
import time


BASE_URL = "http://127.0.0.1:8888"


def print_result(name, result):
    """Pretty print test result"""
    print(f"\n{'='*70}")
    print(f"{name}")
    print(f"{'='*70}")
    print(json.dumps(result, indent=2))
    print(f"{'='*70}\n")


def test_agent_status():
    """Test agent status endpoint"""
    print("\n[1] Testing Agent Status Endpoint...")

    response = requests.get(f"{BASE_URL}/api/v2/agents/status")
    result = response.json()

    print_result("Agent Status", result)
    return result.get('success', False)


def test_technique_selection():
    """Test technique selection agent"""
    print("\n[2] Testing Technique Selection Agent...")

    payload = {
        "target_av": "Windows Defender",
        "objective": "evasion",
        "complexity": "medium",
        "constraints": {
            "max_techniques": 3
        }
    }

    response = requests.post(
        f"{BASE_URL}/api/v2/agents/technique-selection",
        json=payload
    )
    result = response.json()

    print_result("Technique Selection", result)
    return result.get('success', False)


def test_opsec_optimization():
    """Test OPSEC optimization agent"""
    print("\n[3] Testing OPSEC Optimization Agent...")

    test_code = '''
#include <Windows.h>
#include <stdio.h>

int main() {
    char* url = "http://malicious-c2.com/payload.exe";
    printf("Connecting to: %s\\n", url);
    return 0;
}
'''

    payload = {
        "code": test_code,
        "target_score": 8.0,
        "max_iterations": 2
    }

    response = requests.post(
        f"{BASE_URL}/api/v2/agents/opsec-optimization",
        json=payload
    )
    result = response.json()

    print_result("OPSEC Optimization", result)
    return result.get('success', False)


def test_learning_agent():
    """Test learning agent"""
    print("\n[4] Testing Learning Agent...")

    payload = {
        "action": "record_detection",
        "techniques": ["NOCTIS-T001", "NOCTIS-T002"],
        "av_edr": "Windows Defender",
        "detected": False,
        "detection_type": "static",
        "obfuscation_level": "advanced",
        "notes": "Test detection feedback"
    }

    response = requests.post(
        f"{BASE_URL}/api/v2/agents/learning",
        json=payload
    )
    result = response.json()

    print_result("Learning Agent (Detection)", result)
    return result.get('success', False)


def test_malware_development():
    """Test malware development agent"""
    print("\n[5] Testing Malware Development Agent...")

    payload = {
        "goal": "Create a stealthy loader that evades Windows Defender",
        "target_av": "Windows Defender",
        "target_os": "Windows",
        "architecture": "x64",
        "auto_compile": False,  # Skip compilation for test
        "target_opsec_score": 7.0,
        "max_techniques": 3
    }

    response = requests.post(
        f"{BASE_URL}/api/v2/agents/malware-development",
        json=payload
    )
    result = response.json()

    # Don't print full code, just summary
    if result.get('success') and 'data' in result:
        summary = {
            'success': result['success'],
            'execution_time': result.get('execution_time'),
            'techniques_used': result['data'].get('techniques_used'),
            'opsec_score': result['data'].get('opsec_score'),
            'compilation_success': result['data'].get('compilation_success'),
            'workflow_steps': len(result['data'].get('workflow_summary', [])),
            'code_length': len(result['data'].get('source_code', '')) if 'source_code' in result['data'] else 0
        }
        print_result("Malware Development Agent", summary)
    else:
        print_result("Malware Development Agent", result)

    return result.get('success', False)


def main():
    """Run all tests"""
    print("""
====================================================================
          NOCTIS-MCP AGENT SYSTEM TEST SUITE
====================================================================
    """)

    # Wait for server to be ready
    print("[*] Waiting for server to be ready...")
    max_retries = 10
    for i in range(max_retries):
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=2)
            if response.status_code == 200:
                print(f"[+] Server is ready!")
                break
        except:
            if i < max_retries - 1:
                print(f"[*] Waiting... ({i+1}/{max_retries})")
                time.sleep(2)
            else:
                print("[!] Server not responding. Please start the server first:")
                print("    python server/noctis_server.py")
                return 1

    # Run tests
    results = {}

    try:
        results['status'] = test_agent_status()
        results['technique_selection'] = test_technique_selection()
        results['opsec_optimization'] = test_opsec_optimization()
        results['learning'] = test_learning_agent()
        results['malware_development'] = test_malware_development()
    except Exception as e:
        print(f"\n[✗] Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    for test_name, success in results.items():
        status = "+ PASS" if success else "- FAIL"
        print(f"  {status}  {test_name}")
    print("="*70)

    total = len(results)
    passed = sum(results.values())
    print(f"\nTotal: {passed}/{total} tests passed")

    return 0 if passed == total else 1


if __name__ == '__main__':
    exit(main())
