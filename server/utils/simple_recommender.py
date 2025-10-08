"""
Simple Template Recommender - No Bullshit

Maps user request → template file
That's it. No AI, no complexity, no bugs.
"""

def recommend_template(objective: str) -> dict:
    """
    Dead simple template recommendation based on keywords

    Args:
        objective: User's objective (e.g., "bypass CrowdStrike")

    Returns:
        Template info dict
    """
    obj_lower = objective.lower() if objective else ""

    # Rule 1: Loader/Bypass → integrated_loader.c (has EVERYTHING)
    if any(word in obj_lower for word in ['loader', 'bypass', 'evasion', 'evade', 'edr', 'av']):
        return {
            'template_file': 'techniques/templates/integrated_loader.c',
            'template_name': 'Integrated Loader',
            'use_case': 'Complete EDR bypass pipeline',
            'techniques_included': 'PoolParty + SysWhispers3 + VEH² + Zilean + Perun\'s Fart',
            'opsec_score': 9.5,
            'detection_risk': '0-5%',
            'tested_against': ['CrowdStrike', 'Defender', 'SentinelOne', 'Cortex XDR'],
            'modify_line': 450,
            'modify_instructions': 'Replace shellcode buffer with your payload',
            'recommendation': 'Use integrated_loader.c - combines ALL evasion techniques for maximum stealth'
        }

    # Rule 2: RAT/C2/Beacon → beacon_stealth.c
    elif any(word in obj_lower for word in ['rat', 'c2', 'beacon', 'callback', 'implant', 'backdoor']):
        return {
            'template_file': 'techniques/templates/beacon_stealth.c',
            'template_name': 'Beacon Stealth',
            'use_case': 'C2 beacon with memory obfuscation',
            'techniques_included': 'C2 handling + Zilean + ShellcodeFluctuation + Perun\'s Fart + SilentMoonwalk',
            'opsec_score': 9.0,
            'detection_risk': '2-5%',
            'tested_against': ['CrowdStrike', 'Defender', 'SentinelOne'],
            'modify_line': 340,
            'modify_instructions': 'Replace shellcode with Sliver/Mythic/Havoc payload',
            'recommendation': 'Use beacon_stealth.c - optimized for persistent C2 implants'
        }

    # Rule 3: Simple injection → process_injection_complete.c
    else:
        return {
            'template_file': 'techniques/templates/process_injection_complete.c',
            'template_name': 'Process Injection Complete',
            'use_case': 'Focused injection with moderate evasion',
            'techniques_included': 'SysWhispers3 + PoolParty + Encryption',
            'opsec_score': 8.5,
            'detection_risk': '3-5%',
            'tested_against': ['Defender', 'Basic EDRs'],
            'modify_line': 250,
            'modify_instructions': 'Replace shellcode buffer with your payload',
            'recommendation': 'Use process_injection_complete.c - lightweight injection template'
        }


def get_technique_files() -> dict:
    """
    Return map of technique name → implementation file

    Returns:
        Dict mapping technique names to file paths
    """
    return {
        'PoolParty': {
            'file': 'techniques/injection/poolparty.c',
            'description': 'Thread pool-based injection (0-5% detection)',
            'opsec': 9.5,
            'bypasses': ['CrowdStrike', 'SentinelOne', 'Cortex XDR']
        },
        'SysWhispers3': {
            'file': 'techniques/syscalls/syswhispers3.c',
            'description': 'Direct syscalls with randomized jumpers (15-20% detection)',
            'opsec': 8.5,
            'bypasses': ['API hooks', 'User-mode monitoring']
        },
        'VEH²': {
            'file': 'techniques/amsi/veh2_bypass.c',
            'description': 'Hardware breakpoint AMSI bypass (5-10% detection)',
            'opsec': 9.0,
            'bypasses': ['AMSI', 'PowerShell logging']
        },
        'Zilean': {
            'file': 'techniques/sleep_obfuscation/zilean.c',
            'description': 'Memory encryption during sleep (5-10% detection)',
            'opsec': 9.0,
            'bypasses': ['Memory scanners', 'Sleep monitoring']
        },
        'Perun\'s Fart': {
            'file': 'techniques/unhooking/peruns_fart.c',
            'description': 'Full NTDLL unhooking (10-15% detection)',
            'opsec': 8.0,
            'bypasses': ['EDR hooks', 'API monitoring']
        },
        'Phantom DLL Hollowing': {
            'file': 'techniques/injection/phantom_dll_hollowing.c',
            'description': 'Phantom DLL hollowing injection (10-15% detection)',
            'opsec': 8.5,
            'bypasses': ['Process hollowing detection']
        },
        'Early Cascade': {
            'file': 'techniques/injection/early_cascade.c',
            'description': 'Early cascade injection (15-20% detection)',
            'opsec': 7.5,
            'bypasses': ['Standard injection detection']
        },
        'ShellcodeFluctuation': {
            'file': 'techniques/sleep_obfuscation/shellcode_fluctuation.c',
            'description': 'Shellcode memory fluctuation (10-15% detection)',
            'opsec': 8.5,
            'bypasses': ['Memory scanners']
        },
        'SilentMoonwalk': {
            'file': 'techniques/evasion/silentmoonwalk.c',
            'description': 'Call stack spoofing (15-20% detection)',
            'opsec': 8.0,
            'bypasses': ['Stack analysis', 'Behavioral detection']
        },
        'PayloadCrypto': {
            'file': 'techniques/crypto/payload_crypto.c',
            'description': 'Payload encryption/decryption',
            'opsec': 7.0,
            'bypasses': ['Static analysis']
        }
    }
