"""
Simple Template Recommender with Learning Integration

Maps user request → template file
Now checks learning data to avoid recommending detected templates.
"""

def recommend_template(objective: str) -> dict:
    """
    Template recommendation with learning data integration

    Args:
        objective: User's objective (e.g., "bypass CrowdStrike")

    Returns:
        Template info dict with detection warning if needed
    """
    obj_lower = objective.lower() if objective else ""

    # Extract target AV from objective
    target_av = None
    av_keywords = {
        'crowdstrike': 'CrowdStrike',
        'defender': 'Windows Defender',
        'sentinelone': 'SentinelOne',
        'cortex': 'Cortex XDR',
        'sophos': 'Sophos',
        'trendmicro': 'Trend Micro'
    }
    for keyword, av_name in av_keywords.items():
        if keyword in obj_lower:
            target_av = av_name
            break

    # Rule 1: Loader/Bypass → integrated_loader.c (has EVERYTHING)
    if any(word in obj_lower for word in ['loader', 'bypass', 'evasion', 'evade', 'edr', 'av']):
        recommendation = {
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
        return _check_detection_history(recommendation, 'integrated_loader', target_av)

    # Rule 2: RAT/C2/Beacon → beacon_stealth.c
    elif any(word in obj_lower for word in ['rat', 'c2', 'beacon', 'callback', 'implant', 'backdoor']):
        recommendation = {
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
        return _check_detection_history(recommendation, 'beacon_stealth', target_av)

    # Rule 3: Simple injection → process_injection_complete.c
    else:
        recommendation = {
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
        return _check_detection_history(recommendation, 'process_injection_complete', target_av)


def _check_detection_history(recommendation: dict, template_name: str, target_av: str = None) -> dict:
    """
    Check learning database for detection history of this template

    Args:
        recommendation: Base recommendation dict
        template_name: Template identifier
        target_av: Target AV/EDR to check

    Returns:
        Recommendation with detection warning if applicable
    """
    try:
        from server.utils.learning import LearningTracker

        tracker = LearningTracker()

        # Get stats for this template
        if target_av:
            stats = tracker.get_stats(target_av=target_av, template_name=template_name)
        else:
            stats = tracker.get_stats(template_name=template_name)

        if stats and stats.get('total_tests', 0) > 0:
            detection_rate = stats.get('detection_rate', 0)
            total_tests = stats.get('total_tests', 0)

            # Add detection history to recommendation
            recommendation['detection_history'] = {
                'tested': total_tests,
                'detection_rate': f"{detection_rate:.0%}",
                'last_tested': stats.get('last_tested', 'unknown')
            }

            # Warn if detection rate is high (>50%)
            if detection_rate > 0.5:
                recommendation['warning'] = (
                    f"⚠️  This template has {detection_rate:.0%} detection rate against "
                    f"{target_av or 'various AVs'} in {total_tests} tests. "
                    "Consider using alternative techniques or combining with additional evasion."
                )
                recommendation['opsec_score'] = max(5.0, recommendation['opsec_score'] - 2.0)

            # Update recommendation text with real-world data
            if detection_rate < 0.1:  # <10% detection
                recommendation['recommendation'] += f" (Real-world success: {100-detection_rate*100:.0f}% in {total_tests} tests)"

    except Exception as e:
        # If learning tracker unavailable, just return original recommendation
        pass

    return recommendation


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
