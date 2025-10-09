"""EDR Intelligence - Simple bypass recommendations"""

EDR_BYPASSES = {
    "Microsoft Defender": ["indirect_syscalls", "zilean_sleep", "poolparty"],
    "CrowdStrike": ["hwbp_syscalls", "waiting_thread_hijacking", "etw_bypass"],
    "SentinelOne": ["module_stomping", "memory_bouncing", "hwbp_syscalls"],
    "Sophos": ["indirect_syscalls", "zilean_sleep", "poolparty"],
    "Trend Micro": ["indirect_syscalls", "poolparty", "zilean_sleep"],
    "Carbon Black": ["module_stomping", "transacted_hollowing", "hwbp_syscalls"],
    "Palo Alto": ["hwbp_syscalls", "memory_bouncing", "etw_bypass"],
    "Trellix": ["indirect_syscalls", "zilean_sleep", "poolparty"],
    "ESET": ["indirect_syscalls", "module_stomping", "zilean_sleep"],
    "Bitdefender": ["hwbp_syscalls", "transacted_hollowing", "memory_bouncing"]
}

def get_bypasses(edr_name):
    """Get techniques for EDR (fuzzy match)"""
    edr_lower = edr_name.lower()
    for edr in EDR_BYPASSES:
        if edr.lower() in edr_lower or edr_lower in edr.lower():
            return EDR_BYPASSES[edr]
    # Aliases
    aliases = {"defender": "Microsoft Defender", "falcon": "CrowdStrike",
               "sentinel": "SentinelOne", "cortex": "Palo Alto", "mcafee": "Trellix"}
    for alias, edr in aliases.items():
        if alias in edr_lower:
            return EDR_BYPASSES[edr]
    return ["indirect_syscalls", "zilean_sleep", "poolparty"]  # Default
