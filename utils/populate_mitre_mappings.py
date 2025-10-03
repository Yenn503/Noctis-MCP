#!/usr/bin/env python3
"""
Populate MITRE ATT&CK mappings for Noctis techniques.

This script adds appropriate MITRE ATT&CK technique IDs to the metadata
based on the technique category and name.
"""

import json
import os
from pathlib import Path

# MITRE ATT&CK Mapping Reference
# Based on common malware development techniques
CATEGORY_MITRE_MAP = {
    "api_hashing": ["T1027.009", "T1106"],  # Obfuscation + Native API
    "syscalls": ["T1106", "T1055"],  # Native API + Process Injection
    "injection": ["T1055", "T1055.001", "T1055.002", "T1055.012"],  # Process Injection variants
    "encryption": ["T1027", "T1573"],  # Obfuscated Files + Encrypted Channel
    "unhooking": ["T1562.001", "T1055"],  # Impair Defenses: Disable/Modify Tools
    "steganography": ["T1027.003", "T1564"],  # Steganography + Hide Artifacts
    "gpu_evasion": ["T1027", "T1564"],  # Obfuscation + Hide Artifacts
    "stack_spoof": ["T1055", "T1620"],  # Process Injection + Reflective Code Loading
    "veh": ["T1055", "T1574"],  # Process Injection + Hijack Execution Flow
    "persistence": ["T1547", "T1053", "T1543"],  # Boot/Logon, Scheduled Task, Create/Modify Service
    "evasion/obfuscation": ["T1027", "T1027.009"],  # Obfuscated Files
    "evasion/unhooking": ["T1562.001", "T1055"],  # Impair Defenses
    "evasion/advanced": ["T1027", "T1055", "T1564"],  # Advanced evasion techniques
}

# Specific technique name mappings (override category defaults)
NAME_MITRE_MAP = {
    "api hashing": ["T1027.009", "T1106"],
    "syscalls": ["T1106", "T1055"],
    "hellshall": ["T1106", "T1055"],
    "hellsgate": ["T1106", "T1055"],
    "indirect syscalls": ["T1106", "T1055"],
    "process injection": ["T1055"],
    "process hollowing": ["T1055.012"],
    "apc injection": ["T1055.004"],
    "thread pool": ["T1055.012"],
    "dll injection": ["T1055.001"],
    "runpe": ["T1055.012"],
    "unhooking": ["T1562.001"],
    "etw patching": ["T1562.001"],
    "amsi bypass": ["T1562.001"],
    "encryption": ["T1027"],
    "aes": ["T1027"],
    "xor": ["T1027"],
    "rc4": ["T1027"],
    "steganography": ["T1027.003"],
    "persistence": ["T1547", "T1053"],
    "registry": ["T1547.001"],
    "scheduled task": ["T1053.005"],
    "service": ["T1543.003"],
}

def get_mitre_mappings(technique_name, category):
    """
    Get MITRE ATT&CK mappings for a technique based on name and category.
    """
    name_lower = technique_name.lower()
    
    # Check if specific name mapping exists
    for key, mappings in NAME_MITRE_MAP.items():
        if key in name_lower:
            return mappings
    
    # Fall back to category mapping
    if category in CATEGORY_MITRE_MAP:
        return CATEGORY_MITRE_MAP[category]
    
    # Default generic mapping
    return ["T1027"]  # Generic obfuscation

def populate_metadata_file(metadata_path):
    """
    Populate MITRE mappings in a metadata JSON file.
    """
    try:
        with open(metadata_path, 'r') as f:
            data = json.load(f)
        
        # Handle both single technique and array of techniques
        if isinstance(data, dict) and "technique_id" in data:
            # Single technique file
            techniques = [data]
            single_file = True
        else:
            # Multiple techniques (shouldn't happen but handle it)
            techniques = [data] if isinstance(data, dict) else []
            single_file = False
        
        modified = False
        for technique in techniques:
            if not technique.get("mitre_attack") or len(technique.get("mitre_attack", [])) == 0:
                # Get mappings
                name = technique.get("name", "")
                category = technique.get("category", "")
                
                mappings = get_mitre_mappings(name, category)
                technique["mitre_attack"] = mappings
                modified = True
                
                print(f"  [+] {technique.get('technique_id')}: {name} → {mappings}")
        
        if modified:
            with open(metadata_path, 'w') as f:
                if single_file:
                    json.dump(techniques[0], f, indent=2)
                else:
                    json.dump(data, f, indent=2)
            return True
        
        return False
    
    except Exception as e:
        print(f"  [!] Error processing {metadata_path}: {e}")
        return False

def main():
    """
    Main function to populate all metadata files.
    """
    print("[*] MITRE ATT&CK Mapping Populator")
    print("[*] This will add MITRE mappings to all technique metadata files\n")
    
    # Get metadata directory
    script_dir = Path(__file__).parent.parent
    metadata_dir = script_dir / "techniques" / "metadata"
    
    if not metadata_dir.exists():
        print(f"[!] Metadata directory not found: {metadata_dir}")
        return
    
    # Process all JSON files
    json_files = list(metadata_dir.glob("*.json"))
    json_files = [f for f in json_files if f.name != "index.json"]  # Skip index
    
    print(f"[*] Found {len(json_files)} metadata files\n")
    
    modified_count = 0
    for json_file in json_files:
        print(f"[*] Processing: {json_file.name}")
        if populate_metadata_file(json_file):
            modified_count += 1
    
    print(f"\n[+] Complete! Modified {modified_count} files")
    print(f"[*] Restart the Noctis server to load updated mappings")
    print(f"[*] Test with: curl http://localhost:8888/api/mitre")

if __name__ == "__main__":
    main()

