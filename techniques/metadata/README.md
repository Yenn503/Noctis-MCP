# Technique Metadata & MITRE ATT&CK Mappings

This directory contains JSON metadata files for all Noctis techniques, including MITRE ATT&CK framework mappings.

## Structure

Each technique has a dedicated JSON file with the following structure:

```json
{
  "technique_id": "NOCTIS-T124",
  "name": "Api Hashing",
  "category": "evasion/obfuscation",
  "description": "Obfuscates API calls by hashing function names to evade static analysis",
  "source_files": [
    "MaldevAcademy\\Loader1\\MaldevAcademyLdr.1-main\\Loader\\ApiHashing.c"
  ],
  "mitre_attack": ["T1027.009", "T1106"],
  "dependencies": ["Windows.h"],
  "compatible_with": [],
  "incompatible_with": [],
  "opsec": {
    "detection_risk": "unknown",
    "stability": "unknown",
    "tested_on": [],
    "bypasses": [],
    "detected_by": []
  },
  "code_blocks": {
    "file": "ApiHashing.c",
    "functions": ["GetProcAddressH", "GetModuleHandleH"]
  },
  "variants": [],
  "author": "Unknown",
  "source_project": "MaldevAcademy",
  "last_updated": "2025-10-03T03:00:18.804705"
}
```

## MITRE ATT&CK Mapping

### Current Coverage

The Noctis framework currently maps techniques to the following MITRE ATT&CK TTPs:

| TTP | Name | Count |
|-----|------|-------|
| **T1055** | Process Injection | 5 |
| **T1027** | Obfuscated Files or Information | 4 |
| **T1106** | Native API | 2 |
| **T1562.001** | Impair Defenses: Disable/Modify Tools | 1 |
| **T1027.003** | Steganography | 1 |
| **T1027.009** | Indicator Removal from Tools | 1 |
| **T1053** | Scheduled Task/Job | 1 |
| **T1547** | Boot or Logon Autostart Execution | 1 |
| **T1564** | Hide Artifacts | 3 |

### Mapping Guidelines

When adding or updating technique metadata, follow these guidelines:

#### 1. API Obfuscation Techniques
```json
"mitre_attack": ["T1027.009", "T1106"]
```
- **T1027.009**: Indicator Removal from Tools (hiding API names)
- **T1106**: Native API (using GetProcAddress, LoadLibrary)

#### 2. Syscall Techniques
```json
"mitre_attack": ["T1106", "T1055"]
```
- **T1106**: Native API (direct syscall usage)
- **T1055**: Process Injection (often used with syscalls)

#### 3. Injection Techniques
```json
"mitre_attack": ["T1055", "T1055.001", "T1055.002", "T1055.012"]
```
- **T1055**: Generic Process Injection
- **T1055.001**: Dynamic-link Library Injection
- **T1055.002**: Portable Executable Injection
- **T1055.012**: Process Hollowing

#### 4. Encryption Techniques
```json
"mitre_attack": ["T1027"]
```
- **T1027**: Obfuscated Files or Information

#### 5. Unhooking Techniques
```json
"mitre_attack": ["T1562.001"]
```
- **T1562.001**: Impair Defenses: Disable or Modify Tools

#### 6. Steganography Techniques
```json
"mitre_attack": ["T1027.003"]
```
- **T1027.003**: Steganography

#### 7. Persistence Techniques
```json
"mitre_attack": ["T1547", "T1053", "T1543"]
```
- **T1547**: Boot or Logon Autostart Execution
- **T1053**: Scheduled Task/Job
- **T1543**: Create or Modify System Process

## Automatic Population

If you've added new techniques and need to populate MITRE mappings automatically:

```bash
# Run the auto-populator
python utils/populate_mitre_mappings.py

# Restart the server to reload
pkill -f noctis_server.py
python server/noctis_server.py
```

The script will:
1. Scan all metadata JSON files
2. Analyze technique names and categories
3. Apply appropriate MITRE ATT&CK mappings
4. Update the files in place

## Testing Mappings

After updating mappings, test them:

```bash
# Get all MITRE mappings
curl http://localhost:8888/api/mitre | jq

# Query specific TTP
curl "http://localhost:8888/api/techniques?mitre=T1055" | jq

# Check technique details
curl http://localhost:8888/api/techniques/NOCTIS-T124 | jq '.technique.mitre_attack'
```

## Adding Custom Mappings

To manually add MITRE mappings to a technique:

1. **Identify the correct MITRE TTP** from [attack.mitre.org](https://attack.mitre.org)

2. **Edit the technique JSON file**:
```json
{
  "technique_id": "NOCTIS-T124",
  "name": "Api Hashing",
  "mitre_attack": ["T1027.009", "T1106"],  // ← Add here
  ...
}
```

3. **Restart the server** to load changes

4. **Verify** using the API:
```bash
curl http://localhost:8888/api/mitre | jq '.mappings["T1027.009"]'
```

## Common MITRE ATT&CK TTPs Reference

Quick reference for malware development techniques:

### Defense Evasion (TA0005)
- **T1027**: Obfuscated Files or Information
  - T1027.003: Steganography
  - T1027.009: Indicator Removal from Tools
- **T1055**: Process Injection
  - T1055.001: DLL Injection
  - T1055.002: PE Injection
  - T1055.004: APC Queue Injection
  - T1055.012: Process Hollowing
- **T1106**: Native API
- **T1562.001**: Impair Defenses: Disable/Modify Tools
- **T1564**: Hide Artifacts

### Privilege Escalation (TA0004)
- **T1055**: Process Injection (also used for privilege escalation)

### Persistence (TA0003)
- **T1547**: Boot or Logon Autostart Execution
  - T1547.001: Registry Run Keys
- **T1053**: Scheduled Task/Job
  - T1053.005: Scheduled Task
- **T1543**: Create or Modify System Process
  - T1543.003: Windows Service

## Contributing

When contributing new techniques:

1. Ensure source code is properly documented
2. Add appropriate MITRE ATT&CK mappings
3. Test the mappings via the API
4. Update this README if introducing new TTPs
5. Submit a PR with clear descriptions

## Resources

- **MITRE ATT&CK Framework**: https://attack.mitre.org
- **ATT&CK Navigator**: https://mitre-attack.github.io/attack-navigator/
- **Noctis API Reference**: `../docs/API_REFERENCE.md`
- **User Guide**: `../docs/USER_GUIDE.md`

## Index Regeneration

After modifying technique metadata, regenerate the index:

```bash
python utils/technique_indexer.py
```

This updates `index.json` with the latest technique count and categories.

---

**Last Updated**: October 3, 2025  
**Framework Version**: MITRE ATT&CK v14.1  
**Total Techniques**: 126+  
**Mapped TTPs**: 12

