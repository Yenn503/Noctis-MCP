# Live Detection Testing with VirusTotal

## Overview

Noctis-MCP integrates with VirusTotal to provide live malware detection testing against 70+ AV/EDR engines. This validates if generated malware actually evades target defenses.

**Status:** Production Ready
**API:** VirusTotal v3
**Tool:** `test_detection()`

---

## Features

- Upload binaries to VirusTotal
- Test against 70+ AV/EDR engines simultaneously
- Get detection verdicts in **seconds** (not minutes)
- Automated OPSEC score calculation (1-10 scale)
- Smart caching (7-day TTL) to avoid redundant uploads
- Actionable recommendations for OPSEC improvements
- AV-specific evasion suggestions

---

## Quick Start

### 1. Get VirusTotal API Key

1. Register at https://www.virustotal.com/gui/join-us
2. Navigate to Profile → API Key
3. Copy your API key (Free tier: 4 requests/minute)

### 2. Set Environment Variable

```bash
# Add to ~/.bashrc or ~/.zshrc
export VT_API_KEY="your_api_key_here"

# Or set temporarily
export VT_API_KEY="your_api_key_here"
```

### 3. Use in AI Workflow

```
User: "Build a CrowdStrike bypass and test it"

AI:
1. search_intelligence("CrowdStrike bypass syscalls")
2. generate_code(["syscalls"], "CrowdStrike")
3. [Writes code using guidance]
4. compile_code(code, "crowdstrike_bypass")
5. test_detection("compiled/crowdstrike_bypass.exe", "CrowdStrike")
6. [Reviews detection results - 70+ AVs tested]
7. If detected: optimize_opsec() and rewrite
8. If clean: record_feedback(["syscalls"], "CrowdStrike", False)
```

---

## MCP Tool

### test_detection()

```python
test_detection(
    binary_path: str,
    target_av: str = None,
    environment: str = "Windows 10 64-bit"  # Ignored, kept for compatibility
) -> DetectionResult
```

**Tests against ALL 70+ AV engines simultaneously.**

**Parameters:**
- `binary_path`: Path to compiled binary
- `target_av`: Your primary target AV for OPSEC scoring
  - Used to calculate OPSEC score (penalizes if target detects it)
  - Used to highlight if YOUR target detected it
  - Used to tailor recommendations
- `environment`: Ignored (kept for API compatibility)

**Returns:**
```json
{
    "success": true,
    "detected": false,
    "verdict": "clean",
    "opsec_score": 9,
    "detection_count": 2,
    "suspicious_count": 1,
    "total_engines": 71,
    "detection_rate": "2.8%",
    "detected_by": [
        {"name": "Avira", "category": "malicious", "result": "TR/Crypt.XPACK.Gen"},
        {"name": "Jiangmin", "category": "suspicious", "result": "Trojan.Generic"}
    ],
    "target_av": "CrowdStrike",
    "target_detected": false,
    "recommendations": [
        "✅ Excellent! Very low detection rate (2.8%).",
        "✓ CrowdStrike did not detect the binary"
    ],
    "scan_date": "2025-10-08T12:34:56",
    "sha256": "abc123..."
}
```

---

## OPSEC Score

The system automatically calculates an OPSEC score (1-10) based on detection rate:

| Score | Meaning | Detection Rate |
|-------|---------|----------------|
| 9-10 | Excellent | 0-5% detected |
| 8 | Very Good | 5-10% detected |
| 7 | Good | 10-20% detected |
| 6 | Moderate | 20-30% detected |
| 5 | Fair | 30-50% detected |
| 3-4 | Poor | 50-70% detected |
| 1-2 | Failed | >70% detected |

**Penalties:**
- Target AV detection: **-2 points** (critical)
- >5 suspicious detections: **-1 point**

---

## Detection Results

### Verdict Types

- `clean` - No threats detected
- `suspicious` - Flagged by some engines
- `malicious` - Confirmed malicious by multiple engines

### Common AV Detections & Fixes

| AV Engine | Detection | Recommended Fix |
|-----------|-----------|-----------------|
| Windows Defender | Behavior monitoring | Use indirect syscalls + sleep obfuscation |
| CrowdStrike Falcon | User-mode hooks | NTDLL direct calls, avoid hooked APIs |
| Kaspersky | Heuristic analysis | String obfuscation + API hashing |
| Sophos | Process injection | Use thread pool injection (PoolParty) |
| Avira | Signature match | More obfuscation, change patterns |

### Recommendations

The system generates actionable recommendations:

**Critical:**
- "🚨 CRITICAL: Target AV detected the binary. Different evasion technique required."

**High Priority:**
- "⚠️ High detection rate (65%). Add obfuscation and anti-analysis."
- "💡 Windows Defender detected: Use indirect syscalls and sleep obfuscation"
- "💡 CrowdStrike detected: Avoid user-mode hooks, use NTDLL direct calls"

**Success:**
- "✅ Excellent! Very low detection rate (2.8%)."

---

## Caching

Results are cached for 7 days to:
- Avoid redundant API calls
- Save API quota (4 req/min limit)
- Speed up repeated tests

Cache location: `data/detection_cache/`

**Clear cache manually:**
```bash
rm -rf data/detection_cache/*.json
```

**Cache intelligence:**
- If file was already scanned by VirusTotal → instant results (no upload)
- If file is new → upload + wait 10-30 seconds for results

---

## Rate Limiting

VirusTotal free tier limits:
- **4 requests per minute**
- **1000 requests per day**
- Enforced automatically by SDK

**Upgrade options:**
- Free: 4 req/min, 1000 req/day
- Premium ($): Higher limits, private scanning
- Enterprise: Contact sales

**Smart usage:**
- First check: File hash lookup (instant if seen before)
- New file: Upload + scan (one API call)
- Results cached locally for 7 days

---

## Example Workflow

### Complete Test Cycle

```
# 1. User Request
User: "Build ransomware that evades Defender and test it"

# 2. AI Intelligence Gathering
AI calls: search_intelligence("ransomware Windows Defender evasion")
Returns: "Use AES encryption (OPSEC 8/10), indirect syscalls"

# 3. AI Code Generation
AI calls: generate_code(["encryption", "persistence"], "Windows Defender")
AI writes code using guidance

# 4. Compilation
AI calls: compile_code(ransomware_code, "defender_evade")
Returns: "compiled/defender_evade.exe"

# 5. Live Detection Testing (70+ AVs)
AI calls: test_detection("compiled/defender_evade.exe", "Windows Defender")

# 6. Results Analysis
Returns:
{
    "detected": true,
    "verdict": "malicious",
    "opsec_score": 4,
    "detection_count": 45,
    "total_engines": 71,
    "detection_rate": "63.4%",
    "target_detected": true,
    "recommendations": [
        "🚨 CRITICAL: Target AV (Defender) detected the binary.",
        "⚠️ High detection rate (63%). Add obfuscation and anti-analysis.",
        "💡 Windows Defender detected: Use indirect syscalls and sleep obfuscation",
        "💡 Multiple detections: Implement SysWhispers3, API hashing, string encryption"
    ]
}

# 7. AI Iteration
AI calls: optimize_opsec(ransomware_code, "Windows Defender")
AI rewrites code with:
- SysWhispers3 indirect syscalls
- API hashing
- String encryption
- Sleep obfuscation

# 8. Retest
AI calls: compile_code(improved_code, "defender_evade_v2")
AI calls: test_detection("compiled/defender_evade_v2.exe", "Windows Defender")

Returns:
{
    "detected": true,
    "verdict": "suspicious",
    "opsec_score": 7,
    "detection_count": 5,
    "total_engines": 71,
    "detection_rate": "7.0%",
    "target_detected": false,
    "recommendations": [
        "✓ Low detection rate (7.0%). Good OPSEC baseline.",
        "✅ Windows Defender did not detect the binary"
    ]
}

# 9. Success - Record Feedback
AI calls: record_feedback(["encryption", "syscalls"], "Windows Defender", False)
AI delivers: "Ransomware successfully bypasses Windows Defender (OPSEC 7/10, 7% detection rate)"
```

---

## Troubleshooting

### "No API key configured"

```bash
# Check if environment variable is set
echo $VT_API_KEY

# If empty, set it
export VT_API_KEY="your_key"

# Add to shell profile for persistence
echo 'export VT_API_KEY="your_key"' >> ~/.bashrc
source ~/.bashrc
```

### "Rate limit exceeded"

Free tier: 4 requests/minute. Space out tests.

**Solution:**
- Wait 15 seconds between tests (automatic)
- Upgrade to Premium tier
- Use caching (file hash lookups are instant)

### "vt-py not installed"

```bash
pip install vt-py
```

### Results take long time

- **New file:** 10-30 seconds (normal, waiting for scan)
- **Known file:** Instant (hash lookup)
- **Timeout:** Rare, increase wait time in code if needed

---

## CRITICAL: Don't Burn Your Technique

### **THE PROBLEM**

VirusTotal submissions are **PUBLIC**:
- AV vendors **actively monitor** VirusTotal for new samples
- Most popular malware analysis platform in the world
- Your undetected binary = free sample for AV vendors to signature
- Technique can be burned within **hours** of upload

### **THE SOLUTION**

**NEVER upload your final undetected version:**

```
❌ WRONG (Burns technique):
1. Test v1 → 60% detection
2. Test v2 → 30% detection
3. Test v3 → 5% detection (OPSEC 9/10) ← Uploaded to VirusTotal
4. AV vendors download your sample
5. Technique gets signatured within days
6. Your bypass no longer works

✅ RIGHT (Preserves technique):
1. Test v1 → 60% detection (safe to upload)
2. Test v2 → 30% detection (safe to upload)
3. Test v3 → 10% detection (getting close, OPSEC 7/10)
4. STOP TESTING - switch to validate_code() (local, no upload)
5. Deliver to user for offline testing
6. User: "Tested in controlled environment - works!"
7. record_feedback() - System learns WITHOUT burning
```

### **SAFE TESTING WORKFLOW**

```python
# Iteration 1
compile_code(code_v1)
test_detection("v1.exe", "CrowdStrike")  # 60% detected ✓ Safe

# Iteration 2
compile_code(code_v2)
test_detection("v2.exe", "CrowdStrike")  # 30% detected ✓ Safe

# Iteration 3 - Getting close (OPSEC 7)
compile_code(code_v3)
test_detection("v3.exe", "CrowdStrike")  # 10% detected ✓ Still safe

# Iteration 4 - OPSEC 8-9, STOP UPLOADING!
compile_code(code_v4)
validate_code(code_v4)  # LOCAL CHECK - NO UPLOAD ✓

# If validation looks good: STOP
# Deliver to user for real-world testing
# User tests in isolated/offline environment

# User confirms success:
record_feedback(["syscalls"], "CrowdStrike", detected=False)
# System learns without burning the technique!
```

### **WHEN IT'S SAFE TO UPLOAD**

Upload is safe when:
- ✅ Binary is DETECTED (>20% detection rate)
- ✅ OPSEC score < 7 (clearly detected, safe to iterate)
- ✅ Early iterations for testing

Upload is DANGEROUS when:
- ❌ Binary is UNDETECTED or low detection (<5%)
- ❌ OPSEC score 8+ (almost/fully working)
- ❌ Final version ready for deployment

---

## Best Practices

### 1. Test Early and Often

```
✅ Write 100 lines → Test → Iterate → Build incrementally
❌ Write 1000 lines → Test once → Detected → Rewrite everything
```

### 2. Stop at OPSEC 7-8

```
OPSEC 4-6: Keep testing and iterating (safe)
OPSEC 7-8: STOP uploading, switch to local validation
OPSEC 9-10: NEVER upload - you have a working technique!
```

### 3. Use Recommendations

```
AI should:
1. Read all detection results
2. Apply ALL recommendations
3. Retest after each major change
4. Record successful techniques via record_feedback()
```

### 4. Leverage Caching

```
Same file = Cached result (instant)
Modified file = New test
Known file hash = Instant lookup (no upload)
```

---

## Integration with Learning System

Detection results automatically feed back into RAG:

```python
# After test_detection() success
AI calls: record_feedback(
    technique_ids=["NOCTIS-T004"],  # Syscalls
    target_av="CrowdStrike Falcon",
    detected=False,
    details="OPSEC 9/10, 2% detection rate on VT"
)

# System updates:
- Technique effectiveness scores
- Detection patterns database
- RAG intelligence (indexed for future queries)

# Future searches benefit:
search_intelligence("CrowdStrike bypass")
# Now returns: "Syscalls effective (verified 2025-10-08, OPSEC 9/10, 2% VT detection)"
```

---

## Python API

For advanced usage or scripting:

```python
from server.detection_testing import DetectionTester

# Initialize
tester = DetectionTester(api_key="your_key")  # or use VT_API_KEY env var

# Test binary
result = tester.test_binary(
    binary_path="payload.exe",
    target_av="CrowdStrike Falcon"
)

# Check results
if result['success']:
    print(f"Detected: {result['detected']}")
    print(f"OPSEC Score: {result['opsec_score']}/10")
    print(f"Detection Rate: {result['detection_rate']}")
    print(f"Target AV Result: {result['target_detected']}")

    for rec in result['recommendations']:
        print(f"{rec}")
else:
    print(f"Error: {result['error']}")
```

---

## Security Considerations

### API Key Security

```bash
# ✅ Good: Environment variable
export VT_API_KEY="key"

# ❌ Bad: Hardcoded in code
api_key = "my_secret_key_123"  # Never do this!

# ✅ Good: .env file (not committed)
echo "VT_API_KEY=key" > .env
# Add to .gitignore
```

### Binary Upload

Binaries uploaded to VirusTotal are:
- Analyzed by 70+ AV engines
- Stored on VirusTotal servers permanently
- **Publicly accessible** (searchable by hash)
- **Downloaded by AV vendors** for signature development

**For private analysis:**
- Use VirusTotal private API (paid)
- Or test locally with local AV/EDR
- Or use private malware analysis platforms

**Best practice:**
- Only upload early iterations (high detection = already burned)
- Stop uploading when OPSEC 7+ achieved
- Final working versions: NEVER upload to VirusTotal

---

## VirusTotal vs Local Testing

| Feature | VirusTotal | Local Testing |
|---------|------------|---------------|
| AV Coverage | 70+ engines | 1 engine |
| Speed | 10-30 seconds | Instant |
| Privacy | Public | Private |
| Cost | Free (limits) | Free |
| Best For | Broad testing | Final validation |

**Recommended workflow:**
1. Early iterations (60-30% detection): VirusTotal ✓
2. Mid iterations (30-10% detection): VirusTotal ✓
3. Late iterations (<10% detection): Local testing only ✓
4. Final version: NEVER upload, local testing only ✓

---

## Resources

- **VirusTotal:** https://www.virustotal.com
- **API Documentation:** https://docs.virustotal.com/reference/overview
- **Rate Limits:** https://docs.virustotal.com/docs/rate-limits
- **vt-py Library:** https://github.com/VirusTotal/vt-py

---

**Built for security research. Use responsibly.**
