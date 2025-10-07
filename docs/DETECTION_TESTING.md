# Live Detection Testing with Hybrid Analysis

## Overview

Noctis-MCP integrates with Hybrid Analysis to provide live malware detection testing against real AV/EDR solutions. This validates if generated malware actually evades target defenses.

**Status:** Production Ready
**API:** Hybrid Analysis v2
**Tool:** `test_detection()`

---

## Features

- Upload binaries to Hybrid Analysis sandbox
- Test against specific AV/EDR configurations
- Get detection verdicts and triggered signatures
- Automated OPSEC score calculation (1-10 scale)
- Smart caching (7-day TTL) to avoid redundant uploads
- Actionable recommendations for OPSEC improvements

---

## Quick Start

### 1. Get Hybrid Analysis API Key

1. Register at https://www.hybrid-analysis.com/signup
2. Navigate to Profile → API Key
3. Copy your API key

### 2. Set Environment Variable

```bash
# Add to ~/.bashrc or ~/.zshrc
export HYBRID_ANALYSIS_API_KEY="your_api_key_here"

# Or set temporarily
export HYBRID_ANALYSIS_API_KEY="your_api_key_here"
```

### 3. Use in AI Workflow

```
User: "Build a CrowdStrike bypass and test it"

AI:
1. search_intelligence("CrowdStrike bypass syscalls")
2. generate_code(["syscalls"], "CrowdStrike")
3. [Writes code using guidance]
4. compile_code(code, "crowdstrike_bypass")
5. test_detection("compiled/crowdstrike_bypass.exe", "CrowdStrike Falcon")
6. [Reviews detection results]
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
    environment: str = "Windows 10 64-bit"
) -> DetectionResult
```

**Parameters:**
- `binary_path`: Path to compiled binary
- `target_av`: Target AV name (e.g., "CrowdStrike Falcon", "Windows Defender")
- `environment`: OS environment (Windows 7/10/11, Linux)

**Returns:**
```json
{
    "success": true,
    "detected": false,
    "verdict": "no_threats",
    "opsec_score": 9,
    "threat_score": 5,
    "av_detections": 0,
    "detected_by": [],
    "target_av": "CrowdStrike Falcon",
    "target_detected": false,
    "signatures": [],
    "behavioral_alerts": [],
    "recommendations": [
        "Good OPSEC! Binary shows low detection rates."
    ],
    "environment": "Windows 10 64-bit (v2004, Build 19041)",
    "sha256": "abc123..."
}
```

---

## OPSEC Score

The system automatically calculates an OPSEC score (1-10) based on multiple factors:

| Score | Meaning | Criteria |
|-------|---------|----------|
| 9-10 | Excellent | Undetected, no/minimal signatures |
| 7-8 | Good | Low detections, suspicious verdict |
| 5-6 | Moderate | Some detections, malicious verdict |
| 3-4 | Poor | Heavy detections across multiple AVs |
| 1-2 | Failed | Detected by target AV + widespread |

**Calculation Factors:**
- Verdict (malicious/suspicious/clean)
- Threat score (0-100 from Hybrid Analysis)
- Number of AV detections
- Target AV detection (critical factor)
- Triggered behavioral signatures

---

## Detection Results

### Verdict Types

- `no_threats` - Clean, no threats detected
- `suspicious` - Flagged for suspicious behavior
- `malicious` - Confirmed malicious
- `unknown` - Analysis inconclusive

### Signatures

Common triggered signatures and their meanings:

| Signature | Meaning | Fix |
|-----------|---------|-----|
| `CreateRemoteThread API` | Classic injection detected | Use NtCreateThreadEx or thread hijacking |
| `RWX memory allocation` | Suspicious memory pattern | Use RW → RX with VirtualProtect |
| `Suspicious API usage` | API patterns match known malware | Implement API hashing or syscalls |
| `String signatures` | Static strings detected | Encrypt strings at compile time |

### Recommendations

The system generates actionable recommendations:

**Critical:**
- "CRITICAL: Target AV detected the binary. Consider different evasion technique."

**High Priority:**
- "Multiple AV detections. Add obfuscation and anti-analysis techniques."
- "Avoid CreateRemoteThread - use NtCreateThreadEx or thread hijacking instead"
- "RWX memory detected - use RW → RX pattern with VirtualProtect"

**Standard:**
- "Suspicious API usage - implement API hashing or indirect syscalls"
- "String signatures detected - encrypt strings at compile time"

**Success:**
- "Good OPSEC! Binary shows low detection rates."

---

## Caching

Results are cached for 7 days to:
- Avoid redundant API calls
- Save API quota
- Speed up repeated tests

Cache location: `data/detection_cache/`

**Clear cache manually:**
```bash
rm -rf data/detection_cache/*.json
```

---

## Rate Limiting

Hybrid Analysis free tier limits:
- 100 requests per hour
- Enforced automatically by SDK
- Rate limit: 36 seconds between requests

**Upgrade options:**
- Community (Free): 100 req/hour
- Professional ($99/month): 1000 req/hour
- Enterprise: Contact sales

---

## Example Workflow

### Complete Test Cycle

```
# 1. User Request
User: "Build ransomware that evades Defender and test it"

# 2. AI Intelligence Gathering
AI calls: search_intelligence("ransomware Windows Defender evasion")
Returns: "Use AES encryption (OPSEC 8/10), Avoid obvious ransom notes"

# 3. AI Code Generation
AI calls: generate_code(["encryption", "persistence"], "Windows Defender")
AI writes code using guidance

# 4. Compilation
AI calls: compile_code(ransomware_code, "defender_evade")
Returns: "compiled/defender_evade.exe"

# 5. Live Detection Testing
AI calls: test_detection("compiled/defender_evade.exe", "Windows Defender")

# 6. Results Analysis
Returns:
{
    "detected": true,
    "verdict": "malicious",
    "opsec_score": 4,
    "target_detected": true,
    "signatures": [
        {"name": "Suspicious file encryption loop", "severity": "high"},
        {"name": "Registry persistence modification", "severity": "medium"}
    ],
    "recommendations": [
        "CRITICAL: Target AV detected the binary.",
        "File encryption pattern detected - randomize encryption block sizes",
        "Registry persistence detected - use alternative methods"
    ]
}

# 7. AI Iteration
AI calls: optimize_opsec(ransomware_code, "Windows Defender")
AI rewrites code with:
- Variable encryption block sizes
- WMI-based persistence instead of registry
- More obfuscation

# 8. Retest
AI calls: compile_code(improved_code, "defender_evade_v2")
AI calls: test_detection("compiled/defender_evade_v2.exe", "Windows Defender")

Returns:
{
    "detected": false,
    "verdict": "no_threats",
    "opsec_score": 9,
    "target_detected": false
}

# 9. Success - Record Feedback
AI calls: record_feedback(["encryption", "persistence"], "Windows Defender", False)
AI delivers: "Ransomware successfully bypasses Windows Defender (OPSEC 9/10)"
```

---

## Troubleshooting

### "No API key configured"

```bash
# Check if environment variable is set
echo $HYBRID_ANALYSIS_API_KEY

# If empty, set it
export HYBRID_ANALYSIS_API_KEY="your_key"

# Add to shell profile for persistence
echo 'export HYBRID_ANALYSIS_API_KEY="your_key"' >> ~/.bashrc
source ~/.bashrc
```

### "Rate limit exceeded"

Wait 36 seconds between requests. Free tier: 100 req/hour.

**Solution:** Upgrade to Professional tier or space out tests.

### "Submission failed"

Common causes:
- Invalid API key
- File size too large (>100MB)
- Invalid file format
- Network connectivity issues

**Debug:**
```python
from server.detection_testing import test_file

# Test with error output
result = test_file("malware.exe", "CrowdStrike")
print(result)
```

### "Analysis timeout"

Analysis can take 5-10 minutes. Default timeout: 10 minutes.

**Increase timeout:**
```python
from server.detection_testing import DetectionTester

tester = DetectionTester()
result = tester.test_binary(
    "malware.exe",
    target_av="CrowdStrike",
    max_wait=1800  # 30 minutes
)
```

---

## Best Practices

### 1. Test Early and Often

```
Don't wait until final version:
❌ Write 1000 lines → Test once → Detected → Rewrite everything
✅ Write 100 lines → Test → Iterate → Build incrementally
```

### 2. Test Against Target AV First

```
Prioritize testing:
1. Target AV (e.g., CrowdStrike for specific client)
2. Common AVs (Defender, Symantec, McAfee)
3. Obscure AVs (optional)
```

### 3. Use Recommendations

```
AI should:
1. Read all triggered signatures
2. Apply ALL recommendations
3. Retest after each major change
4. Record successful techniques via record_feedback()
```

### 4. Leverage Caching

```
Same binary = Cached result (instant)
Modified binary = New test
Cache valid for 7 days
```

### 5. Monitor API Quota

```
Free tier: 100 req/hour
Test strategically:
- Test after significant changes only
- Use validate_code() first (free, local)
- Use test_detection() for final validation
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
    details="OPSEC 9/10, undetected in sandbox"
)

# System updates:
- Technique effectiveness scores
- Detection patterns database
- RAG intelligence (indexed for future queries)

# Future searches benefit:
search_intelligence("CrowdStrike bypass")
# Now returns: "Syscalls effective (verified 2024-10-07, OPSEC 9/10)"
```

---

## Python API

For advanced usage or scripting:

```python
from server.detection_testing import DetectionTester

# Initialize
tester = DetectionTester(api_key="your_key")  # or use env var

# Test binary
result = tester.test_binary(
    binary_path="payload.exe",
    target_av="CrowdStrike Falcon",
    environment="Windows 10 64-bit"
)

# Check results
if result['success']:
    print(f"Detected: {result['detected']}")
    print(f"OPSEC Score: {result['opsec_score']}/10")
    print(f"Target AV Result: {result['target_detected']}")

    for rec in result['recommendations']:
        print(f"- {rec}")
else:
    print(f"Error: {result['error']}")
```

---

## Security Considerations

### API Key Security

```bash
# ✅ Good: Environment variable
export HYBRID_ANALYSIS_API_KEY="key"

# ❌ Bad: Hardcoded in code
api_key = "my_secret_key_123"  # Never do this!

# ✅ Good: .env file (not committed)
echo "HYBRID_ANALYSIS_API_KEY=key" > .env
# Add to .gitignore
```

### Binary Upload

Binaries uploaded to Hybrid Analysis are:
- Analyzed in isolated VMs
- Stored on Hybrid Analysis servers
- Publicly accessible (community submissions)

**For private analysis:**
- Use Hybrid Analysis private submission (paid)
- Or test locally with local AV/EDR
- Or use private malware analysis platforms

---

## Limitations

- **Free tier quota:** 100 requests/hour
- **Analysis time:** 5-10 minutes per submission
- **Public submissions:** Results visible to community
- **AV coverage:** Limited to AVs installed in sandbox
- **False negatives:** Sandbox environment may differ from production
- **No macOS/Linux malware testing:** Windows focus

---

## Future Enhancements

Planned features:
- VirusTotal integration (multi-AV testing)
- ANY.RUN integration (interactive sandbox)
- Local AV testing (offline mode)
- Automated rewriting based on detection
- Historical detection tracking
- Custom sandbox configurations

---

## Resources

- **Hybrid Analysis:** https://www.hybrid-analysis.com
- **API Documentation:** https://www.hybrid-analysis.com/docs/api/v2
- **Rate Limits:** https://www.hybrid-analysis.com/docs/api/v2#rate-limit
- **Support:** support@hybrid-analysis.com

---

**Built for security research. Use responsibly.**
