# Architecture

Technical architecture and design decisions for Noctis-MCP.

## System Overview

Noctis-MCP follows a three-tier architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                    Presentation Layer                        │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │  MCP Client  │  │  REST Client │  │  Direct Python  │  │
│  │  (AI Chat)   │  │  (HTTP API)  │  │  (Library)      │  │
│  └──────────────┘  └──────────────┘  └─────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP/REST
┌──────────────────────────┼──────────────────────────────────┐
│                    Application Layer                         │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              noctis_server.py (Flask)                  │ │
│  │                                                        │ │
│  │  Routes:                                               │ │
│  │  - /api/generate          Code generation            │ │
│  │  - /api/compile           Compilation                │ │
│  │  - /api/c2/*              C2 beacon generation       │ │
│  │  - /api/techniques/*      Technique queries          │ │
│  │  - /api/analyze/opsec     Security analysis          │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────┼──────────────────────────────────┐
│                     Service Layer                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │Technique │  │   Code   │  │ Compiler │  │    C2     │  │
│  │ Engine   │  │Assembler │  │  Engine  │  │  Adapter  │  │
│  └──────────┘  └──────────┘  └──────────┘  └───────────┘  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │Obfuscate │  │Polymorphic│  │  OPSEC   │  │  Testing  │  │
│  │ Engine   │  │  Engine  │  │ Analyzer │  │  Engine   │  │
│  └──────────┘  └──────────┘  └──────────┘  └───────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────┼──────────────────────────────────┐
│                      Data Layer                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │Technique │  │  Source  │  │ Compiled │  │    C2     │  │
│  │Metadata  │  │   Code   │  │ Binaries │  │  Configs  │  │
│  │  (JSON)  │  │  (C/C++) │  │  (PE)    │  │  (YAML)   │  │
│  └──────────┘  └──────────┘  └──────────┘  └───────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. API Server (`server/noctis_server.py`)

**Purpose**: Central HTTP/REST API providing all functionality

**Design**:
- Flask web framework
- RESTful endpoints
- JSON request/response format
- CORS enabled for cross-origin requests
- Logging and error handling

**Key Endpoints**:
```python
POST /api/generate              # Generate malware code
POST /api/compile               # Compile code to binary
POST /api/c2/sliver/generate    # Generate Sliver beacon
POST /api/c2/havoc/generate     # Generate Havoc demon
POST /api/c2/mythic/generate    # Generate Mythic agent
GET  /api/techniques            # List all techniques
GET  /api/techniques/{id}       # Get technique details
POST /api/analyze/opsec         # Analyze OPSEC
GET  /api/stats                 # Server statistics
```

### 2. Technique Library (`techniques/`)

**Purpose**: Catalog of malware techniques with metadata

**Structure**:
```
techniques/
├── metadata/
│   ├── index.json              # Master index
│   ├── api_hashing.json        # API obfuscation techniques
│   ├── syscalls.json           # Syscall techniques
│   ├── injection.json          # Code injection
│   ├── encryption.json         # Encryption methods
│   ├── steganography.json      # Steganography
│   ├── persistence.json        # Persistence mechanisms
│   └── unhooking.json          # EDR unhooking
└── [source files referenced in metadata]
```

**Metadata Format**:
```json
{
  "technique_id": "NOCTIS-T001",
  "name": "API Hashing (DJB2)",
  "category": "api_hashing",
  "mitre_attack": ["T1027", "T1106"],
  "source_files": ["path/to/implementation.c"],
  "functions": ["HashString", "GetProcAddressByHash"],
  "dependencies": ["windows.h", "kernel32.dll"],
  "compatible_with": ["indirect_syscalls", "encryption"],
  "incompatible_with": [],
  "opsec": {
    "detection_risk": "low",
    "stability": "high",
    "tested_on": ["Win10 21H2", "Win11 22H2"]
  }
}
```

### 3. Code Assembler (`server/code_assembler.py`)

**Purpose**: Intelligently combine techniques into working code

**Algorithm**:
```python
def assemble_code(technique_ids: List[str]) -> str:
    # 1. Load technique metadata
    techniques = load_techniques(technique_ids)
    
    # 2. Validate compatibility
    check_conflicts(techniques)
    
    # 3. Resolve dependencies
    ordered = resolve_dependencies(techniques)
    
    # 4. Extract source code
    functions = extract_functions(ordered)
    
    # 5. Deduplicate
    unique = deduplicate(functions)
    
    # 6. Generate unified code
    code = generate_code(unique)
    
    return code
```

**Features**:
- Function extraction from source files
- Header deduplication
- Dependency ordering
- Conflict detection
- Code formatting

### 4. Compilation Engine (`compilation/`)

**Purpose**: Cross-platform compilation of C/C++ code

**Design**: Platform abstraction with two implementations

**Windows** (`windows_compiler.py`):
- MSBuild integration
- Visual Studio project generation
- x64/x86 architecture support
- Optimization levels (O0-O3)

**Linux** (`linux_compiler.py`):
- MinGW-w64 cross-compilation
- PE executable generation
- Windows API support
- Same architecture/optimization options

**API**:
```python
from compilation import get_compiler

compiler = get_compiler(output_dir='compiled')
result = compiler.compile(
    source_code=code,
    architecture='x64',
    optimization='O2',
    output_name='loader'
)

if result['success']:
    print(f"Binary: {result['binary_path']}")
```

### 5. C2 Adapters (`c2_adapters/`)

**Purpose**: Integration with C2 frameworks

**Design**: Abstract base class with framework-specific implementations

**Class Hierarchy**:
```
C2Adapter (Abstract)
├── SliverAdapter
├── HavocAdapter
└── MythicAdapter
```

**Base Interface**:
```python
class C2Adapter(ABC):
    @abstractmethod
    def connect(self) -> bool:
        """Test connection to C2 server"""
        
    @abstractmethod
    def generate_shellcode(self, output_path: str) -> Tuple[bool, str]:
        """Generate C2 shellcode"""
        
    @abstractmethod
    def validate_config(self) -> Tuple[bool, List[str]]:
        """Validate configuration"""
```

**Adapter Responsibilities**:
1. Connect to C2 server
2. Generate raw shellcode/beacon
3. Wrap shellcode with Noctis techniques
4. Apply obfuscation
5. Compile final binary
6. Return beacon path and metadata

### 6. Obfuscation Pipeline (`server/obfuscation/`)

**Purpose**: Apply evasion techniques to code

**Modules**:

**String Encryption** (`string_encryption.py`):
- Methods: XOR, AES, RC4
- Runtime decryption
- Key generation

**API Hashing** (`api_hashing.py`):
- Algorithms: DJB2, ROT13+XOR, CRC32
- Import table obfuscation
- Dynamic resolution

**Control Flow** (`control_flow.py`):
- Control flow flattening
- Opaque predicates
- Junk code insertion

**Example**:
```python
from server.obfuscation.string_encryption import StringEncryptor
from server.obfuscation.api_hashing import APIHasher

# Encrypt strings
encryptor = StringEncryptor(method='aes')
encrypted_code = encryptor.encrypt_code(source_code)

# Hash API calls
hasher = APIHasher(algorithm='djb2')
hashed_code = hasher.hash_apis(encrypted_code)
```

### 7. Polymorphic Engine (`server/polymorphic/`)

**Purpose**: Generate unique code variants

**Design**: AST-based code transformation

**Mutations**:
- Variable renaming
- Function reordering
- Junk code insertion
- Instruction substitution
- Dead code elimination

**API**:
```python
from server.polymorphic.engine import PolymorphicEngine

engine = PolymorphicEngine()
variant = engine.generate_variant(
    source_code=code,
    mutation_level='high'
)
```

### 8. OPSEC Analyzer (`server/opsec_analyzer.py`)

**Purpose**: Analyze binaries for detection vectors

**Analysis**:
- String scanning (API names, debug strings)
- Import table analysis
- Entropy calculation
- Memory pattern detection
- Signature matching

**Scoring**:
- 0-10 scale
- Weighted by severity
- Actionable recommendations

**API**:
```python
from server.opsec_analyzer import analyze_opsec

result = analyze_opsec(binary_path='loader.exe')
# Returns: {
#   'score': 8.5,
#   'issues': [...],
#   'recommendations': [...]
# }
```

### 9. MCP Client (`noctis_mcp_client/noctis_mcp.py`)

**Purpose**: AI interface using Model Context Protocol

**Design**: FastMCP wrapper exposing tools to AI

**Tools** (14 total):
```python
@mcp.tool()
def query_techniques(category=None, mitre_ttp=None, search=None):
    """Query technique database"""

@mcp.tool()
def generate_malware(techniques, target_os, target_av, ...):
    """Generate malware code"""

@mcp.tool()
def compile_code(source_code, architecture, optimization, ...):
    """Compile code to binary"""

@mcp.tool()
def generate_sliver_beacon(listener_host, listener_port, ...):
    """Generate Sliver beacon"""

# ... 10 more tools
```

## Data Flow

### Malware Generation Flow

```
1. User Request
   │
   ↓
2. MCP Client receives request
   │
   ↓
3. POST /api/generate
   │  {
   │    "techniques": ["NOCTIS-T124", "NOCTIS-T118"],
   │    "target_os": "Windows 11",
   │    "obfuscate": true
   │  }
   │
   ↓
4. Technique Engine
   │  - Load technique metadata
   │  - Validate compatibility
   │  - Order by dependencies
   │
   ↓
5. Code Assembler
   │  - Extract functions from source
   │  - Deduplicate headers
   │  - Generate unified code
   │
   ↓
6. Obfuscation Pipeline
   │  - Encrypt strings
   │  - Hash API calls
   │  - Flatten control flow
   │
   ↓
7. POST /api/compile
   │  {
   │    "source_code": "...",
   │    "architecture": "x64"
   │  }
   │
   ↓
8. Compilation Engine
   │  - Generate project files
   │  - Invoke compiler (MSBuild/MinGW)
   │  - Capture output
   │
   ↓
9. OPSEC Analysis
   │  - Scan binary
   │  - Calculate score
   │  - Generate report
   │
   ↓
10. Return Result
    {
      "success": true,
      "binary_path": "compiled/loader.exe",
      "opsec_score": 8.5,
      "techniques_applied": [...],
      "compilation_time": 2.3
    }
```

### C2 Beacon Generation Flow

```
1. User Request
   │  generate_sliver_beacon(...)
   │
   ↓
2. POST /api/c2/sliver/generate
   │
   ↓
3. SliverAdapter
   │  - Connect to Sliver server
   │  - Generate shellcode
   │
   ↓
4. ShellcodeWrapper
   │  - Load Noctis techniques
   │  - Wrap shellcode
   │
   ↓
5. Obfuscation Pipeline
   │  - Apply techniques
   │
   ↓
6. Compilation
   │  - Compile beacon
   │
   ↓
7. Return beacon + metadata
```

## Design Decisions

### Why Flask?
- Lightweight, easy to deploy
- Excellent REST API support
- Large ecosystem
- Easy testing

### Why MinGW for Linux?
- Cross-compile Windows PE from Linux
- No Windows license required
- Fast compilation
- Full Windows API support

### Why JSON for Technique Metadata?
- Human-readable
- Easy parsing
- Schema validation
- Version control friendly

### Why Abstract Base Classes for C2?
- Enforces consistent interface
- Easy to add new frameworks
- Type checking
- Clear contracts

### Why Separate Compilation Engine?
- Platform independence
- Easy testing
- Clear separation of concerns
- Can add new compilers easily

## Performance Considerations

### Compilation Time

**Windows (MSBuild)**:
- Simple loader: ~3-5 seconds
- Complex project: ~10-15 seconds

**Linux (MinGW)**:
- Simple loader: ~1-2 seconds
- Complex project: ~3-5 seconds

### Optimization

1. **Caching**: Compiled binaries cached by source hash
2. **Parallel Compilation**: Multiple projects can compile simultaneously
3. **Incremental Builds**: Only recompile changed files
4. **Code Deduplication**: Reduces final binary size

### Scalability

- **Concurrent Requests**: Flask supports multiple workers
- **Stateless Design**: No session state maintained
- **Database-Free**: All data in files (fast I/O)
- **Resource Limits**: Configurable memory/CPU limits

## Security Architecture

### Threat Model

**In Scope**:
- Malicious input to API
- Path traversal attacks
- Code injection
- Resource exhaustion

**Out of Scope**:
- Network-level attacks
- Physical access
- Social engineering

### Mitigations

1. **Input Validation**: All API inputs sanitized
2. **Path Sanitization**: Only write to designated directories
3. **Resource Limits**: Compilation timeouts
4. **Sandboxing**: Compilation in isolated environment
5. **Logging**: All operations logged

## Testing Strategy

### Unit Tests
- Individual component testing
- Mock external dependencies
- Fast execution (<1 second per test)

### Integration Tests
- End-to-end workflows
- Real C2 server communication (optional)
- Actual compilation

### Test Coverage
- 186 total tests
- 49 integration tests
- 100% pass rate

## Future Architecture Considerations

### Potential Enhancements

1. **Database Backend**: PostgreSQL for technique metadata
2. **Caching Layer**: Redis for compiled artifacts
3. **Message Queue**: Celery for async compilation
4. **Load Balancer**: Multiple server instances
5. **Container Deployment**: Docker/Kubernetes
6. **Web Dashboard**: React/Vue frontend

### Scalability Path

```
Current: Single Flask server
  ↓
Phase 1: Multiple workers (Gunicorn)
  ↓
Phase 2: Multiple servers + load balancer
  ↓
Phase 3: Distributed compilation (Celery)
  ↓
Phase 4: Microservices architecture
```

---

**Last Updated**: October 3, 2025  
**Version**: 1.0.0

