# Architecture - Noctis-MCP v2.0
## AI-Driven Malware Development Platform

**Last Updated:** October 4, 2025
**Version:** 2.0.0-alpha

---

## Table of Contents
1. [System Overview](#system-overview)
2. [Agent Architecture (v2.0)](#agent-architecture-v20)
3. [Core Components](#core-components)
4. [Data Flow](#data-flow)
5. [MCP Integration](#mcp-integration)
6. [Design Decisions](#design-decisions)

---

## System Overview

Noctis-MCP v2.0 uses a **four-tier agent-based architecture**:

```
=================================================================
|                     Presentation Layer                        |
|  +--------------+  +--------------+  +-------------------+    |
|  |  MCP Client  |  |  REST Client |  |  Direct Python    |    |
|  |  (AI Chat)   |  |  (HTTP API)  |  |  (Library)        |    |
|  +--------------+  +--------------+  +-------------------+    |
=================================================================
                           | HTTP/REST
=================================================================
|                     Application Layer                         |
|  +--------------------------------------------------------+   |
|  |              noctis_server.py (Flask)                  |   |
|  |                                                        |   |
|  |  Agent Endpoints (V2):                                |   |
|  |  - /api/v2/agents/technique-selection                 |   |
|  |  - /api/v2/agents/malware-development                 |   |
|  |  - /api/v2/agents/opsec-optimization                  |   |
|  |  - /api/v2/agents/learning                            |   |
|  |  - /api/v2/agents/status                              |   |
|  |                                                        |   |
|  |  Legacy Endpoints:                                     |   |
|  |  - /api/generate          Code generation             |   |
|  |  - /api/compile           Compilation                 |   |
|  |  - /api/techniques/*      Technique queries           |   |
|  |  - /api/analyze/opsec     OPSEC analysis              |   |
|  |  - /api/c2/*              C2 beacon generation        |   |
|  +--------------------------------------------------------+   |
=================================================================
                           |
=================================================================
|                      Agent Layer (NEW v2.0)                   |
|  +--------------------------------------------------------+   |
|  |                  Agent Registry                        |   |
|  |  (Centralized management & lazy initialization)       |   |
|  +--------------------------------------------------------+   |
|  +--------------+  +--------------+  +-------------------+    |
|  | Technique    |  |   Malware    |  |     OPSEC         |    |
|  | Selection    |  |  Development |  |  Optimization     |    |
|  |    Agent     |  |     Agent    |  |      Agent        |    |
|  +--------------+  +--------------+  +-------------------+    |
|  +--------------+                                             |
|  |   Learning   |                                             |
|  |     Agent    |                                             |
|  +--------------+                                             |
=================================================================
                           |
=================================================================
|                      Service Layer                            |
|  +----------+  +----------+  +----------+  +-----------+      |
|  |Technique |  |   Code   |  | Compiler |  |    C2     |      |
|  | Engine   |  |Assembler |  |  Engine  |  |  Adapter  |      |
|  +----------+  +----------+  +----------+  +-----------+      |
|  +----------+  +----------+  +----------+  +-----------+      |
|  |Obfuscate |  |Polymorphic|  |  OPSEC   |  |  Testing  |      |
|  | Engine   |  |  Engine  |  | Analyzer |  |  Engine   |      |
|  +----------+  +----------+  +----------+  +-----------+      |
=================================================================
                           |
=================================================================
|                      Data Layer                               |
|  +----------+  +----------+  +----------+  +-----------+      |
|  |Technique |  |  Source  |  | Compiled |  |    C2     |      |
|  |Metadata  |  |   Code   |  | Binaries |  |  Configs  |      |
|  |  (JSON)  |  |  (C/C++) |  |  (PE)    |  |  (YAML)   |      |
|  +----------+  +----------+  +----------+  +-----------+      |
|  +----------+  +----------+                                   |
|  | Learning |  | OPSEC    |                                   |
|  | Database |  |  Scores  |                                   |
|  | (SQLite) |  |  (JSON)  |                                   |
|  +----------+  +----------+                                   |
=================================================================
```

---

## Agent Architecture (v2.0)

### **NEW: Professional Agent System**

The v2.0 release introduces a complete agent-based architecture inspired by modern AI frameworks.

### **Key Features:**
- ❌ Removed 21 confusing MCP tools
- ✅ Added 4 specialized AI agents
- ✅ Simplified to 8 intuitive MCP tools
- ✅ Professional lifecycle management
- ✅ Centralized agent registry

---

### **1. Base Agent Architecture**

**File:** `server/agents/base_agent.py`

All agents inherit from `BaseAgent` abstract base class:

```python
@dataclass
class AgentResult:
    """Standard result format for all agents"""
    success: bool
    data: Dict[str, Any]
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

class BaseAgent(ABC):
    """Abstract base class for all agents"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = logging.getLogger(f"Agent.{self.__class__.__name__}")
        self.metrics = {'executions': 0, 'successes': 0, 'failures': 0}

    @abstractmethod
    def execute(self, **kwargs) -> AgentResult:
        """Main execution logic - must be implemented by subclasses"""
        pass

    def run(self, **kwargs) -> AgentResult:
        """Lifecycle wrapper with validation, metrics, and error handling"""
        start_time = time.time()
        self.metrics['executions'] += 1

        try:
            # Validation
            self._validate_params(kwargs)

            # Initialize
            self._initialize()

            # Execute
            result = self.execute(**kwargs)

            # Cleanup
            self._cleanup()

            # Update metrics
            if result.success:
                self.metrics['successes'] += 1
            else:
                self.metrics['failures'] += 1

            result.execution_time = time.time() - start_time
            return result

        except Exception as e:
            self.metrics['failures'] += 1
            return AgentResult(
                success=False,
                data={},
                errors=[str(e)],
                execution_time=time.time() - start_time
            )
```

**Features:**
- Standard result format
- Lifecycle management (init → execute → cleanup)
- Automatic metrics tracking
- Error handling & logging
- Validation framework

---

### **2. Agent Registry**

**File:** `server/agents/__init__.py`

Centralized agent management with lazy initialization:

```python
class AgentRegistry:
    """Singleton registry for all agents"""

    _instances: Dict[str, BaseAgent] = {}
    _config: Dict = {}

    @classmethod
    def initialize(cls, config: Dict):
        """Initialize registry with configuration"""
        cls._config = config

    @classmethod
    def get_agent(cls, agent_type: str) -> BaseAgent:
        """Get or create agent instance (lazy initialization)"""
        if agent_type not in cls._instances:
            cls._instances[agent_type] = cls._create_agent(agent_type)
        return cls._instances[agent_type]

    @classmethod
    def _create_agent(cls, agent_type: str) -> BaseAgent:
        """Factory method for agent creation"""
        agent_map = {
            'technique_selection': TechniqueSelectionAgent,
            'malware_development': MalwareDevelopmentAgent,
            'opsec_optimization': OpsecOptimizationAgent,
            'learning': LearningAgent
        }

        agent_class = agent_map.get(agent_type)
        if not agent_class:
            raise ValueError(f"Unknown agent type: {agent_type}")

        return agent_class(cls._config)
```

**Features:**
- Singleton pattern - one instance per agent type
- Lazy initialization - agents created on first use
- Centralized configuration
- Type safety with factory pattern

---

### **3. The Four Agents**

#### **A. TechniqueSelectionAgent**

**File:** `server/agents/technique_selection_agent.py`

**Purpose:** AI-powered technique selection based on effectiveness scores and MITRE ATT&CK coverage.

**Key Logic:**
```python
def execute(self, **kwargs) -> AgentResult:
    target_av = kwargs.get('target_av', 'Windows Defender')
    objective = kwargs.get('objective', 'evasion')
    complexity = kwargs.get('complexity', 'medium')
    max_techniques = kwargs.get('max_techniques', 5)

    # 1. Load all techniques
    all_techniques = self._load_techniques()

    # 2. Filter by category and objective
    filtered = self._filter_by_objective(all_techniques, objective)

    # 3. Score each technique against target AV
    scored_techniques = []
    for tech in filtered:
        score = self.learning_engine.get_effectiveness_score(
            tech['technique_id'],
            target_av
        )
        scored_techniques.append((tech, score))

    # 4. Sort by score and select top N
    scored_techniques.sort(key=lambda x: x[1], reverse=True)
    selected = scored_techniques[:max_techniques]

    # 5. Check compatibility
    compatibility = self._check_compatibility(selected)

    # 6. Calculate MITRE coverage
    mitre_coverage = self._calculate_mitre_coverage(selected)

    # 7. Generate rationale
    rationale = self._generate_rationale(selected, target_av, objective)

    return AgentResult(
        success=True,
        data={
            'selected_techniques': [t[0]['technique_id'] for t in selected],
            'scores': {t[0]['technique_id']: t[1] for t in selected},
            'technique_details': [t[0] for t in selected],
            'compatibility_matrix': compatibility,
            'mitre_coverage': mitre_coverage,
            'rationale': rationale
        }
    )
```

**Output Example:**
```json
{
  "success": true,
  "data": {
    "selected_techniques": ["NOCTIS-T006", "NOCTIS-T004", "NOCTIS-T009"],
    "scores": {
      "NOCTIS-T006": 0.95,
      "NOCTIS-T004": 0.92,
      "NOCTIS-T009": 0.91
    },
    "compatibility_matrix": {...},
    "mitre_coverage": {...},
    "rationale": "Selected 3 techniques optimized for Windows Defender..."
  }
}
```

---

#### **B. MalwareDevelopmentAgent**

**File:** `server/agents/malware_development_agent.py`

**Purpose:** Orchestrate complete autonomous malware development workflow.

**Workflow:**
```python
def execute(self, **kwargs) -> AgentResult:
    goal = kwargs.get('goal')
    target_av = kwargs.get('target_av', 'Windows Defender')
    auto_compile = kwargs.get('compile', False)

    workflow_summary = []
    warnings = []

    # STEP 1: Select optimal techniques
    selection_result = self.technique_agent.run(
        target_av=target_av,
        objective='evasion',
        complexity='medium'
    )

    techniques = selection_result.data['selected_techniques']

    # STEP 2: Assemble code
    assembly_result = self.assembler.assemble(techniques)
    source_code = assembly_result.source_code

    # STEP 3: Optimize OPSEC
    opsec_result = self.opsec_agent.run(
        code=source_code,
        target_score=7.0,
        max_iterations=3
    )

    optimized_code = opsec_result.data['optimized_code']
    opsec_score = opsec_result.data['final_score']

    # STEP 4: Compile (if requested)
    binary_path = None
    if auto_compile and self.compiler_available:
        compile_result = self.compiler.compile(
            source_code=optimized_code,
            architecture='x64',
            optimization='O2'
        )
        if compile_result['success']:
            binary_path = compile_result['binary_path']

    # STEP 5: Record learning feedback
    learning_result = self.learning_agent.run(
        action='record_compilation',
        techniques=techniques,
        success=compilation_success
    )

    # Return comprehensive result
    return AgentResult(
        success=True,
        data={
            'source_code': optimized_code,
            'binary_path': binary_path,
            'techniques_used': techniques,
            'opsec_score': opsec_score,
            'workflow_summary': workflow_summary
        },
        warnings=warnings
    )
```

**This agent coordinates:**
1. TechniqueSelectionAgent - Pick optimal techniques
2. CodeAssembler - Generate working code
3. OpsecOptimizationAgent - Improve stealth
4. Compiler - Build executable (optional)
5. LearningAgent - Record feedback

---

#### **C. OpsecOptimizationAgent**

**File:** `server/agents/opsec_optimization_agent.py`

**Purpose:** Iteratively improve code OPSEC through analysis and obfuscation.

**Algorithm:**
```python
def execute(self, **kwargs) -> AgentResult:
    code = kwargs.get('code')
    target_score = kwargs.get('target_score', 8.0)
    max_iterations = kwargs.get('max_iterations', 3)

    current_code = code
    improvements = []

    for iteration in range(max_iterations):
        # Analyze current OPSEC
        analysis = self.opsec_analyzer.analyze(current_code)
        current_score = analysis['overall_score']

        # Check if target reached
        if current_score >= target_score:
            break

        # Apply improvements
        if analysis['issues']:
            # Prioritize by severity
            critical_issues = [i for i in analysis['issues']
                             if i['severity'] == 'critical']

            # Apply fixes
            if 'cleartext_strings' in critical_issues:
                current_code = self._encrypt_strings(current_code)
                improvements.append('String encryption')

            if 'api_calls_visible' in critical_issues:
                current_code = self._hash_apis(current_code)
                improvements.append('API hashing')

    return AgentResult(
        success=True,
        data={
            'optimized_code': current_code,
            'original_score': initial_score,
            'final_score': current_score,
            'iterations_used': iteration + 1,
            'improvements_applied': improvements
        }
    )
```

---

#### **D. LearningAgent**

**File:** `server/agents/learning_agent.py`

**Purpose:** Record feedback to improve future technique selection.

**Capabilities:**
- Record detection results (detected vs bypassed)
- Record compilation results (success vs failure)
- Update effectiveness scores
- Track technique statistics

```python
def execute(self, **kwargs) -> AgentResult:
    action = kwargs.get('action')

    if action == 'record_detection':
        return self._record_detection(**kwargs)
    elif action == 'record_compilation':
        return self._record_compilation(**kwargs)

def _record_detection(self, **kwargs):
    techniques = kwargs.get('techniques', [])
    av_edr = kwargs.get('av_edr')
    detected = kwargs.get('detected')

    feedback = DetectionFeedback(
        techniques=techniques,
        av_edr=av_edr,
        detected=detected,
        timestamp=datetime.now()
    )

    self.learning_engine.record_detection(feedback)

    # Update effectiveness scores
    for tech_id in techniques:
        self.learning_engine.update_effectiveness(
            tech_id,
            av_edr,
            success=not detected
        )
```

---

## Core Components

### **1. Code Assembler** (`server/code_assembler.py`)

**Purpose:** Intelligently combine techniques into working C code.

**Key Features:**
- Function extraction from source files
- Dependency resolution & ordering
- Conflict detection (incompatible techniques)
- Header deduplication
- Code formatting

**Algorithm:**
```python
def assemble(self, technique_ids: List[str]) -> AssemblyResult:
    # 1. Load technique metadata
    techniques = [self.load_technique(tid) for tid in technique_ids]

    # 2. Detect conflicts
    conflicts = self.detect_conflicts(techniques)
    if conflicts:
        raise ConflictError(conflicts)

    # 3. Resolve dependencies
    includes, required_funcs = self.dependency_resolver.resolve(techniques)

    # 4. Extract functions
    functions = self.extract_functions(techniques)

    # 5. Generate code
    source_code = self.generate_code(includes, functions)

    return AssemblyResult(
        source_code=source_code,
        technique_ids=technique_ids,
        conflicts=conflicts
    )
```

---

### **2. Compilation Engine** (`compilation/`)

**Platform abstraction:**
- **Windows:** MSBuild integration
- **Linux:** MinGW-w64 cross-compilation

**Features:**
- x64/x86 support
- Optimization levels (O0-O3)
- Auto-fix common errors
- Detailed error reporting

---

### **3. OPSEC Analyzer** (`server/opsec_analyzer.py`)

**Analysis:**
- String scanning (API names, URLs, debug strings)
- Import table analysis
- Entropy calculation
- Pattern detection
- Signature matching

**Scoring:** 0-10 scale with actionable recommendations

---

### **4. C2 Adapters** (`c2_adapters/`)

**Supported frameworks:**
- Sliver C2
- Havoc Framework
- Mythic C2

**Integration flow:**
```
C2 Adapter
  → Generate raw beacon/shellcode
  → Wrap with Noctis techniques
  → Apply obfuscation
  → Compile final binary
```

---

## Data Flow

### **v2.0 Malware Generation Flow**

```
1. MCP Client Tool Call
   | develop(goal="Create loader", auto_compile=True)
   ↓
2. POST /api/v2/agents/malware-development
   |
   ↓
3. MalwareDevelopmentAgent.run()
   |
   ├→ TechniqueSelectionAgent
   |   └→ Returns: ['NOCTIS-T006', 'NOCTIS-T004', 'NOCTIS-T009']
   |
   ├→ CodeAssembler
   |   └→ Returns: 1391 lines of C code
   |
   ├→ OpsecOptimizationAgent
   |   └→ Returns: Optimized code (score: 9.6/10)
   |
   ├→ Compiler (if auto_compile=True)
   |   └→ Returns: Binary path
   |
   └→ LearningAgent
       └→ Records compilation feedback
   ↓
4. Save to workspace
   | output/malware_TIMESTAMP.c
   | output/malware_TIMESTAMP_metadata.json
   | output/malware_TIMESTAMP_report.md
   ↓
5. Return formatted result to MCP Client
```

---

## MCP Integration

### **MCP Client Architecture** (`noctis_mcp_client/noctis_mcp.py`)

**Framework:** FastMCP (Model Context Protocol)

**Design:**
```python
mcp = FastMCP("Noctis-MCP")

@mcp.tool()
def develop(goal: str, target: str = "Windows Defender", ...):
    """Primary tool - one-stop malware development"""
    result = api_post('/api/v2/agents/malware-development', {...})
    # Format and return beautiful output
    return formatted_output

# 7 more tools...
```

**The 8 Tools:**
1. `develop()` - ⭐ Primary autonomous development
2. `browse()` - Explore techniques
3. `compile()` - Build executables
4. `learn()` - Provide feedback
5. `files()` - Manage workspace
6. `help()` - Get guidance
7. `c2_generate()` - Generate C2 beacons
8. `c2_list()` - List C2 frameworks

**Connection Flow:**
```
Cursor IDE
  ↓
MCP Protocol (STDIO)
  ↓
FastMCP Server (noctis_mcp.py)
  ↓
HTTP REST API (localhost:8888)
  ↓
Flask Server (noctis_server.py)
  ↓
Agent System
```

---

## Design Decisions

### **Why Agents?**
- **Separation of concerns** - Each agent has clear responsibility
- **Composability** - Agents can be chained/composed
- **Testability** - Each agent tested independently
- **Extensibility** - Easy to add new agents
- **Professional** - Industry-standard pattern

### **Why Simplified MCP Tools?**
- **AI clarity** - AI assistants know which tool to use
- **No overlap** - Each tool has distinct purpose
- **User-friendly** - Simple, predictable behavior
- **85% reduction** - From 21 tools to 8

### **Why Agent Registry?**
- **Lazy initialization** - Only create agents when needed
- **Singleton pattern** - One instance per type
- **Centralized config** - All agents share configuration
- **Easy testing** - Can inject mock agents

### **Why SQLite for Learning?**
- **Embedded** - No separate database server
- **Fast** - File-based, low latency
- **Simple** - Easy schema management
- **Portable** - Single file database

### **Why Separate Agents from MCP Tools?**
- **Backend independence** - Agents work without MCP
- **Reusability** - Can call agents from REST API, CLI, etc.
- **Testing** - Test agents separately from MCP layer
- **Clean architecture** - UI/logic separation

---

## Performance

### **Agent Execution Times:**
- TechniqueSelectionAgent: ~0.2ms
- OpsecOptimizationAgent: ~1.5ms
- LearningAgent: ~12ms (database write)
- MalwareDevelopmentAgent: ~130ms (full workflow)

### **Compilation Times:**
- Windows (MSBuild): 3-5 seconds
- Linux (MinGW): 1-2 seconds

### **Scalability:**
- Agents are stateless
- Can run multiple requests concurrently
- No session state maintained

---

## Testing

### **Agent Tests** (`test_agents.py`)
- 5 comprehensive integration tests
- Tests all 4 agents + status endpoint
- 100% pass rate

### **Unit Tests** (`tests/`)
- Component-level testing
- Mock external dependencies
- Fast execution

---

## Future Enhancements

### **Potential Additions:**
1. **Code Review Agent** - Analyze generated code for issues
2. **Optimization Agent** - Size/performance optimization
3. **Testing Agent** - Automated AV testing
4. **Documentation Agent** - Generate code documentation
5. **Deployment Agent** - Package and deploy malware

### **Scalability:**
```
Current: Single server with 4 agents
  ↓
Phase 1: Add more specialized agents
  ↓
Phase 2: Distributed agents (Celery)
  ↓
Phase 3: Multi-agent collaboration
  ↓
Phase 4: Self-improving agents (reinforcement learning)
```

---

**Last Updated:** October 4, 2025
**Version:** 2.0.0-alpha
**License:** MIT
