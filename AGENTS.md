# Noctis-MCP Agent System

**Autonomous AI agents for intelligent malware development workflows**

---

## Overview

Noctis-MCP implements an **agent-based architecture** where specialized AI agents autonomously handle complex malware development tasks. Each agent focuses on a specific domain and can collaborate with other agents to achieve sophisticated objectives.

## Agent Architecture

### Core Components

```
┌─────────────────────────────────────────────────┐
│           AgentRegistry (Singleton)             │
│  - Centralized agent lifecycle management       │
│  - Dependency injection via configuration       │
│  - Lazy initialization for performance          │
└─────────────────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┬─────────────┐
        ▼               ▼               ▼             ▼
┌──────────────┐ ┌──────────────┐ ┌──────────┐ ┌─────────┐
│ Technique    │ │  Malware     │ │  OPSEC   │ │Learning │
│ Selection    │ │ Development  │ │   Opt    │ │  Agent  │
│   Agent      │ │   Agent      │ │  Agent   │ │         │
└──────────────┘ └──────────────┘ └──────────┘ └─────────┘
```

### Base Agent (BaseAgent)

All agents inherit from `BaseAgent` which provides:
- **State management** - Track agent execution state
- **Metrics collection** - Execution time, success rate, task count
- **Cleanup hooks** - Resource cleanup on shutdown
- **Result formatting** - Standardized AgentResult objects

---

## Available Agents

### 1. 🎯 Technique Selection Agent

**Purpose:** AI-powered technique recommendation based on objectives and constraints

**Endpoint:** `POST /api/v2/agents/technique-selection`

**Capabilities:**
- Analyzes target environment (AV/EDR, OS, constraints)
- Recommends optimal technique combinations
- Considers OPSEC requirements and detection history
- Provides effectiveness scoring and rationale

**Request Example:**
```json
{
  "target_av": "Windows Defender",
  "objective": "evasion",
  "complexity": "medium",
  "constraints": {
    "max_techniques": 5,
    "min_effectiveness_score": 0.8
  }
}
```

**Response:**
```json
{
  "success": true,
  "techniques": [
    {
      "technique_id": "NOCTIS-T004",
      "name": "Direct Syscalls",
      "effectiveness_score": 0.92,
      "rationale": "Bypasses user-mode hooks in Windows Defender"
    }
  ],
  "metadata": {
    "total_candidates": 10,
    "selected_count": 3,
    "avg_effectiveness": 0.88
  }
}
```

---

### 2. 🔧 Malware Development Agent

**Purpose:** Autonomous end-to-end malware creation from goal to compiled binary

**Endpoint:** `POST /api/v2/agents/malware-development`

**Capabilities:**
- Interprets high-level objectives ("create stealthy loader")
- Selects optimal technique combinations
- Generates code using RAG-powered intelligence
- Applies OPSEC optimizations iteratively
- Compiles and validates output
- Returns production-ready binary

**Request Example:**
```json
{
  "goal": "Create stealthy loader for Cobalt Strike",
  "target_av": "CrowdStrike Falcon",
  "target_os": "Windows",
  "architecture": "x64",
  "auto_compile": true,
  "target_opsec_score": 8.0,
  "max_techniques": 5
}
```

**Response:**
```json
{
  "success": true,
  "binary_path": "output/stealthy_loader_x64.exe",
  "techniques_used": ["NOCTIS-T004", "NOCTIS-T002", "NOCTIS-T118"],
  "opsec_score": 8.2,
  "compilation_time": 3.4,
  "warnings": [],
  "metadata": {
    "iterations": 2,
    "final_size": "24.5 KB",
    "obfuscation_applied": true
  }
}
```

---

### 3. 🛡️ OPSEC Optimization Agent

**Purpose:** Iterative code improvement to maximize operational security

**Endpoint:** `POST /api/v2/agents/opsec-optimization`

**Capabilities:**
- Analyzes code for OPSEC weaknesses
- Applies automated fixes (string encryption, API hashing, etc.)
- Iteratively improves until target score is met
- Provides detailed before/after comparison
- Tracks all applied transformations

**Request Example:**
```json
{
  "code": "int main() { printf(\"malware\"); }",
  "target_score": 8.0,
  "max_iterations": 3
}
```

**Response:**
```json
{
  "success": true,
  "optimized_code": "...",
  "initial_score": 3.2,
  "final_score": 8.1,
  "iterations": 2,
  "improvements": [
    {
      "issue": "Hardcoded strings detected",
      "fix": "XOR string encryption applied",
      "score_delta": +2.1
    }
  ]
}
```

---

### 4. 📚 Learning Agent

**Purpose:** Feedback collection and continuous improvement from real-world results

**Endpoint:** `POST /api/v2/agents/learning`

**Capabilities:**
- Records detection feedback (AV/EDR results)
- Tracks technique effectiveness over time
- Updates recommendation scores based on outcomes
- Identifies patterns in successful/failed attempts
- Powers future technique selection decisions

**Request Example:**
```json
{
  "action": "record_detection",
  "techniques": ["NOCTIS-T001", "NOCTIS-T004"],
  "av_edr": "Windows Defender",
  "detected": false,
  "detection_type": null,
  "obfuscation_level": "high",
  "notes": "Bypassed successfully on Windows 11 22H2"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Detection feedback recorded",
  "insights": {
    "techniques_tested": 2,
    "success_rate_delta": +0.03
  },
  "updated_stats": {
    "NOCTIS-T004": {
      "total_uses": 47,
      "detection_rate": 0.12
    }
  }
}
```

---

## Agent Registry

### Initialization

The `AgentRegistry` is initialized during server startup and manages all agent lifecycle operations.

```python
from server.agents import AgentRegistry

# Initialize registry with configuration
config = {
    'db_path': 'data/knowledge_base.db',
    'metadata_path': 'techniques/metadata',
    'output_dir': 'output',
    'rag_db_path': 'data/rag_db'
}
AgentRegistry.initialize(config)

# Get agent instance (lazy-loaded)
agent = AgentRegistry.get_agent('technique_selection')
result = agent.run(target_av="Windows Defender", objective="evasion")
```

### Dependency Injection

To prevent circular dependencies, the learning engine is injected after initialization:

```python
# Initialize registry first
AgentRegistry.initialize(agent_config)

# Create learning engine
learning_engine = AgenticLearningEngine(db_path='data/kb.db')

# Inject back into registry
AgentRegistry.set_learning_engine(learning_engine)
```

---

## Agent Status and Metrics

### Get All Agent Status

**Endpoint:** `GET /api/v2/agents/status`

**Response:**
```json
{
  "success": true,
  "agents": {
    "technique_selection": {
      "type": "TechniqueSelectionAgent",
      "state": "ready",
      "metrics": {
        "total_executions": 42,
        "avg_execution_time": 0.23,
        "success_rate": 0.98
      }
    },
    "malware_development": {
      "type": "MalwareDevelopmentAgent",
      "state": "ready",
      "metrics": {
        "total_executions": 15,
        "avg_execution_time": 4.67,
        "success_rate": 0.93
      }
    }
  },
  "total_agents": 4
}
```

---

## Agent Workflows

### Workflow 1: Autonomous Malware Development

```
User Request: "Create stealthy loader for Cobalt Strike"
                      │
                      ▼
         ┌────────────────────────────┐
         │ Malware Development Agent  │
         └────────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
┌─────────────┐ ┌──────────┐ ┌──────────────┐
│ Technique   │ │   Code   │ │    OPSEC     │
│ Selection   │ │ Assembly │ │ Optimization │
│   Agent     │ │   (RAG)  │ │    Agent     │
└─────────────┘ └──────────┘ └──────────────┘
        │             │             │
        └─────────────┼─────────────┘
                      ▼
              ┌─────────────┐
              │ Compilation │
              └─────────────┘
                      │
                      ▼
              Binary Output
```

### Workflow 2: Iterative OPSEC Improvement

```
Initial Code
     │
     ▼
┌──────────────────┐
│ OPSEC Analyzer   │ ← Score: 3.2/10
└──────────────────┘
     │
     ▼
┌──────────────────┐
│ Apply Fixes:     │
│ - String encrypt │
│ - API hashing    │
│ - Control flow   │
└──────────────────┘
     │
     ▼
┌──────────────────┐
│ Re-analyze       │ ← Score: 6.1/10
└──────────────────┘
     │
     ▼
┌──────────────────┐
│ Apply More Fixes │
└──────────────────┘
     │
     ▼
┌──────────────────┐
│ Final Analysis   │ ← Score: 8.2/10 ✅
└──────────────────┘
```

---

## Advanced Features

### 1. RAG Integration

Agents leverage the RAG engine for intelligence-driven decisions:
- **TechniqueSelectionAgent** queries RAG for latest evasion techniques
- **MalwareDevelopmentAgent** generates code using RAG-powered templates
- **LearningAgent** indexes new intelligence into RAG database

### 2. Learning Feedback Loop

```
Agent Execution → Results → Learning Agent → Updated Stats → Better Future Decisions
```

The learning agent continuously improves agent performance by:
- Recording detection outcomes
- Updating technique effectiveness scores
- Identifying successful patterns
- Pruning ineffective approaches

### 3. Metrics Collection

Each agent tracks:
- **Total executions** - Number of times agent was invoked
- **Success rate** - Percentage of successful completions
- **Average execution time** - Performance monitoring
- **Error count** - Failure tracking for debugging

---

## Best Practices

### 1. Agent Selection

- **Simple technique query** → Use `TechniqueSelectionAgent`
- **Full development pipeline** → Use `MalwareDevelopmentAgent`
- **Code already exists, needs hardening** → Use `OpsecOptimizationAgent`
- **Testing in live environment** → Use `LearningAgent` for feedback

### 2. Error Handling

All agents return standardized `AgentResult` objects:

```python
{
  "success": true/false,
  "data": {...},
  "error": "Error message if failed",
  "metadata": {
    "execution_time": 1.23,
    "agent_type": "technique_selection"
  }
}
```

### 3. Resource Cleanup

Always cleanup agents on shutdown:

```python
# Cleanup all agents (done automatically on server shutdown)
AgentRegistry.cleanup_all()
```

---

## Development

### Creating a New Agent

1. **Create agent file** in `server/agents/`
2. **Inherit from BaseAgent**
3. **Implement `_execute()` method**
4. **Register in AgentRegistry**

**Example:**

```python
from server.agents.base_agent import BaseAgent, AgentResult

class CustomAgent(BaseAgent):
    """Custom agent for specialized task"""

    def _execute(self, **kwargs) -> AgentResult:
        # Agent logic here
        result_data = self._do_work(kwargs)

        return AgentResult(
            success=True,
            data=result_data,
            metadata={'custom_field': 'value'}
        )
```

### Testing Agents

```python
import pytest
from server.agents import AgentRegistry

def test_technique_selection_agent():
    config = {'db_path': 'test.db', ...}
    AgentRegistry.initialize(config)

    agent = AgentRegistry.get_agent('technique_selection')
    result = agent.run(target_av="Test AV", objective="evasion")

    assert result.success
    assert len(result.data['techniques']) > 0
```

---

## Troubleshooting

### Agent Not Found

```
ValueError: Unknown agent type: custom_agent
```

**Solution:** Register agent in `AgentRegistry._create_agent()`

### Circular Dependency Error

```
RuntimeError: Circular dependency detected
```

**Solution:** Use `set_learning_engine()` for dependency injection after registry initialization

### Agent Timeout

Agents have no built-in timeout. For long-running tasks, implement timeout in your client code.

---

## Related Documentation

- [README.md](README.md) - Main project documentation
- [SETUP.md](docs/SETUP.md) - Installation and configuration
- [API Documentation](docs/API.md) - REST API reference
- [Architecture](docs/ARCHITECTURE.md) - System architecture

---

## License

MIT License - See [LICENSE](LICENSE) for details

**For authorized security research and red team operations only.**
