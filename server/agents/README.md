# Agent System (DEPRECATED)

**Status**: ⚠️ LEGACY - Not used by new intelligence system

## Overview

This folder contains the OLD agent-based system that was designed before the hybrid intelligence architecture was implemented.

## Why Deprecated?

The new system (v2 APIs in `agentic_api.py`) uses a **different approach**:

### OLD Approach (This folder):
```
Server creates Python agent objects → Agent makes decisions → Returns code
```

### NEW Approach (Hybrid system):
```
AI in IDE is the agent → Server provides intelligence → AI writes code
```

## Key Difference

**OLD**: Server-side agents try to be "intelligent" (limited)
**NEW**: IDE AI (Claude/GPT) is intelligent, server provides structured intelligence

The NEW approach is superior because:
1. Leverages full AI capabilities (Claude, GPT, etc.)
2. AI can ask clarifying questions
3. AI can make creative decisions
4. AI writes custom code, not templates
5. Works with any AI model (model-agnostic)

## Components in This Folder

- `base_agent.py` - Abstract agent class
- `malware_development_agent.py` - Code generation agent
- `opsec_optimization_agent.py` - OPSEC analysis agent
- `technique_selection_agent.py` - Technique recommendation agent
- `learning_agent.py` - Feedback collection agent

**All superseded by**: `intelligence_processor.py` and AI in IDE

## Migration

If you're using the OLD `/api/v2/agents/*` endpoints, migrate to:

- `/api/v2/agents/malware-development` → `/api/v2/code/generate`
- `/api/v2/agents/opsec-optimization` → `/api/v2/code/optimize-opsec`
- `/api/v2/agents/technique-selection` → `/api/v2/techniques/select`
- `/api/v2/agents/learning` → `/api/v2/learning/record-detection`

## Status

**Keep for**: Reference, backward compatibility
**Do NOT**: Extend or enhance this system
**Future**: Will be removed in v4.0
