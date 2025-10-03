# 📚 Noctis-MCP Documentation Map

**Quick guide to finding what you need.**

---

## 🚀 Getting Started

**New to Noctis-MCP? Start here:**

1. **README.md** - Main project overview and architecture
2. **QUICKSTART.md** - Get up and running in 5 minutes
3. **QUICK_REFERENCE.md** - Common commands and API reference

---

## 📊 Project Status

**Want to know where we are?**

- **progress/STATUS.md** - Current overall status and progress
- **progress/README.md** - Roadmap and milestones
- **progress/PHASE2_PROGRESS.md** - Detailed Phase 2 tracking

---

## 🛠️ Component Guides

**Need help with specific components?**

### MCP Client (Cursor IDE Integration)
- **progress/MCP_GUIDE.md** - Complete guide
  - Setup instructions
  - All 9 tools explained
  - Usage examples
  - Troubleshooting

### Compilation Engine
- **progress/COMPILATION_GUIDE.md** - Complete guide
  - Quick start
  - API usage
  - MCP tool usage
  - Troubleshooting

### API Server
- **QUICK_REFERENCE.md** - API endpoints
- **server/noctis_server.py** - Source code (well-documented)

### Code Assembler
- **server/code_assembler.py** - Source code (prototype)

---

## 📖 Historical Records

**Looking for past milestones?**

- **progress/PHASE1_COMPLETE.md** - Phase 1 completion summary
- **RESTART_GUIDE.md** - Guide for resuming development
- **CONTRIBUTING.md** - How to contribute

---

## 🎯 By Use Case

### "I want to use Noctis-MCP"
1. **QUICKSTART.md** - Installation and first run
2. **progress/MCP_GUIDE.md** - Setup Cursor IDE
3. **QUICK_REFERENCE.md** - Common commands

### "I want to develop/extend Noctis-MCP"
1. **CONTRIBUTING.md** - Development guidelines
2. **RESTART_GUIDE.md** - Resume development
3. **progress/PHASE2_PROGRESS.md** - Current tasks
4. Component source code in `server/`, `compilation/`, `noctis_mcp_client/`

### "I need technical details"
1. **README.md** - Full architecture
2. **progress/COMPILATION_GUIDE.md** - Compilation internals
3. **progress/MCP_GUIDE.md** - MCP architecture
4. Source code (all well-documented)

### "Something isn't working"
1. **progress/MCP_GUIDE.md** - MCP troubleshooting section
2. **progress/COMPILATION_GUIDE.md** - Compilation troubleshooting
3. **QUICKSTART.md** - Common issues
4. **logs/noctis.log** - Check error logs

---

## 📁 Complete File Structure

```
Noctis-MCP/
│
├── 📘 Core Documentation
│   ├── README.md                    - Main project documentation (START HERE)
│   ├── QUICKSTART.md                - Quick start guide
│   ├── QUICK_REFERENCE.md           - Commands and API reference
│   ├── CONTRIBUTING.md              - How to contribute
│   ├── RESTART_GUIDE.md             - Resume development guide
│   ├── LICENSE                      - MIT license
│   └── DOCUMENTATION_MAP.md         - This file
│
├── 📊 Progress Tracking (progress/)
│   ├── README.md                    - Roadmap overview
│   ├── STATUS.md                    - Current status (updated regularly)
│   ├── PHASE1_COMPLETE.md           - Phase 1 record
│   ├── PHASE2_PROGRESS.md           - Phase 2 detailed tracking
│   ├── MCP_GUIDE.md                 - Complete MCP guide
│   └── COMPILATION_GUIDE.md         - Complete compilation guide
│
├── 🔧 Configuration
│   ├── config.yaml                  - Server configuration
│   ├── requirements.txt             - Python dependencies
│   └── noctis-mcp-config.json       - Cursor MCP configuration
│
├── 🖥️ Server Components (server/)
│   ├── noctis_server.py             - Main API server (608 lines)
│   └── code_assembler.py            - Code assembler (510 lines)
│
├── 🔌 MCP Client (noctis_mcp_client/)
│   └── noctis_mcp.py                - FastMCP integration (825 lines)
│
├── 🔨 Compilation (compilation/)
│   └── windows_compiler.py          - Windows compiler (530 lines)
│
├── 🛠️ Utilities (utils/)
│   └── technique_indexer.py         - Technique scanner (450 lines)
│
├── 📊 Technique Database (techniques/)
│   └── metadata/*.json              - 126 techniques indexed
│
└── 📝 Examples (Examples/)
    ├── MaldevAcademy/               - Source techniques
    └── MyOwn/TheSilencer/           - Custom improvements
```

---

## 🎯 Quick Links by Topic

### Setup & Installation
- Main setup: `QUICKSTART.md`
- MCP setup: `progress/MCP_GUIDE.md` (Setup Guide section)
- Requirements: `requirements.txt`

### Usage
- API reference: `QUICK_REFERENCE.md`
- MCP tools: `progress/MCP_GUIDE.md` (Available Tools section)
- Examples: `progress/MCP_GUIDE.md` (Usage Examples section)

### Development
- Contribution guide: `CONTRIBUTING.md`
- Current tasks: `progress/PHASE2_PROGRESS.md`
- Resume work: `RESTART_GUIDE.md`

### Troubleshooting
- MCP issues: `progress/MCP_GUIDE.md` (Troubleshooting section)
- Compilation issues: `progress/COMPILATION_GUIDE.md` (Troubleshooting section)
- General issues: `QUICKSTART.md`

---

## 📞 Where to Find Help

### For Users
1. Start with `QUICKSTART.md`
2. Check `QUICK_REFERENCE.md` for commands
3. See component guides in `progress/`
4. Check troubleshooting sections

### For Developers
1. Read `CONTRIBUTING.md`
2. Check `progress/STATUS.md` for current work
3. Review `RESTART_GUIDE.md` for context
4. See detailed progress in `progress/PHASE2_PROGRESS.md`

---

## 🔄 Documentation Updates

This documentation is actively maintained:

- **STATUS.md** - Updated after each development session
- **PHASE2_PROGRESS.md** - Updated with each milestone
- **Component Guides** - Updated when features change
- **README.md** - Updated for major features

Last major update: October 3, 2024 (Phase 2 at 50%)

---

**🌙⚔️ Everything you need to know about Noctis-MCP in one place!**

*Documentation version: 1.0.0-alpha*  
*Project version: 1.0.0-alpha*

