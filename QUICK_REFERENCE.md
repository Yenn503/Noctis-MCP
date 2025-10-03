# Noctis-MCP Quick Reference Card

**Current Version:** 1.0.0-alpha  
**Phase:** 2 (Code Generation) - 10% Complete  
**Last Updated:** October 3, 2024

---

## 🚀 Quick Commands

```bash
# Index techniques
python utils/technique_indexer.py

# Start API server
python server/noctis_server.py

# Test code assembler
python server/code_assembler.py

# Test API (in another terminal)
curl http://localhost:8888/health
curl http://localhost:8888/api/techniques
curl http://localhost:8888/api/stats
```

---

## 📊 Current Status

```
✅ Phase 1: Foundation              100% COMPLETE
🚧 Phase 2: Code Generation          10% IN PROGRESS
⏳ Phase 3: Dynamic Development       0% PLANNED
⏳ Phase 4: C2 Integration            0% PLANNED

Overall Project: 30% Complete
```

---

## 🎯 What Works Now

| Feature | Status | Command |
|---------|--------|---------|
| **Technique Indexing** | ✅ Working | `python utils/technique_indexer.py` |
| **API Server** | ✅ Working | `python server/noctis_server.py` |
| **Technique Query** | ✅ Working | `GET /api/techniques` |
| **Code Assembly** | 🚧 Prototype | `python server/code_assembler.py` |
| **Compilation** | ⏳ Planned | Phase 2 |
| **OPSEC Analysis** | ⏳ Planned | Phase 2 |
| **Cursor Integration** | ⏳ Planned | Phase 2 |

---

## 📁 Project Structure

```
Noctis-MCP/
├── server/
│   ├── noctis_server.py      # Main API server
│   └── code_assembler.py     # Code generation
├── utils/
│   └── technique_indexer.py  # Technique scanner
├── techniques/metadata/      # 11 JSON files
├── progress/                 # Progress tracking
├── Examples/                 # Your source material
│   ├── MaldevAcademy/       # 53 source files
│   └── MyOwn/TheSilencer/   # 18 source files
└── Documentation files
```

---

## 🔍 API Endpoints

### **Server Information**
- `GET /health` - Server health check
- `GET /api/stats` - Database statistics

### **Technique Queries**
- `GET /api/techniques` - List all techniques
- `GET /api/techniques?category=evasion/obfuscation` - Filter by category
- `GET /api/techniques?search=api` - Search techniques
- `GET /api/techniques?mitre=T1027` - Filter by MITRE TTP
- `GET /api/techniques/<id>` - Get specific technique

### **Metadata**
- `GET /api/categories` - List all categories
- `GET /api/mitre` - MITRE ATT&CK mappings

### **Code Generation** (Phase 2 - Partial)
- `POST /api/generate` - Generate malware code (coming soon)
- `POST /api/compile` - Compile code (coming soon)

---

## 📊 Your Techniques

**Total:** 126 techniques indexed

| Category | Count |
|----------|-------|
| API Hashing | 29 |
| Syscalls/Unhooking | 35 |
| GPU Evasion | 16 |
| Encryption | 23 |
| Steganography | 14 |
| Injection | 5 |
| Persistence | 4 |

---

## 💻 Example Usage

### **Query API with PowerShell:**

```powershell
# Get all techniques
Invoke-WebRequest http://localhost:8888/api/techniques | 
    Select-Object -ExpandProperty Content | 
    ConvertFrom-Json

# Get API hashing techniques
Invoke-WebRequest "http://localhost:8888/api/techniques?search=api_hashing" |
    Select-Object -ExpandProperty Content |
    ConvertFrom-Json

# Get statistics
Invoke-WebRequest http://localhost:8888/api/stats |
    Select-Object -ExpandProperty Content |
    ConvertFrom-Json
```

### **Query API with Python:**

```python
import requests

# Get all techniques
response = requests.get('http://localhost:8888/api/techniques')
data = response.json()
print(f"Found {data['count']} techniques")

# Get specific technique
response = requests.get('http://localhost:8888/api/techniques/NOCTIS-T124')
technique = response.json()['technique']
print(f"Technique: {technique['name']}")
print(f"Category: {technique['category']}")
print(f"MITRE: {technique['mitre_attack']}")
```

---

## 🔧 Troubleshooting

### **Server won't start:**
```bash
# Check if port is in use
netstat -an | findstr :8888

# Use different port
python server/noctis_server.py --port 9999
```

### **No techniques found:**
```bash
# Re-run indexer
python utils/technique_indexer.py

# Verify metadata exists
dir techniques\metadata
```

### **Import errors:**
```bash
# Install dependencies
python -m pip install flask pyyaml
```

---

## 📚 Documentation Files

- **README.md** - Complete project overview (1,171 lines)
- **QUICKSTART.md** - Getting started guide
- **CONTRIBUTING.md** - Contribution guidelines
- **SESSION_SUMMARY.md** - What we built today
- **progress/STATUS.md** - Current status
- **progress/PHASE1_COMPLETE.md** - Phase 1 details
- **progress/PHASE2_PROGRESS.md** - Current phase
- **QUICK_REFERENCE.md** - This file

---

## 🎯 Next Steps

### **For Next Session:**

1. **Continue Phase 2:**
   ```
   Tell AI: "Continue Phase 2 - improve code assembler"
   ```

2. **Focus Areas:**
   - Better C function extraction
   - MSBuild compilation support
   - MCP client for Cursor

3. **What to Build:**
   - Compilation engine
   - OPSEC analyzer
   - Cursor integration

---

## 🏆 Achievements Today

✅ Built complete MCP infrastructure  
✅ Indexed 126 malware techniques  
✅ Created REST API server  
✅ Built code assembler prototype  
✅ Wrote 3,000+ lines of documentation  
✅ Set up open source framework  

**Phase 1: 100% Complete!** 🎉

---

## 🔗 Quick Links

### **Important Files:**
- `README.md` - Start here
- `SESSION_SUMMARY.md` - Today's work
- `progress/STATUS.md` - Current status

### **Code:**
- `server/noctis_server.py` - API server
- `server/code_assembler.py` - Code generation
- `utils/technique_indexer.py` - Indexing

### **Data:**
- `techniques/metadata/` - All technique metadata
- `Examples/` - Your source code

---

## 💡 Pro Tips

1. **Explore Metadata:**
   ```bash
   cat techniques/metadata/api_hashing.json | jq
   ```

2. **Monitor Server:**
   ```bash
   python server/noctis_server.py --debug
   ```

3. **Test Code Assembly:**
   ```python
   from server.code_assembler import CodeAssembler
   assembler = CodeAssembler()
   result = assembler.assemble(['NOCTIS-T124', 'NOCTIS-T118'])
   print(result.source_code)
   ```

---

**🌙⚔️ Noctis-MCP - Dynamic AI Malware Development**

*Use responsibly. Use legally. Use ethically.*

---

*Quick Reference v1.0 - October 3, 2024*

