# Noctis-MCP Quick Start Guide

**Get up and running in 5 minutes!** ⚡

---

## ✅ What's Already Done

Phase 1 is **COMPLETE**! You have:

✅ **126 techniques indexed** from your MaldevAcademy and TheSilencer examples  
✅ **REST API server** ready to query techniques  
✅ **JSON metadata** for all techniques  
✅ **MITRE ATT&CK mapping** for all TTPs  
✅ **Complete documentation** (README, CONTRIBUTING, etc.)

---

## 🚀 Quick Start

### **Step 1: Verify Indexing** (Already Done ✅)

Your techniques have been indexed. Check the results:

```bash
# View the metadata
dir techniques\metadata

# You should see 11 JSON files including:
# - api_hashing.json
# - encryption.json  
# - gpu_evasion.json
# - syscalls.json
# - etc.
```

---

### **Step 2: Start the Server**

```bash
cd C:\Users\lewis\Desktop\Noctis-MCP
python server/noctis_server.py
```

**You should see:**
```
====================================================================
                  NOCTIS-MCP SERVER                            
    AI-Driven Malware Development Platform v1.0-alpha          
====================================================================

🚀 Server starting on http://127.0.0.1:8888
📚 Techniques loaded: 126

💡 API Endpoints:
   - GET  /health                  - Health check
   - GET  /api/techniques          - List all techniques
   - GET  /api/techniques/<id>     - Get technique by ID
   - GET  /api/categories          - List categories
   - GET  /api/stats               - Database statistics
```

---

### **Step 3: Test the API**

Open a **new terminal** and test the server:

```powershell
# Health check
Invoke-WebRequest http://localhost:8888/health | Select-Object Content

# Get all techniques
Invoke-WebRequest http://localhost:8888/api/techniques | Select-Object Content

# Get statistics
Invoke-WebRequest http://localhost:8888/api/stats | Select-Object Content

# Get techniques by category
Invoke-WebRequest "http://localhost:8888/api/techniques?category=evasion/obfuscation" | Select-Object Content
```

**Or use Python:**

```python
import requests

# Health check
response = requests.get('http://localhost:8888/health')
print(response.json())

# Get all techniques
response = requests.get('http://localhost:8888/api/techniques')
data = response.json()
print(f"Found {data['count']} techniques")

# Get specific technique
response = requests.get('http://localhost:8888/api/techniques/NOCTIS-T001')
print(response.json())
```

---

### **Step 4: Explore Your Techniques**

```powershell
# Get all API hashing techniques
Invoke-WebRequest "http://localhost:8888/api/techniques?search=api_hashing"

# Get all techniques using MITRE T1027 (Obfuscation)
Invoke-WebRequest "http://localhost:8888/api/techniques?mitre=T1027"

# Get GPU evasion techniques
Invoke-WebRequest "http://localhost:8888/api/techniques?search=gpu"
```

---

## 📊 What You Have

### **Your Technique Inventory:**

| **Category** | **Count** | **What You Can Do** |
|--------------|-----------|---------------------|
| **API Hashing** | 29 | Obfuscate API calls to evade static analysis |
| **Syscalls** | 35 | Bypass API hooks with direct syscalls |
| **GPU Evasion** | 16 | Hide payloads in GPU memory |
| **Encryption** | 23 | Encrypt payloads with AES, XOR, etc. |
| **Steganography** | 14 | Hide malware in PNG files |
| **Injection** | 5 | Inject code into processes |
| **Persistence** | 4 | Maintain access via registry, tasks |

### **Your Source Projects:**

- **MaldevAcademy Loader1** - Basic evasion (API hashing, syscalls, unhooking)
- **MaldevAcademy Loader2** - Advanced evasion (GPU, steganography, stack spoofing)
- **TheSilencer** - Your improved variants with better OPSEC

---

## 🎯 Example Queries

### **Find all techniques from TheSilencer:**

```bash
GET /api/techniques?search=MyOwn
```

### **Find techniques that bypass static analysis:**

```bash
# Search technique descriptions
GET /api/techniques?search=static
```

### **Get MITRE ATT&CK coverage:**

```bash
GET /api/mitre
```

**Response:**
```json
{
  "success": true,
  "mappings": {
    "T1027": [
      {"id": "NOCTIS-T006", "name": "Api Hashing"},
      {"id": "NOCTIS-T041", "name": "Encryption"},
      ...
    ],
    "T1055": [
      {"id": "NOCTIS-T048", "name": "Injection"},
      ...
    ]
  }
}
```

---

## 🔮 What's Coming: Phase 2

Once Phase 2 is complete, you'll be able to:

```bash
# Generate a loader combining multiple techniques
curl -X POST http://localhost:8888/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "techniques": ["NOCTIS-T006", "NOCTIS-T007", "NOCTIS-T030"],
    "target_os": "Windows 11",
    "target_av": "CrowdStrike",
    "payload_type": "loader"
  }'

# Response:
{
  "success": true,
  "source_code": "...",  // Generated C code
  "binary": "loader.exe",  // Compiled binary
  "opsec_score": 9.2,
  "mitre_ttps": ["T1027", "T1055", "T1106"]
}
```

---

## 🛠️ Troubleshooting

### **Server won't start:**

```bash
# Check if port 8888 is already in use
netstat -an | findstr :8888

# If in use, kill the process or use different port
python server/noctis_server.py --port 9999
```

### **No techniques found:**

```bash
# Re-run the indexer
python utils/technique_indexer.py

# Should create 11 JSON files in techniques/metadata/
```

### **Import errors:**

```bash
# Install dependencies
python -m pip install flask pyyaml
```

---

## 📚 Documentation

- **README.md** - Complete project overview
- **PHASE1_COMPLETE.md** - What we accomplished in Phase 1
- **STATUS.md** - Current project status
- **CONTRIBUTING.md** - How to contribute
- **techniques/metadata/index.json** - Master technique index

---

## 🎓 Learning Resources

### **Understand Your Techniques:**

1. Read the README for each source project:
   - `Examples/MaldevAcademy/Loader1/README.md`
   - `Examples/MaldevAcademy/Loader2/README.md`

2. Explore the metadata:
   - `techniques/metadata/api_hashing.json`
   - See dependencies, MITRE mappings, OPSEC notes

3. Study the source code:
   - `Examples/MaldevAcademy/Loader1/Loader/ApiHashing.c`
   - `Examples/MyOwn/TheSilencer/Loader/ApiHashing.c`
   - Compare basic vs. improved versions

---

## 🚀 Next Steps

### **Immediate:**

1. ✅ Start the server
2. ✅ Test API endpoints
3. ✅ Explore your techniques

### **This Week:**

1. ⏳ Build MCP client for Cursor integration
2. ⏳ Start Phase 2: Code Assembler
3. ⏳ Design compilation pipeline

### **This Month:**

1. ⏳ Complete Phase 2 (Code Generation)
2. ⏳ Add auto-compilation
3. ⏳ OPSEC analyzer
4. ⏳ Learning engine

---

## 💡 Pro Tips

### **Explore Techniques Efficiently:**

```python
# Python script to explore your techniques
import requests
import json

base_url = "http://localhost:8888"

# Get all categories
response = requests.get(f"{base_url}/api/categories")
categories = response.json()['categories']

for cat in categories:
    print(f"\n{cat['name']}: {cat['count']} techniques")
    
    # Get techniques in this category
    response = requests.get(f"{base_url}/api/techniques?category={cat['name']}")
    techniques = response.json()['techniques']
    
    for tech in techniques[:3]:  # Show first 3
        print(f"  - {tech['name']} ({tech['technique_id']})")
        print(f"    MITRE: {', '.join(tech['mitre_attack'])}")
        print(f"    Author: {tech['author']}")
```

### **Compare Variants:**

```python
# Compare your TheSilencer improvements vs. MaldevAcademy originals
response = requests.get(f"{base_url}/api/techniques?search=api_hashing")
techniques = response.json()['techniques']

for tech in techniques:
    print(f"{tech['name']} - {tech['source_project']}")
    print(f"  OPSEC Risk: {tech['opsec']['detection_risk']}")
    print(f"  Functions: {', '.join(tech['code_blocks']['functions'][:3])}")
    print()
```

---

## ✅ Checklist

Before moving to Phase 2, verify:

- [ ] Server starts without errors
- [ ] Health endpoint returns 200 OK
- [ ] `/api/techniques` returns 126 techniques
- [ ] Metadata files exist in `techniques/metadata/`
- [ ] Can filter by category
- [ ] Can search techniques
- [ ] Statistics endpoint works

**All checked?** You're ready for Phase 2! 🎉

---

## 🎉 Congratulations!

You've successfully completed **Phase 1** of the Noctis-MCP project!

You now have a **working API** that can serve your **126 malware techniques** to AI agents.

**Next:** Build the MCP client and integrate with Cursor so you can ask the AI about your techniques directly in your IDE!

---

*Happy hacking! 🌙⚔️*

*Remember: Use this tool only for authorized security research and red team engagements.*

