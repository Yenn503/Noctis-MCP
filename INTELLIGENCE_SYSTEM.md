# Noctis-MCP Dynamic Intelligence System

## 🎯 Overview

Noctis-MCP features a **fully automated, self-updating intelligence system** that keeps your RAG database fresh with the latest malware techniques, exploits, and research - seamlessly integrated into your workflow.

## 🔄 How It Works

### **Seamless Auto-Update Flow**

```
User: "Generate CrowdStrike bypass using latest syscalls"
    ↓
AI calls: search_intelligence("CrowdStrike syscalls")
    ↓
[AUTO-CHECK] Has RAG been updated in last 7 days?
    ├─ YES → Search existing database
    └─ NO  → Fetch 2-3 latest GitHub repos for this query
             Index them
             Then search
    ↓
Returns: Fresh results with latest techniques
    ↓
AI calls: generate_code() with cutting-edge intelligence
```

**No manual intervention needed!** The system automatically:
- ✅ Checks if RAG data is stale (>7 days)
- ✅ Fetches latest GitHub repos for your specific query
- ✅ Indexes new intelligence on-the-fly
- ✅ Returns fresh results instantly

---

## 📊 Intelligence Sources

### **25+ Malware & Red Team Feeds**

Your system automatically monitors:

#### Elite Red Team Blogs
- **MDSec** - British offensive security legends
- **Outflank** - Dutch red team innovators
- **XPN InfoSec** - Advanced Windows internals
- **TrustedSec** - APT-level techniques
- **SpecterOps** - BloodHound creators

#### Malware Research
- **VX Underground** - Premier malware research archive
- **Malware-Traffic-Analysis** - Real-world samples
- **Malwarebytes Labs** - Latest malware trends
- **Hybrid Analysis** - Automated malware analysis

#### Exploit Development
- **Exploit-DB** - Comprehensive exploit database
- **Google Project Zero** - 0-day research
- **ZDI (Zero Day Initiative)** - Exploit marketplace

#### Windows Internals & Evasion
- **ired.team (Red Team Notes)** - Comprehensive techniques
- **Pentester Academy** - Advanced training content
- **0x00sec** - Underground community
- **Hexacorn** - EDR bypass expert

#### APT & Threat Intelligence
- **Unit42 (Palo Alto)** - APT tracking
- **Mandiant** - Nation-state TTPs
- **CrowdStrike** - Threat intelligence

#### Security News
- **Bleeping Computer** - Breaking security news
- **The Hacker News** - Daily updates
- **Dark Reading** - Enterprise security
- **Krebs on Security** - Investigative journalism

---

## 🤖 How The AI Uses It

### **Example 1: Latest CrowdStrike Bypass**

```
User: "I need to bypass CrowdStrike Falcon EDR using the newest techniques"

AI Workflow:
1. search_intelligence("CrowdStrike Falcon bypass")
   → Auto-checks: RAG last updated 9 days ago
   → Fetches latest 2 GitHub repos: "CrowdStrike-bypass-2025", "Falcon-unhook"
   → Indexes new techniques
   → Returns fresh results

2. analyze_technique("NOCTIS-T004")
   → Finds latest Hell's Gate variants from newly indexed repos
   → Effectiveness score updated with 2025 data

3. generate_code(["syscalls", "unhooking"])
   → Uses 2025 GitHub implementations
   → Includes latest CrowdStrike-specific bypasses

Result: Cutting-edge payload using techniques from THIS WEEK
```

### **Example 2: Trending Techniques**

```
User: "What are the hottest malware evasion techniques right now?"

AI Workflow:
1. fetch_latest("malware evasion 2025")
   → Searches GitHub trending (last 30 days)
   → Fetches top starred repos: "GPU-based-evasion", "Kernel-callback-removal"
   → Indexes 15 new repos, 25 blog posts
   → Returns summary

2. compare_techniques(newly_discovered_techniques)
   → Analyzes effectiveness vs popular EDRs
   → Ranks by novelty + success rate

3. select_techniques(goal="evade Windows 11 Defender")
   → Recommends newly indexed GPU evasion (NOCTIS-T009)
   → Provides implementation from trending repo

Result: AI discovers and implements bleeding-edge techniques automatically
```

---

## ⚡ Smart Features

### **1. Automatic Staleness Detection**
- Checks `data/intelligence_stats.json` on every search
- If last update >7 days ago → auto-fetches latest for your query
- **Transparent**: AI doesn't need to think about it

### **2. Query-Specific Updates**
- Search for "AMSI bypass" → Fetches latest AMSI repos
- Search for "process injection" → Fetches latest injection techniques
- **Targeted**: Only fetch what you need, when you need it

### **3. 24-Hour Smart Cache**
- `fetch_latest("CrowdStrike bypass")` caches results for 24 hours
- Prevents redundant API calls
- Use `force=true` to bypass cache

### **4. Auto-Indexing on Startup**
- Server checks if RAG database is empty on startup
- Automatically indexes `techniques/knowledge/*.md` files
- **Zero config**: Just start the server!

---

## 🔧 Manual Intelligence Updates (Optional)

### **Option 1: Via MCP Tool (Recommended)**

```python
# In IDE chat with AI
User: "Update the intelligence database with latest techniques"

AI calls: fetch_latest("EDR bypass syscalls 2025", sources=["github", "blogs"])

Result: Fetches and indexes latest intelligence
```

### **Option 2: Via Cron (Background)**

Run the standalone updater script:

```bash
# Daily light update (5 min)
python scripts/intelligence_updater.py --mode daily

# Weekly full update (15 min)
python scripts/intelligence_updater.py --mode weekly

# Custom queries
python scripts/intelligence_updater.py --mode manual --queries "CrowdStrike bypass" "AMSI evasion"
```

### **Option 3: Setup Automated Cron**

```bash
chmod +x scripts/setup_auto_update.sh
./scripts/setup_auto_update.sh

# Select option 2: Daily (2 AM) + Weekly full refresh (Sunday 3 AM)
```

---

## 📈 Monitoring

### **Check RAG Statistics**

```python
# Via MCP tool
rag_stats()

# Returns:
{
  "enabled": true,
  "knowledge_base": 55,      # Markdown chunks
  "github_repos": 127,       # Auto-updated!
  "research_papers": 34,     # arXiv papers
  "blog_posts": 89,          # Latest posts
  "detection_intel": 12,     # User feedback
  "embedding_model": "all-MiniLM-L6-v2",
  "vector_db": "ChromaDB"
}
```

### **View Update Logs**

```bash
# Live tail
tail -f logs/intelligence/cron.log

# View last update
cat logs/intelligence/update_YYYYMMDD_HHMMSS.log
```

### **Check Update History**

```bash
cat data/intelligence_stats.json

# Shows:
{
  "total_runs": 42,
  "total_indexed": 1547,
  "last_run": "2025-01-10T02:00:00",
  "runs": [...]  # Last 30 runs
}
```

---

## 🎯 Best Practices

### **For AI Agents**

1. **Trust the auto-update** - It's enabled by default, don't overthink it
2. **Use `fetch_latest()` for new topics** - Gets targeted fresh intel
3. **Check `auto_updated` field** - Know when new techniques were indexed
4. **Leverage 24hr cache** - Don't re-fetch the same topic repeatedly

### **For Users**

1. **Let it auto-update** - System handles staleness automatically
2. **Optional cron for heavy users** - Weekly updates keep everything fresh
3. **Monitor RAG stats** - Use `rag_stats()` to see what's indexed
4. **Add GITHUB_TOKEN env var** - Higher API rate limits (optional)

---

## 🔐 API Rate Limits

### **GitHub API**
- **Unauthenticated**: 60 requests/hour
- **With GITHUB_TOKEN**: 5,000 requests/hour

Set token:
```bash
export GITHUB_TOKEN="ghp_your_token_here"
```

### **arXiv API**
- No official limits
- Built-in 1s delay between requests

### **RSS Feeds**
- No limits (public feeds)
- Fetched via HTTP GET

---

## 🚀 Advanced Usage

### **Force Fresh Update**

```python
# Bypass 24hr cache
fetch_latest("CrowdStrike bypass", force=True)
```

### **Disable Auto-Update (search only)**

```python
# Don't auto-fetch if stale
search_intelligence("syscalls", auto_update=False)
```

### **Custom GitHub Searches**

```python
# Fetch specific trending repos
fetch_latest(
    topic="Cobalt Strike BOF development",
    sources=["github"],
    days_back=7  # Only last week
)
```

---

## 📂 File Structure

```
Noctis-MCP/
├── server/
│   ├── intelligence/
│   │   ├── __init__.py
│   │   └── live_intel.py           # 25+ feeds, GitHub/arXiv/RSS
│   ├── rag/
│   │   └── rag_engine.py           # ChromaDB + embeddings
│   └── agentic_api.py              # Auto-update logic
├── scripts/
│   ├── intelligence_updater.py     # Standalone updater
│   └── setup_auto_update.sh        # Cron setup
├── data/
│   ├── rag_db/                     # ChromaDB persistent storage
│   ├── intelligence_stats.json     # Update history
│   └── fetch_cache_*.json          # 24hr query cache
└── logs/
    └── intelligence/               # Update logs
```

---

## 🎓 How RAG Makes AI Smarter

### **Without RAG (Traditional AI)**
```
User: "Generate CrowdStrike bypass"
AI: Uses training data from 2023
    → Generates outdated techniques
    → Hardcoded syscall numbers
    → Missing 2025 evasion methods
```

### **With Noctis RAG (Intelligence-Driven)**
```
User: "Generate CrowdStrike bypass"
AI: search_intelligence("CrowdStrike bypass")
    → Auto-fetches latest repos (2025)
    → Finds "CrowdStrike-unhook-2025" with 500 stars
    → Indexes kernel callback bypasses
    → generate_code() uses FRESH techniques
```

**Result**: AI generates payloads using code from THIS MONTH, not 2023 blog posts!

---

## 🔍 Troubleshooting

### **RAG not auto-updating?**

Check `data/intelligence_stats.json` exists:
```bash
python scripts/intelligence_updater.py --mode daily
```

### **GitHub API rate limit hit?**

Add GitHub token:
```bash
export GITHUB_TOKEN="ghp_..."
# Or add to .env file
```

### **Cron not running?**

Verify crontab:
```bash
crontab -l | grep Noctis-MCP
```

Check logs:
```bash
tail -f logs/intelligence/cron.log
```

---

## ✨ Summary

**Your Noctis-MCP intelligence system is:**

✅ **Fully Automatic** - No manual updates needed
✅ **Smart & Efficient** - Only fetches when stale or needed
✅ **Transparent** - AI sees `auto_updated=true` flag
✅ **Comprehensive** - 25+ elite security feeds
✅ **Cached** - 24hr smart cache prevents redundant fetches
✅ **Integrated** - Works seamlessly with existing workflow

**Just use it - the system handles the rest!** 🚀
