# Contributing to Noctis-MCP

Thank you for your interest in contributing to **Noctis-MCP**! This is a community-driven open source project, and we welcome contributions from security researchers, malware analysts, and developers.

## 🎯 Project Vision

Noctis-MCP aims to democratize advanced malware development techniques for **authorized security research** by creating an AI-driven platform that makes sophisticated evasion techniques accessible to red teams and security researchers.

## 🤝 How to Contribute

### 1. **Add New Techniques**

The most valuable contribution is adding new evasion/injection/persistence techniques.

**Steps:**
1. Add your technique source code to `Examples/` directory
2. Follow the naming convention: `Examples/YourName/TechniqueName/`
3. Include a README.md explaining the technique
4. Run the technique indexer: `python utils/technique_indexer.py`
5. Submit a Pull Request

**Example Structure:**
```
Examples/
└── CommunityContributions/
    └── YourUsername/
        └── NewTechnique/
            ├── README.md          # Explanation
            ├── technique.c        # Source code
            ├── technique.h        # Headers
            └── metadata.json      # Manual metadata (optional)
```

**Required Information:**
- Technique name and description
- MITRE ATT&CK mapping
- Tested Windows versions
- Detection status (which AVs detect it)
- OPSEC considerations
- Source attribution

### 2. **Improve Existing Techniques**

Found a way to improve an existing technique?

1. Create a variant in your own folder
2. Document what you improved (OPSEC score, detection rate, etc.)
3. Link to the original technique
4. Submit PR with comparison

### 3. **Enhance the AI Engine**

Contributions to the core engine:

- **Code Assembler**: Better technique combination logic
- **OPSEC Analyzer**: New detection pattern recognition
- **Learning Engine**: Improved ML models for technique selection
- **Auto-Fix Engine**: Better error detection and fixing

### 4. **Add C2 Framework Support**

Create adapters for additional C2 frameworks:

```python
# c2_adapters/your_c2_adapter.py
class YourC2Adapter(C2Adapter):
    def generate_shellcode_stub(self) -> bytes:
        """Implementation"""
    
    def wrap_with_techniques(self, shellcode, techniques) -> str:
        """Implementation"""
```

### 5. **Documentation**

- Improve README clarity
- Add usage examples
- Create tutorials
- Write technique guides
- Translate documentation

### 6. **Testing**

- Add unit tests for new features
- Test techniques against different AVs
- Report detection rates
- Create test cases

## 📋 Contribution Guidelines

### Code Standards

**Python Code:**
- Follow PEP 8 style guide
- Use type hints where possible
- Add docstrings to all functions
- Keep functions focused and small
- Use meaningful variable names

```python
def parse_technique(file_path: str, technique_type: str) -> TechniqueMetadata:
    """
    Parse a technique source file and extract metadata.
    
    Args:
        file_path: Path to the technique source file
        technique_type: Type of technique (evasion, injection, etc.)
    
    Returns:
        TechniqueMetadata object with parsed information
    
    Raises:
        FileNotFoundError: If source file doesn't exist
        ParseError: If file cannot be parsed
    """
    # Implementation
```

**C/C++ Code:**
- Comment your code thoroughly
- Include OPSEC considerations in comments
- Avoid hardcoded strings when possible
- Document Windows version compatibility

```c
/*
 * API Hashing with Timing Jitter
 * 
 * OPSEC: High stealth - adds random delays to avoid signature detection
 * Tested: Windows 10 21H2, Windows 11 22H2
 * Bypasses: Static analysis, basic behavioral detection
 * Detected by: Advanced ML-based AV (as of 2024-01)
 * 
 * MITRE ATT&CK: T1027 (Obfuscated Files or Information)
 */
FARPROC GetProcAddressH(HMODULE hModule, UINT32 uApiHash) {
    // Implementation
}
```

### Commit Messages

Use clear, descriptive commit messages:

```
✅ Good:
feat: Add GPU evasion technique with D3D11 integration
fix: Resolve compilation error in API hashing module
docs: Update OPSEC guide with CrowdStrike bypass notes

❌ Bad:
Update code
Fix bug
Changes
```

**Format:**
```
<type>: <subject>

<body (optional)>

<footer (optional)>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code formatting
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

### Pull Request Process

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feature/your-feature-name`
3. **Make changes** and commit with clear messages
4. **Test your changes** thoroughly
5. **Update documentation** if needed
6. **Submit PR** with detailed description

**PR Template:**
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] New technique
- [ ] Bug fix
- [ ] Enhancement
- [ ] Documentation
- [ ] Other (specify)

## Technique Information (if applicable)
- **Technique Name**: 
- **Category**: (evasion/injection/persistence/etc.)
- **MITRE ATT&CK**: T1XXX
- **Tested On**: Windows 10/11 version
- **Detection Status**: AV detection results
- **OPSEC Score**: X/10

## Testing
- [ ] Code compiles without errors
- [ ] Technique tested and working
- [ ] OPSEC analysis performed
- [ ] Documentation updated

## Additional Notes
Any other relevant information
```

## 🔒 Security & Ethics

### ⚠️ Critical Guidelines

1. **Legal Use Only**
   - Only contribute techniques for authorized security research
   - Never share techniques designed for malicious purposes
   - Include legal disclaimers in documentation

2. **No Malicious Payloads**
   - Do NOT commit actual malware binaries
   - Do NOT include working exploits for unpatched vulnerabilities
   - Do NOT share credentials or access tokens

3. **Responsible Disclosure**
   - If your technique bypasses a major AV, consider responsible disclosure
   - Don't publicly expose zero-day evasion techniques immediately
   - Work with vendors when appropriate

4. **Attribution**
   - Give credit to original researchers
   - Link to source material (papers, blog posts)
   - Respect licenses of referenced code

### What NOT to Contribute

❌ **Do NOT contribute:**
- Actual malware samples (binaries)
- Working exploits for current vulnerabilities
- Credentials or API keys
- Techniques designed purely for harm
- Code that violates laws in major jurisdictions
- Plagiarized or unlicensed code

✅ **DO contribute:**
- Educational evasion techniques
- Defensive research findings
- Tool improvements
- Documentation
- Test frameworks
- C2 framework integrations (for authorized use)

## 🧪 Testing Your Contribution

### Local Testing

```bash
# 1. Install development dependencies
pip install -r requirements.txt

# 2. Run technique indexer on your new technique
python utils/technique_indexer.py --path Examples/YourUsername/NewTechnique/

# 3. Start server and test
python server/noctis_server.py

# 4. Test via API
curl -X POST http://localhost:8888/api/techniques/query \
  -H "Content-Type: application/json" \
  -d '{"category": "your_category"}'

# 5. Run unit tests
pytest tests/

# 6. Check code quality
black server/ mcp/ utils/
flake8 server/ mcp/ utils/
mypy server/ mcp/ utils/
```

### OPSEC Testing

When adding techniques:

1. **Compile the technique** in a clean Windows VM
2. **Test execution** - Does it work as intended?
3. **Static analysis** - Scan with VirusTotal, strings, PE tools
4. **Dynamic analysis** - Test against Windows Defender
5. **Document results** - Include detection rates in metadata

## 💬 Communication

### Getting Help

- **GitHub Issues**: For bugs, feature requests, questions
- **GitHub Discussions**: For general discussion, ideas
- **Pull Request Comments**: For code-specific questions

### Community Guidelines

- Be respectful and professional
- Help newcomers learn
- Share knowledge generously
- Provide constructive feedback
- Follow the Code of Conduct

## 🏆 Recognition

Contributors will be recognized in:
- **CONTRIBUTORS.md** - Hall of fame
- **Technique metadata** - Your name on techniques you contribute
- **Release notes** - Mentioned in version releases

Top contributors may become **maintainers** with commit access.

## 📚 Resources for Contributors

### Learning Resources

- [MalDev Academy](https://maldevacademy.com) - Malware development courses
- [MITRE ATT&CK](https://attack.mitre.org/) - Adversary tactics reference
- [Windows Internals](https://docs.microsoft.com/en-us/windows/win32/) - Microsoft docs
- [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) - Inspiration project

### Recommended Tools

- **Visual Studio 2022** - For Windows compilation
- **x64dbg** - For debugging
- **PE-bear** - For PE analysis
- **Process Hacker** - For runtime analysis
- **VirusTotal** - For detection testing

## 🚀 Getting Started

**First-time contributor?**

1. **Star the repository** ⭐
2. **Read the README.md** to understand the project
3. **Look at existing examples** in `Examples/` folder
4. **Find an issue tagged `good-first-issue`**
5. **Comment on the issue** to let us know you're working on it
6. **Submit your first PR!**

**Questions?** Open a GitHub Discussion or Issue.

---

## 📝 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to Noctis-MCP! Together we're building the most advanced AI-driven malware development platform for the security community.** 🌙⚔️

---

*Last Updated: 2024-10-03*  
*Senior Developer: AI Agent (Claude)*  
*Community Maintainers: Open Source Contributors*

