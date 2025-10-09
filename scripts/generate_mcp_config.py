#!/usr/bin/env python3
"""
Generate MCP Configuration with Correct Paths
==============================================

Automatically generates MCP configuration with your actual system paths.
Outputs config ready to paste into Cursor or Claude Desktop.
"""

import os
import sys
import json
import platform
from pathlib import Path

# Colors for terminal output
BLUE = '\033[0;34m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
NC = '\033[0m'  # No Color

def main():
    print(f"\n{BLUE}{'='*70}{NC}")
    print(f"{BLUE}MCP Configuration Generator for Noctis-MCP{NC}")
    print(f"{BLUE}{'='*70}{NC}\n")

    # Detect repository root
    script_dir = Path(__file__).parent.resolve()
    repo_root = script_dir.parent

    print(f"📂 Detected repository: {GREEN}{repo_root}{NC}")

    # Detect OS
    os_name = platform.system()
    print(f"💻 Operating System: {GREEN}{os_name}{NC}")

    # Find Python venv path
    if os_name == "Windows":
        venv_python = repo_root / "venv" / "Scripts" / "python.exe"
        config_locations = [
            Path.home() / "AppData" / "Roaming" / "Cursor" / "User" / "globalStorage" / "mcp.json",
            Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
        ]
    else:  # Linux/macOS
        venv_python = repo_root / "venv" / "bin" / "python"
        config_locations = [
            Path.home() / ".config" / "Cursor" / "User" / "globalStorage" / "mcp.json",
            Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "globalStorage" / "mcp.json",
            Path.home() / ".config" / "Claude" / "claude_desktop_config.json",
            Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        ]

    # Check if venv exists
    if not venv_python.exists():
        print(f"\n{YELLOW}⚠️  Warning: Virtual environment not found!{NC}")
        print(f"Expected: {venv_python}")
        print(f"\nRun setup first: ./scripts/setup/setup.sh")
        sys.exit(1)

    print(f"🐍 Python venv: {GREEN}{venv_python}{NC}\n")

    # Generate configuration
    config = {
        "mcpServers": {
            "noctis-mcp": {
                "command": str(venv_python),
                "args": [
                    "-m",
                    "noctis_mcp_client.noctis_mcp"
                ],
                "cwd": str(repo_root),
                "description": "Noctis-MCP v2.0 - 5 core malware development tools",
                "timeout": 300,
                "env": {
                    "PYTHONPATH": str(repo_root)
                }
            }
        }
    }

    # Display configuration
    print(f"{BLUE}{'='*70}{NC}")
    print(f"{BLUE}GENERATED MCP CONFIGURATION{NC}")
    print(f"{BLUE}{'='*70}{NC}\n")

    config_json = json.dumps(config, indent=2)
    print(config_json)

    print(f"\n{BLUE}{'='*70}{NC}")
    print(f"{BLUE}INSTALLATION INSTRUCTIONS{NC}")
    print(f"{BLUE}{'='*70}{NC}\n")

    # Detect IDE
    print("📝 Copy the configuration above and paste it into:\n")

    print(f"{GREEN}For Cursor IDE:{NC}")
    print("  1. Open Cursor")
    print("  2. Settings → Features → Model Context Protocol")
    print("  3. Click 'Edit Config' or 'Add Server'")
    print("  4. Paste the configuration above")
    print("  5. Save and completely restart Cursor\n")

    print(f"  {YELLOW}Or manually edit:{NC}")
    for loc in config_locations:
        if "Cursor" in str(loc):
            print(f"  {loc}")

    print(f"\n{GREEN}For Claude Desktop:{NC}")
    print("  1. Locate your Claude config file:")
    for loc in config_locations:
        if "Claude" in str(loc):
            print(f"     {loc}")
    print("  2. Add the 'noctis-mcp' server to 'mcpServers'")
    print("  3. Save and restart Claude Desktop")

    print(f"\n{BLUE}{'='*70}{NC}")
    print(f"{BLUE}VERIFICATION{NC}")
    print(f"{BLUE}{'='*70}{NC}\n")

    print("After configuring MCP:")
    print("  1. Start Noctis server: ./start_server.sh")
    print("  2. Restart your IDE completely")
    print("  3. Ask: 'What MCP tools do you have?'")
    print("  4. Should see 5 Noctis tools available\n")

    print(f"{GREEN}✅ Configuration generated successfully!{NC}\n")

    # Offer to save to file
    print(f"{YELLOW}💾 Save configuration?{NC}")
    save = input("Save to mcp_config.json? (y/N): ").lower().strip()

    if save == 'y':
        output_file = repo_root / "mcp_config.json"
        with open(output_file, 'w') as f:
            f.write(config_json)
        print(f"{GREEN}✅ Saved to: {output_file}{NC}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Cancelled by user{NC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{YELLOW}Error: {e}{NC}")
        sys.exit(1)
