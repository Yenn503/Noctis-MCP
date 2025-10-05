#!/bin/bash
#
# Noctis-MCP Auto-Update Setup Script
# ====================================
#
# Configures cron jobs for automated intelligence gathering
#
# Usage:
#   chmod +x scripts/setup_auto_update.sh
#   ./scripts/setup_auto_update.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "===================================================================="
echo "  Noctis-MCP Auto-Update Setup"
echo "===================================================================="
echo -e "${NC}"

# Get project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PYTHON="$PROJECT_ROOT/venv/bin/python"
UPDATER_SCRIPT="$PROJECT_ROOT/scripts/intelligence_updater.py"
CRON_LOG="$PROJECT_ROOT/logs/intelligence/cron.log"

echo -e "${YELLOW}[*] Project root: $PROJECT_ROOT${NC}"
echo -e "${YELLOW}[*] Python: $VENV_PYTHON${NC}"
echo -e "${YELLOW}[*] Updater: $UPDATER_SCRIPT${NC}"
echo ""

# Verify files exist
if [ ! -f "$VENV_PYTHON" ]; then
    echo -e "${RED}[!] Virtual environment not found at $VENV_PYTHON${NC}"
    echo -e "${RED}[!] Run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt${NC}"
    exit 1
fi

if [ ! -f "$UPDATER_SCRIPT" ]; then
    echo -e "${RED}[!] Updater script not found at $UPDATER_SCRIPT${NC}"
    exit 1
fi

# Make updater executable
chmod +x "$UPDATER_SCRIPT"

# Create log directory
mkdir -p "$PROJECT_ROOT/logs/intelligence"

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macOS"
    CRON_CMD="crontab"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="Linux"
    CRON_CMD="crontab"
else
    echo -e "${RED}[!] Unsupported OS: $OSTYPE${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Detected OS: $OS${NC}"
echo ""

# Ask user for schedule preference
echo -e "${BLUE}Select update schedule:${NC}"
echo "  1) Daily at 2 AM (recommended)"
echo "  2) Daily at 2 AM + Weekly full refresh on Sunday 3 AM"
echo "  3) Custom schedule"
echo "  4) Manual only (no cron)"
echo ""
read -p "Enter choice [1-4]: " schedule_choice

case $schedule_choice in
    1)
        # Daily only
        CRON_ENTRIES=(
            "0 2 * * * cd $PROJECT_ROOT && $VENV_PYTHON $UPDATER_SCRIPT --mode daily >> $CRON_LOG 2>&1"
        )
        echo -e "${GREEN}[+] Selected: Daily at 2 AM${NC}"
        ;;
    2)
        # Daily + Weekly
        CRON_ENTRIES=(
            "0 2 * * 1-6 cd $PROJECT_ROOT && $VENV_PYTHON $UPDATER_SCRIPT --mode daily >> $CRON_LOG 2>&1"
            "0 3 * * 0 cd $PROJECT_ROOT && $VENV_PYTHON $UPDATER_SCRIPT --mode weekly >> $CRON_LOG 2>&1"
        )
        echo -e "${GREEN}[+] Selected: Daily (2 AM) + Weekly full refresh (Sunday 3 AM)${NC}"
        ;;
    3)
        # Custom
        echo ""
        echo -e "${YELLOW}Enter cron schedule (e.g., '0 */6 * * *' for every 6 hours):${NC}"
        read -p "Schedule: " custom_schedule
        read -p "Mode [daily/weekly]: " custom_mode
        CRON_ENTRIES=(
            "$custom_schedule cd $PROJECT_ROOT && $VENV_PYTHON $UPDATER_SCRIPT --mode $custom_mode >> $CRON_LOG 2>&1"
        )
        echo -e "${GREEN}[+] Selected: Custom schedule${NC}"
        ;;
    4)
        # Manual only
        echo -e "${YELLOW}[*] Skipping cron setup. Run manually:${NC}"
        echo -e "${YELLOW}    $VENV_PYTHON $UPDATER_SCRIPT --mode daily${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}[!] Invalid choice${NC}"
        exit 1
        ;;
esac

# Backup existing crontab
BACKUP_FILE="$PROJECT_ROOT/logs/crontab_backup_$(date +%Y%m%d_%H%M%S).txt"
crontab -l > "$BACKUP_FILE" 2>/dev/null || echo "# New crontab" > "$BACKUP_FILE"
echo -e "${GREEN}[+] Backed up existing crontab to: $BACKUP_FILE${NC}"

# Add new cron entries
TEMP_CRON=$(mktemp)
crontab -l 2>/dev/null > "$TEMP_CRON" || true

# Add header
echo "" >> "$TEMP_CRON"
echo "# Noctis-MCP Intelligence Auto-Update (Added $(date))" >> "$TEMP_CRON"

# Add entries
for entry in "${CRON_ENTRIES[@]}"; do
    echo "$entry" >> "$TEMP_CRON"
done

# Install new crontab
crontab "$TEMP_CRON"
rm "$TEMP_CRON"

echo -e "${GREEN}[+] Cron jobs installed successfully!${NC}"
echo ""

# Show installed cron jobs
echo -e "${BLUE}Installed cron jobs:${NC}"
crontab -l | grep -A 10 "Noctis-MCP" || echo "No Noctis-MCP cron jobs found"
echo ""

# Test run
echo -e "${YELLOW}[*] Testing updater script...${NC}"
if $VENV_PYTHON "$UPDATER_SCRIPT" --mode daily --dry-run 2>&1 | head -20; then
    echo -e "${GREEN}[+] Test successful!${NC}"
else
    echo -e "${RED}[!] Test failed. Check configuration.${NC}"
    exit 1
fi

# Final instructions
echo ""
echo -e "${BLUE}===================================================================="
echo "  Setup Complete!"
echo "====================================================================${NC}"
echo ""
echo -e "${GREEN}✅ Auto-update is now configured!${NC}"
echo ""
echo -e "${YELLOW}Cron jobs will run:${NC}"
for entry in "${CRON_ENTRIES[@]}"; do
    echo "  - $entry"
done
echo ""
echo -e "${YELLOW}Logs will be written to:${NC}"
echo "  $CRON_LOG"
echo ""
echo -e "${YELLOW}To view cron jobs:${NC}"
echo "  crontab -l"
echo ""
echo -e "${YELLOW}To remove cron jobs:${NC}"
echo "  crontab -e  # Then delete Noctis-MCP entries"
echo ""
echo -e "${YELLOW}To test manually:${NC}"
echo "  $VENV_PYTHON $UPDATER_SCRIPT --mode daily"
echo ""
echo -e "${BLUE}====================================================================${NC}"
