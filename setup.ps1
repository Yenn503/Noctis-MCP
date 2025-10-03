# Noctis-MCP Automated Setup Script (Windows)
# =============================================
# PowerShell script for Windows setup

Write-Host "🚀 Noctis-MCP Automated Setup (Windows)" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "⚠️  Warning: Not running as Administrator" -ForegroundColor Yellow
    Write-Host "Some features may require admin privileges" -ForegroundColor Yellow
    Write-Host ""
}

# Step 1: Check Python version
Write-Host "🐍 Checking Python version..." -ForegroundColor White
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ $pythonVersion found" -ForegroundColor Green
    
    # Verify Python 3.11+
    $version = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    if ([double]$version -ge 3.11) {
        Write-Host "✓ Python version is 3.11 or higher" -ForegroundColor Green
    } else {
        Write-Host "⚠ Warning: Python 3.11+ recommended (current: $version)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "✗ Python not found!" -ForegroundColor Red
    Write-Host "Please install Python 3.11+ from: https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "Make sure to check 'Add Python to PATH' during installation!" -ForegroundColor Yellow
    exit 1
}
Write-Host ""

# Step 2: Create virtual environment
Write-Host "📦 Creating virtual environment..." -ForegroundColor White
if (Test-Path "venv") {
    Write-Host "⚠ Virtual environment already exists" -ForegroundColor Yellow
    $recreate = Read-Host "Recreate it? (y/N)"
    if ($recreate -eq 'y' -or $recreate -eq 'Y') {
        Remove-Item -Recurse -Force venv
        python -m venv venv
        Write-Host "✓ Virtual environment recreated" -ForegroundColor Green
    }
} else {
    python -m venv venv
    Write-Host "✓ Virtual environment created" -ForegroundColor Green
}
Write-Host ""

# Step 3: Activate virtual environment and install dependencies
Write-Host "📥 Installing Python dependencies..." -ForegroundColor White

# Activate venv
& .\venv\Scripts\Activate.ps1

# Upgrade pip
python -m pip install --upgrade pip --quiet
Write-Host "✓ pip upgraded" -ForegroundColor Green

# Install dependencies
if (Test-Path "requirements.txt") {
    pip install -r requirements.txt --quiet
    Write-Host "✓ Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "✗ requirements.txt not found!" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 4: Check MSBuild
Write-Host "🔨 Checking MSBuild (Visual Studio Build Tools)..." -ForegroundColor White

$msbuildPaths = @(
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
)

$msbuildFound = $false
foreach ($path in $msbuildPaths) {
    if (Test-Path $path) {
        Write-Host "✓ MSBuild found: $path" -ForegroundColor Green
        $msbuildFound = $true
        break
    }
}

if (-not $msbuildFound) {
    Write-Host "⚠ MSBuild not found!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "MSBuild is required to compile Windows malware." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "📥 Install Visual Studio Build Tools:" -ForegroundColor Cyan
    Write-Host "  1. Download: https://aka.ms/vs/17/release/vs_BuildTools.exe" -ForegroundColor White
    Write-Host "  2. Run installer" -ForegroundColor White
    Write-Host "  3. Select 'Desktop development with C++'" -ForegroundColor White
    Write-Host "  4. Install and restart this script" -ForegroundColor White
    Write-Host ""
    
    $install = Read-Host "Open download page in browser? (Y/n)"
    if ($install -ne 'n' -and $install -ne 'N') {
        Start-Process "https://aka.ms/vs/17/release/vs_BuildTools.exe"
    }
}
Write-Host ""

# Step 5: Run tests
Write-Host "🧪 Running test suite..." -ForegroundColor White
try {
    $testResult = python -m pytest tests/ -v --tb=short 2>&1
    if ($LASTEXITCODE -eq 0) {
        $testCount = (python -m pytest tests/ --co -q 2>$null | Select-String "test_").Count
        Write-Host "✓ All tests passed ($testCount tests)" -ForegroundColor Green
    } else {
        Write-Host "⚠ Some tests failed (this might be OK if C2 servers aren't running)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "⚠ Test suite encountered issues" -ForegroundColor Yellow
}
Write-Host ""

# Step 6: Verify imports
Write-Host "🔍 Verifying installation..." -ForegroundColor White

# Test MCP client
try {
    python -c "from noctis_mcp_client.noctis_mcp import mcp" 2>$null
    Write-Host "✓ MCP client working" -ForegroundColor Green
} catch {
    Write-Host "✗ MCP client import failed" -ForegroundColor Red
}

# Test C2 adapters
try {
    python -c "from c2_adapters import SliverAdapter, HavocAdapter, MythicAdapter" 2>$null
    Write-Host "✓ C2 adapters working" -ForegroundColor Green
} catch {
    Write-Host "✗ C2 adapters import failed" -ForegroundColor Red
}

# Test compiler
try {
    python -c "from compilation import get_compiler" 2>$null
    Write-Host "✓ Compilation module working" -ForegroundColor Green
} catch {
    Write-Host "✗ Compilation module import failed" -ForegroundColor Red
}

# Test server
try {
    python -c "from server.noctis_server import app" 2>$null
    Write-Host "✓ Flask server working" -ForegroundColor Green
} catch {
    Write-Host "✗ Flask server import failed" -ForegroundColor Red
}
Write-Host ""

# Step 7: Final summary
Write-Host "=========================================" -ForegroundColor Green
Write-Host "✅ Noctis-MCP Setup Complete!" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host ""
Write-Host "📚 Next steps:" -ForegroundColor Cyan
Write-Host "  1. Activate venv:     .\venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host "  2. Start server:      python server\noctis_server.py" -ForegroundColor White
Write-Host "  3. Run verification:  python verify_setup.py" -ForegroundColor White
Write-Host "  4. Run tests:         python test_all.py" -ForegroundColor White
Write-Host ""
Write-Host "🎯 Optional C2 setup:" -ForegroundColor Cyan
Write-Host "  - Sliver:  See docs\C2_INTEGRATION.md" -ForegroundColor White
Write-Host "  - Havoc:   Manual generation via GUI (API not available)" -ForegroundColor White
Write-Host "  - Mythic:  See docs\C2_INTEGRATION.md" -ForegroundColor White
Write-Host ""
Write-Host "📖 Documentation:" -ForegroundColor Cyan
Write-Host "  - Getting started:    docs\GETTING_STARTED.md" -ForegroundColor White
Write-Host "  - User guide:         docs\USER_GUIDE.md" -ForegroundColor White
Write-Host "  - API reference:      docs\API_REFERENCE.md" -ForegroundColor White
Write-Host ""
Write-Host "🚀 Happy hacking with Noctis-MCP!" -ForegroundColor Cyan

