# Build Windows binary with PyInstaller
# Run this on Windows with PowerShell

Write-Host "🔨 Building Windows binary with PyInstaller..." -ForegroundColor Cyan

# Install PyInstaller if not present
pip install pyinstaller

# Install dependencies
pip install click rich pyyaml requests jinja2 pygments aiohttp javalang esprima tree-sitter

# Build binary
pyinstaller --clean --noconfirm `
    --onefile `
    --name=valid8 `
    --add-data="valid8;valid8" `
    --hidden-import=valid8.scanner `
    --hidden-import=valid8.cli `
    --hidden-import=valid8.detectors `
    valid8/__main__.py

if (Test-Path "dist\valid8.exe") {
    Write-Host "✅ Windows binary built: dist\valid8.exe" -ForegroundColor Green
    Compress-Archive -Path dist\valid8.exe -DestinationPath valid8-binaries\valid8-windows-amd64.zip -Force
    Write-Host "✅ Created: valid8-binaries\valid8-windows-amd64.zip" -ForegroundColor Green
} else {
    Write-Host "❌ Build failed" -ForegroundColor Red
}
