#!/bin/bash
# Build Linux binary using Docker

echo "🔨 Building Linux binary with PyInstaller..."

docker run --rm \
  -v "$(pwd)":/workspace \
  -w /workspace \
  python:3.11-slim bash -c "
    pip install -q pyinstaller click rich pyyaml requests jinja2 pygments aiohttp javalang esprima tree-sitter &&
    pyinstaller --clean --noconfirm \
      --onefile \
      --name=valid8 \
      --add-data='valid8:valid8' \
      --hidden-import=valid8.scanner \
      --hidden-import=valid8.cli \
      --hidden-import=valid8.detectors \
      valid8/__main__.py &&
    cp dist/valid8 /workspace/valid8-linux &&
    chmod +x /workspace/valid8-linux
"

if [ -f "valid8-linux" ]; then
    echo "✅ Linux binary built: valid8-linux"
    zip -j valid8-binaries/valid8-linux-amd64.zip valid8-linux
    echo "✅ Created: valid8-binaries/valid8-linux-amd64.zip"
else
    echo "❌ Build failed"
fi
