# Building Valid8 for Windows and Linux

## Windows Build

1. Install Python 3.8+ on Windows
2. Install PyInstaller: pip install pyinstaller
3. Run: pyinstaller --onefile --name=valid8 valid8/__main__.py
4. Zip the valid8.exe from dist/

## Linux Build

1. Install Python 3.8+ on Linux
2. Install PyInstaller: pip install pyinstaller
3. Run: pyinstaller --onefile --name=valid8 valid8/__main__.py
4. Zip the valid8 binary from dist/

## Using Docker (Cross-platform)

docker run -v $(pwd):/workspace python:3.11 bash -c "
  cd /workspace &&
  pip install pyinstaller -r requirements.txt &&
  pyinstaller --onefile --name=valid8 valid8/__main__.py
"
