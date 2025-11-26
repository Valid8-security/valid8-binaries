# Windows Binary Memory Protection Fix

## Issue
Windows binary was causing system reboots due to attempting to write to read-only memory.

## Root Cause
PyInstaller was building with:
- UPX compression enabled (can cause memory protection issues)
- UAC admin requirements (can cause permission conflicts)
- Console mode issues

## Fix Applied
1. **Disabled UPX compression** (`--noupx`)
   - UPX can cause memory protection violations
   - Increases binary size but ensures stability

2. **Disabled UAC admin requirement** (`--uac-admin=false`)
   - Prevents permission conflicts
   - Allows normal user execution

3. **Set proper console mode** (`--noconsole`)
   - Prevents console window conflicts
   - Better for GUI/background execution

4. **Added binary testing**
   - Tests binary before packaging
   - Ensures it runs without crashing

## New Build Command
```powershell
pyinstaller --clean --noconfirm `
  --onefile `
  --name=valid8 `
  --add-data="valid8;valid8" `
  --hidden-import=valid8.scanner `
  --hidden-import=valid8.cli `
  --hidden-import=valid8.detectors `
  --noupx `
  --noconsole `
  --uac-admin=false `
  valid8/__main__.py
```

## Status
- ✅ Fixed workflow pushed
- ✅ New build triggered
- ⏱️ Waiting for build to complete (~5-10 minutes)
