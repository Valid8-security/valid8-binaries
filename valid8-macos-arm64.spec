# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['valid8/__main__.py'],
    pathex=[],
    binaries=[],
    datas=[('valid8/models', 'valid8/models')],
    hiddenimports=['valid8.scanner', 'valid8.language_support', 'valid8.language_support.java_analyzer', 'valid8.language_support.python_analyzer', 'valid8.language_support.javascript_analyzer', 'valid8.language_support.base', 'valid8.language_support.universal_detectors', 'valid8.ai_detector', 'valid8.models', 'sklearn', 'sklearn.ensemble', 'numpy', 'ast', 're', 'json', 'typing', 'pathlib'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='valid8-macos-arm64',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
