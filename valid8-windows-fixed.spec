# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['valid8/__main__.py'],
    pathex=[],
    binaries=[],
    datas=[('valid8', 'valid8')],
    hiddenimports=[
        'valid8.scanner',
        'valid8.cli',
        'valid8.detectors',
        'valid8.detectors.cwe_expansion',
        'click',
        'rich',
        'yaml',
        'requests',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='valid8',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # Disable UPX to avoid memory issues
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=False,  # Don't require admin - avoids permission issues
)
