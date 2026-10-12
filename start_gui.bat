@echo off
setlocal
cd /d "%~dp0"
if exist "target\release\tg-stealth-proxy.exe" (
    start "" "target\release\tg-stealth-proxy.exe"
) else (
    echo [INFO] Release binary not found. Compiling via cargo build --release...
    cargo build --release
    if exist "target\release\tg-stealth-proxy.exe" (
        start "" "target\release\tg-stealth-proxy.exe"
    ) else (
        echo [ERROR] Build failed. Please check compiler output above.
        pause
    )
)
