@echo off
setlocal
cd /d "%~dp0"

set CGO_ENABLED=0
set GOARCH=amd64

echo Building publisher.exe (GUI, no console window)...
go build -ldflags "-H=windowsgui -s -w" -trimpath -o publisher.exe .
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)
echo Done: publisher.exe
echo Double-click publisher.exe to open the GUI, or run with args for CLI.
