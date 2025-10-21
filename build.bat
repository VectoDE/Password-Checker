@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "OUTPUT_DIR=%SCRIPT_DIR%\bin"

if not exist "%OUTPUT_DIR%" (
    mkdir "%OUTPUT_DIR%"
)

echo Building Password Checker for Windows (amd64)...
set "GOOS=windows"
set "GOARCH=amd64"
go build -o "%OUTPUT_DIR%\password-checker.exe" ./cmd/password-checker
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

echo Build complete: %OUTPUT_DIR%\password-checker.exe
endlocal
