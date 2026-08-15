@echo off
:: ============================================================
::  SpotX+ Launcher
::  Downloads and runs the SpotX+ PowerShell patcher.
::  
::  Usage: Double-click this file or run from command prompt.
::  
::  To customize, add parameters after -ExecutionPolicy Bypass:
::    -NoPodcastFilter   : Keep podcasts on homepage
::    -NoUpdateBlock     : Don't block Spotify updates
::    -LaunchAfter       : Auto-launch Spotify after patching
::    -SkipInstall       : Only patch, don't download Spotify
:: ============================================================

title SpotX+ — Spotify Patcher

:: ── Check for PowerShell ──
where powershell >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] PowerShell is not installed or not in PATH.
    echo Please install Windows Management Framework 5.1 or later.
    pause
    exit /b 1
)

:: ── Run SpotX+ ──
if exist "%~dp0SpotX+.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0SpotX+.ps1" -LaunchAfter
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "& { iwr 'https://raw.githubusercontent.com/Mehmetyll/SpotX-Plus/main/SpotX+.ps1' -UseBasicParsing | iex }"
)

pause
