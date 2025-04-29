@echo off
echo =============================================
echo 🚀 Building CrewAI Vulnerability Scanner EXE
echo =============================================

if exist build (
    rmdir /s /q build
)
if exist dist (
    rmdir /s /q dist
)

echo 🔥 Running PyInstaller...
pyinstaller --onefile --name crewai_scanner crewai_scanner.py

echo =============================================
echo ✅ Build Completed! Find EXE in dist\
echo =============================================
pause
