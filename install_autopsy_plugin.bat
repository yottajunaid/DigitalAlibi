@echo off
echo ======================================
echo  Digital Alibi - Autopsy Installer    
echo ======================================

set "TARGET_DIR=%APPDATA%\autopsy\python_modules"

if not exist "%TARGET_DIR%" (
    echo Could not find your Autopsy python_modules folder at %TARGET_DIR%
    echo Please open Autopsy -^> Tools -^> Python Plugins, and manually copy Autopsy_DigitalAlibi_Ingest.py there.
    pause
    exit /b 1
)

if not exist "%TARGET_DIR%\DigitalAlibi" mkdir "%TARGET_DIR%\DigitalAlibi"

copy /Y "Autopsy_DigitalAlibi_Ingest.py" "%TARGET_DIR%\DigitalAlibi\" >nul
echo Success! The plugin has been installed.
echo Please restart Autopsy.
pause
