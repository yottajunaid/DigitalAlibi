#!/bin/bash
echo "======================================"
echo " Digital Alibi - Autopsy Installer    "
echo "======================================"

TARGET_DIR="$HOME/snap/autopsy/common/.autopsy/dev/python_modules"
ALT_DIR="$HOME/.autopsy/dev/config/python_modules"

if [ -d "$TARGET_DIR" ]; then
    FINAL_DIR="$TARGET_DIR"
elif [ -d "$ALT_DIR" ]; then
    FINAL_DIR="$ALT_DIR"
else
    echo "Could not find your Autopsy python_modules folder."
    echo "Please open Autopsy -> Tools -> Python Plugins, and copy Autopsy_DigitalAlibi_Ingest.py there."
    exit 1
fi

mkdir -p "$FINAL_DIR/DigitalAlibi"
cp Autopsy_DigitalAlibi_Ingest.py "$FINAL_DIR/DigitalAlibi/"
echo "Success! Installed to $FINAL_DIR/DigitalAlibi"
echo "Please restart Autopsy."
