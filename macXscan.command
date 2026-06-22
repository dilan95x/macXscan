#!/usr/bin/env bash
# macXscan.command — double-click this file in Finder to run a security scan.
# macOS will open it in Terminal automatically.

cd "$(dirname "$0")"
bash mac-security-scan.sh
