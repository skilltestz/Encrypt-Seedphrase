#!/bin/bash
# Launcher for Tails OS / Debian Linux
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
cd "$DIR"
if command -v node >/dev/null 2>&1; then
  node "$DIR/app-server.js"
else
  python3 "$DIR/seedvault-launcher.py"
fi
