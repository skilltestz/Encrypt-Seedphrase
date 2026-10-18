#!/bin/bash
# Double-click launcher for macOS
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
cd "$DIR"
node "$DIR/app-server.js"
