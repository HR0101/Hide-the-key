#!/usr/bin/env bash
# ==============================================================================
#  HideTheKey - macOS Finder Launcher (.command)
#  Double-click this file in Finder to check any directory for leaked API keys!
# ==============================================================================

# Change working directory to the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

export PYTHONPATH="$DIR:$PYTHONPATH"

# Run interactive CLI
python3 -m hide_the_key.cli --interactive

echo ""
echo "================================================================="
read -p "Finished! Press [Enter] to close this window..." dummy
