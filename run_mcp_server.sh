#!/usr/bin/env bash
# Ubuntu MCP Server launcher script

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Run through the project environment managed by uv.
exec uv --directory "$SCRIPT_DIR" run --frozen ubuntu-mcp-server "$@"
