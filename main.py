"""Backward-compatible entry point. Prefer ubuntu-mcp-server after installation."""
from ubuntu_mcp_server.server import *  # noqa: F403
from ubuntu_mcp_server.server import cli

if __name__ == "__main__":
    cli()
