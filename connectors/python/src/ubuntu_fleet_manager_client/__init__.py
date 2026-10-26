"""Thin Python connections to the Ubuntu Fleet Manager MCP runtime."""

from .client import connect_http, connect_stdio

__all__ = ["connect_http", "connect_stdio"]
