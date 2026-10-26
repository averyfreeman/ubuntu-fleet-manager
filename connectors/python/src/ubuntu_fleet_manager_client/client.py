"""Transport helpers that preserve the Go runtime's MCP contract."""

from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from os import PathLike

from httpx2 import AsyncClient, Timeout
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client


@asynccontextmanager
async def connect_stdio(
    command: str | PathLike[str],
    *,
    args: Sequence[str] = (),
    env: Mapping[str, str] | None = None,
) -> AsyncIterator[Client]:
    """Launch the Go MCP runtime over stdio and yield its SDK client.

    The Python MCP SDK supplies a minimal child environment; values in ``env``
    are explicit additions. No tool policy or result conversion is performed.
    """
    parameters = StdioServerParameters(
        command=str(command),
        args=list(args),
        env=dict(env) if env is not None else None,
    )
    async with Client(parameters) as client:
        yield client


@asynccontextmanager
async def connect_http(
    url: str,
    *,
    token: str | None = None,
) -> AsyncIterator[Client]:
    """Connect to a Streamable HTTP MCP endpoint and yield its SDK client.

    When ``token`` is provided, it is sent as a bearer token. Authentication,
    authorization, and transport failures are raised by the MCP SDK unchanged.
    """
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    http_client = AsyncClient(
        headers=headers,
        timeout=Timeout(30.0, read=300.0),
    )
    try:
        transport = streamable_http_client(url, http_client=http_client)
        async with Client(transport) as client:
            yield client
    finally:
        await http_client.aclose()
