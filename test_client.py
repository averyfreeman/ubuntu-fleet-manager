#!/usr/bin/env python3
"""
Test client for Ubuntu MCP Server
"""

import asyncio
import json
import sys
import tempfile
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def test_mcp_client():
    """Test the MCP server using a client"""

    print("🚀 Starting Ubuntu MCP Server test...")

    # Start the server process
    server_params = StdioServerParameters(
        command="python3",
        args=["main.py"],
        env=None
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the session
            await session.initialize()

            print("✅ Connected to Ubuntu MCP Server")

            # List available tools
            tools = await session.list_tools()
            print(f"\n📋 Available tools: {[tool.name for tool in tools.tools]}")

            # Test system info
            print("\n🖥️  Testing system info...")
            result = await session.call_tool("get_system_info", {})
            system_info = json.loads(result.content[0].text)
            print(f"OS: {system_info['os_info'].get('PRETTY_NAME', 'Unknown')}")
            print(f"User: {system_info['current_user']}")

            # Test command execution
            print("\n⚡ Testing command execution...")
            result = await session.call_tool("execute_command", {
                "command": "echo 'Hello from MCP client!'"
            })
            cmd_result = json.loads(result.content[0].text)
            print(f"Command output: {cmd_result['stdout'].strip()}")

            state_temp_dir = Path.home() / ".local" / "state" / "ubuntu-mcp" / "tmp"
            state_temp_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            state_temp_dir.chmod(0o700)
            with tempfile.TemporaryDirectory(
                prefix=".ubuntu-mcp-client-",
                dir=str(state_temp_dir),
            ) as temp_dir:
                # Test directory listing
                print("\n📁 Testing directory listing...")
                result = await session.call_tool("list_directory", {"path": temp_dir})
                items = json.loads(result.content[0].text)
                print(f"Found {len(items)} items in the private test directory")

                # Test file operations
                print("\n📝 Testing file operations...")
                test_content = "This is a test from the MCP client"
                test_file = str(Path(temp_dir) / "mcp_client_test.txt")
                await session.call_tool("write_file", {
                    "file_path": test_file,
                    "content": test_content
                })

                result = await session.call_tool("read_file", {
                    "file_path": test_file
                })
                read_content = result.content[0].text
                print(f"File content: {read_content}")

            # Test package search
            print("\n🔍 Testing package search...")
            result = await session.call_tool("search_packages", {"query": "curl"})
            search_output = result.content[0].text
            lines = search_output.split('\n')[:5]  # First 5 lines
            print("Package search results:")
            for line in lines:
                if line.strip():
                    print(f"  {line.strip()}")

            print("\n✅ All MCP tests completed successfully!")


async def simple_test():
    """Simple test without full MCP protocol"""
    print("🧪 Running simple functionality test...")

    from main import create_secure_policy, SecureUbuntuController

    policy = create_secure_policy()
    controller = SecureUbuntuController(policy)

    # Test basic operations
    print("✅ Controller created")

    # Test command
    result = await controller.execute_command("whoami")
    print(f"Current user: {result['stdout'].strip()}")

    # Test system info
    info = controller.get_system_info()
    print(f"OS: {info['os_info'].get('PRETTY_NAME', 'Unknown')}")

    print("✅ Simple test completed")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--simple":
        asyncio.run(simple_test())
    else:
        asyncio.run(test_mcp_client())
