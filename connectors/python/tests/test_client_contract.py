import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest

from ubuntu_fleet_manager_client import connect_http, connect_stdio


ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = ROOT / "schemas" / "mcp-local-stdio-contract.json"


def load_contract():
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


class StdioContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_startup_failure_is_surfaced(self):
        with self.assertRaises(OSError):
            async with connect_stdio("/definitely/not/an/ubuntu-fleet-manager-binary"):
                self.fail("stdio connection unexpectedly opened")

    async def test_go_runtime_discovery_and_structured_result(self):
        binary = os.environ.get("UFM_SERVER_BINARY")
        self.assertTrue(binary, "set UFM_SERVER_BINARY to the built Go runtime")

        async with asyncio.timeout(20):
            async with connect_stdio(binary) as client:
                listed = await client.list_tools()
                observed_tools = [tool.model_dump(by_alias=True, exclude_none=True) for tool in listed.tools]
                self.assertEqual(observed_tools, load_contract()["tools"])

                result = await client.call_tool("get_system_info", {})
                payload = result.model_dump(by_alias=True, exclude_none=True)
                self.assertFalse(payload.get("isError", False), payload)
                info = payload.get("structuredContent")
                self.assertIsInstance(info, dict)
                self.assertEqual(sorted(info), load_contract()["resultFields"])
                self.assertTrue(info["hostname"])
                self.assertTrue(info["architecture"])
                self.assertGreater(info["memory"]["total_bytes"], 0)
                self.assertGreater(info["root_filesystem"]["total_bytes"], 0)

    async def test_host_policy_error_and_confirmation_annotations_are_preserved(self):
        binary = os.environ.get("UFM_SERVER_BINARY")
        self.assertTrue(binary, "set UFM_SERVER_BINARY to the built Go runtime")

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            home = root / "home"
            home.mkdir(mode=0o700)
            policy_path = root / "apt-policy.json"
            policy_path.write_text(
                json.dumps(
                    {
                        "enabled": True,
                        "allowed_operations": ["install", "rollback"],
                        "allowed_packages": ["curl"],
                    }
                ),
                encoding="utf-8",
            )
            policy_path.chmod(0o600)
            key_path = root / "action-key"
            key_path.write_bytes(b"0123456789abcdef0123456789abcdef")
            key_path.chmod(0o600)

            async with connect_stdio(
                binary,
                args=[
                    "--local-apt-policy-file",
                    str(policy_path),
                    "--local-apt-key-file",
                    str(key_path),
                ],
                env={"HOME": str(home)},
            ) as client:
                listed = await client.list_tools()
                install = next(tool for tool in listed.tools if tool.name == "apt_install")
                annotations = install.annotations.model_dump(by_alias=True, exclude_none=True)
                self.assertTrue(annotations["destructiveHint"])
                self.assertFalse(annotations["readOnlyHint"])
                self.assertFalse(annotations["idempotentHint"])

                result = await client.call_tool("apt_install", {"packages": ["wget"]})
                payload = result.model_dump(by_alias=True, exclude_none=True)
                self.assertTrue(payload["isError"], payload)
                self.assertTrue(payload["content"])


class HTTPTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_authenticated_go_streamable_http_contract(self):
        binary = os.environ.get("UFM_HTTP_SERVER_BINARY")
        self.assertTrue(binary, "set UFM_HTTP_SERVER_BINARY to the MCP HTTP contract fixture")

        process = await asyncio.create_subprocess_exec(
            binary,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            line = await asyncio.wait_for(process.stdout.readline(), timeout=10)
            self.assertTrue(line, "the HTTP contract fixture exited before announcing its URL")
            url = line.decode("utf-8").strip()
            async with connect_http(url, token="fixture-token") as client:
                listed = await client.list_tools()
                observed_tools = [tool.model_dump(by_alias=True, exclude_none=True) for tool in listed.tools]
                self.assertEqual(observed_tools, load_contract()["tools"])
                result = await client.call_tool("get_system_info", {})
                payload = result.model_dump(by_alias=True, exclude_none=True)
                self.assertFalse(payload.get("isError", False), payload)
                self.assertEqual(sorted(payload["structuredContent"]), load_contract()["resultFields"])
        finally:
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=3)
                except TimeoutError:
                    process.kill()
                    await process.wait()

    async def test_bearer_authentication_failure_is_surfaced(self):
        class RejectUnauthorizedHandler(BaseHTTPRequestHandler):
            authorization = None

            def do_POST(self):
                self.server.authorization = self.headers.get("Authorization")
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, _format, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), RejectUnauthorizedHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/mcp"
            with self.assertRaises(Exception) as caught:
                async with connect_http(url, token="test-token"):
                    self.fail("a 401 response must prevent the MCP connection")
            self.assertNotIsInstance(caught.exception, AssertionError)
            self.assertEqual(server.authorization, "Bearer test-token")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
