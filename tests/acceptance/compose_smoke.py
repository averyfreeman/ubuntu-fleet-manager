"""Clean Compose deployment acceptance for MCP auth, enrollment, and reversal."""

import asyncio
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from ubuntu_fleet_manager_client import connect_http


ROOT = Path(__file__).resolve().parents[2]
AUDIENCE = "ubuntu-fleet-manager-ci"


def free_port():
    with socket.socket() as listener:
        # Reserve against listeners bound to any host interface, because the
        # OIDC fixture listens on 0.0.0.0 for container-to-host traffic.
        listener.bind(("0.0.0.0", 0))
        return listener.getsockname()[1]


def wait_for_json(url, *, context=None, timeout=60, process=None):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            details = process.stderr.read() if process.stderr else ""
            raise RuntimeError(f"process exited while waiting for {url}: {details.strip()}")
        try:
            with urllib.request.urlopen(url, context=context, timeout=2) as response:
                return json.loads(response.read())
        except (OSError, urllib.error.URLError, TimeoutError) as error:
            last_error = error
            time.sleep(0.25)
    raise TimeoutError(f"timed out waiting for {url}: {last_error}")


def wait_for_http(url, *, timeout=60):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                return response.read()
        except (OSError, urllib.error.URLError, TimeoutError) as error:
            last_error = error
            time.sleep(0.25)
    raise TimeoutError(f"timed out waiting for {url}: {last_error}")


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def call_result(result, name):
    payload = result.model_dump(by_alias=True, exclude_none=True)
    if payload.get("isError"):
        raise AssertionError(f"MCP tool {name} returned an error: {payload.get('content')}")
    structured = payload.get("structuredContent")
    if not isinstance(structured, dict):
        raise AssertionError(f"MCP tool {name} returned no structured content: {payload}")
    return structured


async def exercise_deployment(server_binary, base_url, token, agent_home):
    async with connect_http(f"{base_url}/mcp", token=token) as client:
        listing = await client.list_tools()
        tools = {tool.name: tool for tool in listing.tools}
        required = {
            "get_system_info",
            "list_hosts",
            "create_pairing_code",
            "remove_host",
            "get_host_system_info",
            "list_directory",
            "read_file",
            "write_file",
            "rollback_file",
        }
        if not required.issubset(tools):
            raise AssertionError(f"authenticated tool discovery omitted {sorted(required - tools.keys())}")
        for name in ("write_file", "rollback_file"):
            definition = tools[name].model_dump(by_alias=True, exclude_none=True)
            annotations = definition.get("annotations", {})
            if annotations.get("destructiveHint") is not True or annotations.get("readOnlyHint") is not False:
                raise AssertionError(f"{name} lacks destructive confirmation annotations: {annotations}")
            if "per-call human confirmation" not in definition.get("description", ""):
                raise AssertionError(f"{name} does not explain its human confirmation requirement")

        local_info = call_result(await client.call_tool("get_system_info", {}), "get_system_info")
        if not local_info.get("hostname") or not local_info.get("os", {}).get("id"):
            raise AssertionError(f"get_system_info returned an incomplete host snapshot: {local_info}")

        pairing = call_result(await client.call_tool("create_pairing_code", {}), "create_pairing_code")
        pairing_code = pairing.get("pairing_code")
        if not pairing_code:
            raise AssertionError("create_pairing_code returned no code")

        shared_path = agent_home / "managed"
        shared_path.mkdir(mode=0o700)
        target = shared_path / "service.conf"
        prior_content = "mode=prior\n"
        target.write_text(prior_content, encoding="utf-8")
        config_path = agent_home / "agent.json"
        enrollment = subprocess.run(
            [
                server_binary,
                "agent",
                "enroll",
                "--server",
                base_url,
                "--pairing-code-stdin",
                "--config",
                str(config_path),
                "--allowed-path",
                str(shared_path),
                "--writable-path",
                str(shared_path),
            ],
            input=pairing_code + "\n",
            text=True,
            capture_output=True,
            check=True,
            timeout=20,
        )
        host_id = json.loads(config_path.read_text(encoding="utf-8"))["host_id"]
        if pairing_code in enrollment.stdout or pairing_code in enrollment.stderr:
            raise AssertionError("agent enrollment exposed the pairing code in command output")

        agent = subprocess.Popen(
            [server_binary, "agent", "run", "--config", str(config_path), "--interval", "200ms"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if agent.poll() is not None:
                    raise AssertionError(f"host agent exited with status {agent.returncode}")
                page = call_result(await client.call_tool("list_hosts", {}), "list_hosts")
                if any(host.get("id") == host_id for host in page.get("hosts", [])):
                    break
                await asyncio.sleep(0.25)
            else:
                raise TimeoutError("enrolled host did not appear in list_hosts")

            remote_info = call_result(
                await client.call_tool("get_host_system_info", {"host_id": host_id}, read_timeout_seconds=100),
                "get_host_system_info",
            )
            if remote_info.get("host_id") != host_id or not remote_info.get("system_info", {}).get("hostname"):
                raise AssertionError(f"get_host_system_info returned an incomplete snapshot: {remote_info}")

            read_result = call_result(
                await client.call_tool("read_file", {"host_id": host_id, "path": str(target)}, read_timeout_seconds=100),
                "read_file",
            )
            if read_result.get("file", {}).get("content") != prior_content:
                raise AssertionError(f"read_file returned unexpected content: {read_result}")

            written = call_result(
                await client.call_tool(
                    "write_file",
                    {"host_id": host_id, "path": str(target), "content": "mode=managed\n"},
                    read_timeout_seconds=100,
                ),
                "write_file",
            )
            action_id = written.get("action_id")
            if not action_id or target.read_text(encoding="utf-8") != "mode=managed\n":
                raise AssertionError(f"write_file did not change the target or return an action ID: {written}")

            rollback = call_result(
                await client.call_tool(
                    "rollback_file",
                    {"host_id": host_id, "action_id": action_id},
                    read_timeout_seconds=100,
                ),
                "rollback_file",
            )
            if rollback.get("exact") is not True or rollback.get("restored") is not True:
                raise AssertionError(f"rollback_file did not restore the captured file: {rollback}")
            if target.read_text(encoding="utf-8") != prior_content:
                raise AssertionError("rollback_file did not restore the prior file content")

            removed = call_result(await client.call_tool("remove_host", {"host_id": host_id}), "remove_host")
            if removed.get("removed") is not True:
                raise AssertionError(f"remove_host did not revoke the enrolled host: {removed}")
        finally:
            stop_process(agent)


def main():
    server_binary = Path(os.environ.get("UFM_SERVER_BINARY", ROOT / "build/ubuntu-fleet-manager"))
    issuer_binary = Path(os.environ.get("UFM_OIDC_FIXTURE_BINARY", ROOT / "build/oidc-fixture"))
    if not server_binary.is_file() or not issuer_binary.is_file():
        raise SystemExit("build the runtime and tests/oidc-fixture binaries before running this acceptance")

    http_port = free_port()
    issuer_port = free_port()
    project_name = f"ufm-acceptance-{secrets.token_hex(4)}"
    with tempfile.TemporaryDirectory(prefix="ufm-compose-acceptance-") as temp_directory:
        temporary = Path(temp_directory)
        certificate_path = temporary / "oidc.crt"
        private_key_path = temporary / "oidc.key"
        key_path = temporary / "file-action-key"
        env_path = temporary / ".env"
        agent_home = temporary / "agent-home"
        agent_home.mkdir(mode=0o700)
        key_path.write_bytes(secrets.token_bytes(32))
        key_path.chmod(0o600)
        control_plane_user = os.environ.get(
            "UFM_ACCEPTANCE_CONTAINER_USER",
            f"{os.getuid()}:{os.getgid()}",
        )

        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-nodes",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(private_key_path),
                "-out",
                str(certificate_path),
                "-sha256",
                "-days",
                "1",
                "-subj",
                "/CN=host.docker.internal",
                "-addext",
                "subjectAltName=DNS:host.docker.internal,DNS:localhost,IP:127.0.0.1",
                "-addext",
                "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
        certificate_path.chmod(0o644)
        private_key_path.chmod(0o600)

        issuer_url = f"https://host.docker.internal:{issuer_port}"
        base_url = f"http://127.0.0.1:{http_port}"
        password = secrets.token_urlsafe(32)
        env_path.write_text(
            "\n".join(
                [
                    f"POSTGRES_PASSWORD={password}",
                    f"OIDC_ISSUER_URL={issuer_url}",
                    f"OIDC_AUDIENCE={AUDIENCE}",
                    f"FILE_ACTION_KEY_SOURCE={key_path}",
                    f"CONTROL_PLANE_USER={control_plane_user}",
                    "ALLOW_FILE_WRITES=true",
                    "ALLOW_APT_WRITES=false",
                    "ALLOW_COMMAND_EXECUTION=false",
                    f"PUBLIC_URL={base_url}",
                    f"MCP_HOST_PORT={http_port}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        compose_environment = os.environ.copy()
        compose_environment["UFM_TEST_CA_FILE"] = str(certificate_path)
        compose_command = [
            "docker",
            "compose",
            "--project-name",
            project_name,
            "--env-file",
            str(env_path),
            "--file",
            str(ROOT / "compose.yaml"),
            "--file",
            str(ROOT / "tests/acceptance/compose.override.yaml"),
        ]

        issuer = subprocess.Popen(
            [
                str(issuer_binary),
                "--listen",
                f"0.0.0.0:{issuer_port}",
                "--issuer",
                issuer_url,
                "--cert",
                str(certificate_path),
                "--key",
                str(private_key_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            tls_context = ssl.create_default_context(cafile=str(certificate_path))
            access_token = wait_for_json(
                f"https://localhost:{issuer_port}/token",
                context=tls_context,
                process=issuer,
            )["access_token"]
            subprocess.run(
                compose_command + ["config", "--quiet"],
                cwd=ROOT,
                env=compose_environment,
                check=True,
                timeout=20,
            )
            subprocess.run(
                ["docker", "build", "--platform", "linux/amd64", "--tag", "ubuntu-fleet-manager:acceptance", str(ROOT)],
                cwd=ROOT,
                check=True,
                timeout=300,
            )
            subprocess.run(
                compose_command + ["up", "--detach", "--remove-orphans"],
                cwd=ROOT,
                env=compose_environment,
                check=True,
                timeout=180,
            )
            wait_for_http(base_url + "/readyz", timeout=60)
            asyncio.run(exercise_deployment(str(server_binary), base_url, access_token, agent_home))
        except Exception:
            try:
                subprocess.run(
                    compose_command + ["logs", "--no-color"],
                    cwd=ROOT,
                    env=compose_environment,
                    check=False,
                    timeout=20,
                )
            except Exception as log_error:
                print(f"could not collect Compose logs: {log_error}", file=sys.stderr)
            raise
        finally:
            subprocess.run(
                compose_command + ["down", "--volumes", "--remove-orphans"],
                cwd=ROOT,
                env=compose_environment,
                check=False,
                timeout=60,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            stop_process(issuer)
            if issuer.poll() not in (None, 0):
                error = issuer.stderr.read() if issuer.stderr else ""
                if error:
                    print(error, file=sys.stderr)

    print("Clean Compose acceptance passed: auth, MCP discovery, enrollment, read, write, rollback, confirmation hints.")


if __name__ == "__main__":
    main()
