#!/usr/bin/env python3
"""Synthetic Codex -> loopback bridge -> Unix broker turn; no live account."""

import base64
import json
import os
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from pathlib import Path


CAPABILITY = base64.urlsafe_b64encode(bytes([9]) * 32).decode().rstrip("=")


def sse_response() -> bytes:
    text = "synthetic bridge works"
    message = {
        "id": "msg_bridge_001",
        "type": "message",
        "status": "completed",
        "role": "assistant",
        "content": [{"type": "output_text", "text": text, "annotations": []}],
    }
    base = {
        "id": "resp_bridge_001",
        "object": "response",
        "created_at": 1_800_000_000,
        "completed_at": 1_800_000_001,
        "error": None,
        "incomplete_details": None,
        "instructions": None,
        "model": "gpt-6-sol",
        "output": [message],
        "parallel_tool_calls": False,
        "previous_response_id": None,
        "reasoning": {"effort": None, "summary": None},
        "store": False,
        "text": {"format": {"type": "text"}},
        "tool_choice": "auto",
        "tools": [],
        "truncation": "disabled",
        "usage": {"input_tokens": 1, "output_tokens": 3, "total_tokens": 4},
    }
    events = [
        ("response.created", {"response": {**base, "status": "in_progress", "completed_at": None, "output": []}}),
        ("response.output_item.added", {"output_index": 0, "item": {**message, "status": "in_progress", "content": []}}),
        ("response.content_part.added", {"item_id": message["id"], "output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": []}}),
        ("response.output_text.delta", {"item_id": message["id"], "output_index": 0, "content_index": 0, "delta": text}),
        ("response.content_part.done", {"item_id": message["id"], "output_index": 0, "content_index": 0, "part": message["content"][0]}),
        ("response.output_item.done", {"output_index": 0, "item": message}),
        ("response.completed", {"response": {**base, "status": "completed"}}),
    ]
    return b"".join(
        f"event: {kind}\ndata: {json.dumps({'type': kind, 'sequence_number': index, **fields}, separators=(',', ':'))}\n\n".encode()
        for index, (kind, fields) in enumerate(events)
    )


class FakeBroker(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True
    requests = 0
    errors: list[str] = []
    request_shape: dict[str, bool] = {}


class BrokerHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        line = self.rfile.readline(4096).decode("ascii", "replace").strip()
        headers: dict[str, str] = {}
        while True:
            raw = self.rfile.readline(4096)
            if raw in (b"\r\n", b"\n", b""):
                break
            key, value = raw.decode("ascii", "replace").split(":", 1)
            headers[key.lower()] = value.strip()
        length = int(headers.get("content-length", "0"))
        body = self.rfile.read(length)
        errors = []
        if line != "POST /v1/responses HTTP/1.1":
            errors.append("wrong route")
        if headers.get("authorization") != f"Bearer {CAPABILITY}":
            errors.append("wrong scoped capability")
        if headers.get("x-factory-campaign-id") != "campaign-1":
            errors.append("wrong campaign")
        if headers.get("x-factory-lane-id") != "lane-1":
            errors.append("wrong lane")
        request = json.loads(body)
        type(self.server).request_shape = {
            "store_false": request.get("store") is False,
            "stream_true": request.get("stream") is True,
            "input_array": isinstance(request.get("input"), list),
        }
        type(self.server).requests += 1
        type(self.server).errors.extend(errors)
        response = sse_response() if not errors else b"{}"
        status = b"200 OK" if not errors else b"403 Forbidden"
        content_type = b"text/event-stream" if not errors else b"application/json"
        self.wfile.write(
            b"HTTP/1.1 " + status + b"\r\nContent-Type: " + content_type
            + f"\r\nContent-Length: {len(response)}\r\nConnection: close\r\n\r\n".encode()
            + response
        )


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def main() -> None:
    codex = shutil.which("codex")
    if codex is None:
        raise SystemExit("Codex CLI is required for this synthetic probe")
    repo = Path(__file__).resolve().parent.parent
    subprocess.run(
        ["cargo", "build", "--locked", "--features", "experimental-bridge", "--bin", "siwc-agent-bridge"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    with tempfile.TemporaryDirectory(prefix="siwc-bridge-", dir="/tmp") as workspace:
        work = Path(workspace)
        socket_path = work / "broker.sock"
        server = FakeBroker(str(socket_path), BrokerHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        capability_file = work / "capability"
        capability_file.write_text(CAPABILITY)
        capability_file.chmod(0o600)
        port = free_port()
        bridge = subprocess.Popen(
            [
                str(repo / "target/debug/siwc-agent-bridge"),
                "--listen", f"127.0.0.1:{port}",
                "--broker-socket", str(socket_path),
                "--capability-file", str(capability_file),
                "--campaign-id", "campaign-1",
                "--lane-id", "lane-1",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            for _ in range(50):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    if bridge.poll() is not None:
                        raise SystemExit("bridge exited before Codex reached it")
                    time.sleep(0.1)
            else:
                raise SystemExit("bridge did not start")
            codex_home = work / "codex"
            codex_home.mkdir()
            codex_env = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": workspace,
                "CODEX_HOME": str(codex_home),
                "FACTORY_PLACEHOLDER_TOKEN": "not-a-service-credential",
                "HTTP_PROXY": "http://127.0.0.1:1",
                "HTTPS_PROXY": "http://127.0.0.1:1",
                "ALL_PROXY": "http://127.0.0.1:1",
                "NO_PROXY": "127.0.0.1,localhost",
            }
            command = [
                codex, "exec", "--skip-git-repo-check", "--ignore-user-config", "--ephemeral",
                "--sandbox", "read-only", "-C", workspace, "-m", "gpt-6-sol",
                "-c", 'model_provider="fixture"',
                "-c", 'model_providers.fixture.name="Fixture"',
                "-c", f'model_providers.fixture.base_url="http://127.0.0.1:{port}/v1"',
                "-c", 'model_providers.fixture.env_key="FACTORY_PLACEHOLDER_TOKEN"',
                "-c", 'model_providers.fixture.wire_api="responses"',
                "-c", 'model_providers.fixture.requires_openai_auth=false',
                "-c", 'model_providers.fixture.supports_websockets=false',
                "Reply with ok",
            ]
            result = subprocess.run(command, env=codex_env, capture_output=True, timeout=30)
            output = result.stdout + result.stderr
            if server.errors or server.requests == 0:
                raise SystemExit(f"broker fixture did not receive a valid scoped call: {server.errors}")
            if not all(server.request_shape.values()):
                raise SystemExit(f"Codex request shape was unexpected: {server.request_shape}")
            if result.returncode != 0 or b"synthetic bridge works" not in output:
                raise SystemExit(f"Codex failed the synthetic bridge turn: {output[-800:]!r}")
            if CAPABILITY.encode() in output or (codex_home / "auth.json").exists():
                raise SystemExit("bridge capability or Codex auth file appeared in Codex output/home")
            print(f"Codex completed a synthetic bridge turn ({server.requests} broker request(s))")
        finally:
            bridge.terminate()
            bridge.communicate(timeout=3)
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)


if __name__ == "__main__":
    main()
