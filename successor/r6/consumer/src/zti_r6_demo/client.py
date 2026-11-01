"""Public Python SDK bridge. Input commands drive real SDK I/O, never replies.

The campaign speaks a local command protocol to this process. The SDK alone
speaks MCP to the separately launched endpoint through a byte-recording relay.
"""
import argparse
import asyncio
import json
import hashlib
import importlib.metadata
from pathlib import Path
import sys
from typing import Any, Literal

from mcp import Client, StdioServerParameters, types
from mcp.client.extension import advertise
from mcp.shared.exceptions import MCPError
from pydantic import ConfigDict
from .binding import BindingError, bind, verify_ict, validate_domain

EXT = "org.example/zti-mcp"
PROTOCOL = "2026-07-28"
CAP = {"revision": "0.1", "profile": "zti-mcp/0.1", "mode": "current-online", "effect_coupling": "required"}


class Params(types.RequestParams):
    model_config = ConfigDict(extra="allow", alias_generator=None, populate_by_name=True)


class ControlResult(types.Result):
    model_config = ConfigDict(extra="allow", alias_generator=None, populate_by_name=True)
    status: Literal["ACTIVE", "REVOKED", "RESERVED", "COMMITTED", "CANCELLED", "EXPIRED", "UNKNOWN", "COMPLETED", "SUSPENDED"]


def dumped(value):
    return value if isinstance(value, dict) else value.model_dump(by_alias=True, mode="json", exclude_none=True)


async def serve(settings):
    output_lock = asyncio.Lock()
    async def output(value):
        async with output_lock:
            sys.stdout.write(json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    client = Client(
        StdioServerParameters(command=settings["python"], args=["-I", settings["relay"],
            "--config", settings["config"], "--wire", settings["wire"], "--lifecycle", settings["lifecycle"]]),
        client_info=types.Implementation.model_validate(settings.get("client_info", {"name": "zti-r6-python", "version": "0.3.0"})),
        mode="auto", extensions=[advertise(EXT, settings=CAP)], cache=None, read_timeout_seconds=35,
    )
    tasks = set()
    async with client:
        if client.protocol_version != PROTOCOL:
            raise RuntimeError("Pinned modern protocol was not selected")
        discovery = dumped(await client.session.send_discover(PROTOCOL))
        if discovery.get("supportedVersions") != [PROTOCOL] or discovery.get("capabilities", {}).get("extensions", {}).get(EXT) != CAP:
            raise RuntimeError("Modern extension discovery is incompatible")
        from . import binding as binding_module
        loaded = {"python": sys.version, "entry": {"path": __file__, "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
                  "binding": {"path": binding_module.__file__, "sha256": hashlib.sha256(Path(binding_module.__file__).read_bytes()).hexdigest()},
                  "versions": {name: importlib.metadata.version(name) for name in ("zti-r6-demo", "mcp", "mcp-types")}}
        await output({"type": "ready", "client": "P", "protocol": client.protocol_version, "discovery": discovery, "loaded": loaded})
        async def execute(command):
            reply = {"id": command["id"], "client": "P"}
            try:
                method, params = command["method"], command.get("params", {})
                action = command.get("binding_action") or (params.get("action") if method.endswith(".reserve") else None)
                if action is not None:
                    try:
                        reply["binding"] = bind(action)
                    except BindingError as exc:
                        reply["binding_error"] = exc.reason
                if method == "bind":
                    reply["binding"] = bind(command["action"])
                    reply["result"] = {"bound": True}
                elif method == "server/discover":
                    reply["result"] = dumped(await client.session.send_discover(PROTOCOL))
                elif method == "tools/list":
                    reply["result"] = dumped(await client.session.list_tools())
                elif method == "tools/call":
                    result = await client.session.call_tool(params["name"], params.get("arguments"), meta=params.get("_meta"))
                    reply["result"] = dumped(result)
                    receipt = reply["result"].get("_meta", {}).get(EXT)
                    structured = reply["result"].get("structuredContent")
                    if not isinstance(receipt, dict) or receipt.get("status") != "COMMITTED" or not isinstance(structured, dict) or structured.get("receipt") != receipt:
                        raise ValueError("Invalid committed tool result shape")
                else:
                    response = await client.session.send_request(types.Request(method=method, params=Params.model_validate(params)), ControlResult)
                    reply["result"] = dumped(response)
                    if method.endswith(".reserve") and "ict" in reply["result"]:
                        try:
                            reply["permit_verification"] = verify_ict(reply["result"]["ict"], settings["public_keys"]["KP"],
                                settings["context"], settings["principal"], reply["binding"])
                        except Exception as exc:
                            raise BindingError("INVALID_TOKEN") from exc
                if method == "tools/call" and "result" in reply and "binding" in reply:
                    if reply["result"]["_meta"][EXT]["action_hash"] != reply["binding"]["action_hash"]:
                        raise ValueError("Receipt differs from client-computed action hash")
            except BindingError as exc:
                reply.pop("result", None)
                reply["local_error"] = {"type": "BindingError", "reason": exc.reason}
            except MCPError as exc:
                reply["error"] = dumped(exc.error)
            except Exception as exc:
                reply.pop("result", None)
                reply["transport_error"] = {"type": type(exc).__name__, "message": str(exc)}
            await output(reply)
        while True:
            line = await asyncio.to_thread(sys.stdin.readline)
            if not line:
                break
            command = json.loads(line)
            if command.get("method") == "close":
                break
            task = asyncio.create_task(execute(command))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
        if tasks:
            await asyncio.gather(*tasks)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--settings")
    parser.add_argument("--vectors")
    args = parser.parse_args()
    if args.vectors:
        data = json.loads(Path(args.vectors).read_text(encoding="utf-8"))
        reports = []
        for vector in data:
            try:
                row = {"id": vector["id"], "binding": bind(vector["input"])}
                try:
                    validate_domain(vector["input"])
                    row["domain_accepted"] = True
                except BindingError as exc:
                    row["domain_error"] = exc.reason
                reports.append(row)
            except BindingError as exc:
                reports.append({"id": vector["id"], "error": exc.reason})
        print(json.dumps(reports, ensure_ascii=True))
    elif args.settings:
        asyncio.run(serve(json.loads(Path(args.settings).read_text(encoding="utf-8"))))
    else:
        parser.error("--settings or --vectors is required")


if __name__ == "__main__":
    main()
