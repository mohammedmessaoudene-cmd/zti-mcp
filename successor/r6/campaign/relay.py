"""Record and forward actual SDK stdio lines unchanged; no protocol replies."""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--wire", required=True)
    parser.add_argument("--lifecycle", required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    wire, lifecycle = Path(args.wire), Path(args.lifecycle)
    wire.parent.mkdir(parents=True, exist_ok=True)
    lock, sequence = threading.Lock(), 0
    with lifecycle.with_suffix(".stderr.txt").open("ab", buffering=0) as stderr:
        process = subprocess.Popen([sys.executable, "-I", "-m", "zti_mcp_r6", "--config", str(Path(args.config).resolve())], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, bufsize=0)
        ready_path = Path(config["control_dir"]) / "events.jsonl"
        deadline, pid = time.monotonic() + 30, None
        while pid is None:
            if ready_path.exists():
                for line in ready_path.read_text(encoding="utf-8").splitlines():
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if item.get("event") == "endpoint_ready" and item.get("endpoint_instance_id") == config["endpoint_instance_id"]:
                        pid = item["provider_pid"]
            if pid is not None:
                break
            if process.poll() is not None or time.monotonic() > deadline:
                process.terminate() if process.poll() is None else None
                process.wait(timeout=15)
                raise RuntimeError("No trusted startup identity from provider")
            time.sleep(0.01)
        identity = {"endpoint_instance_id": config["endpoint_instance_id"], "provider_pid": pid,
                    "launcher_pid": process.pid, "relay_pid": os.getpid()}
        def life(kind, **details):
            with lifecycle.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps({**identity, "type": kind, "timestamp_ns": time.monotonic_ns(), **details}, sort_keys=True) + "\n")
        def capture(raw, direction):
            nonlocal sequence
            with lock:
                sequence += 1
                record = {**identity, "direction": direction, "sequence": sequence,
                          "timestamp_ns": time.monotonic_ns(), "raw_base64": base64.b64encode(raw).decode("ascii")}
                try:
                    record["frame"] = json.loads(raw)
                except (ValueError, UnicodeError):
                    record.update(frame=None, parse_error=True)
                with wire.open("a", encoding="utf-8", newline="\n") as stream:
                    stream.write(json.dumps(record, sort_keys=True) + "\n")
        life("provider_start")
        def upstream():
            try:
                while raw := sys.stdin.buffer.readline():
                    capture(raw, "client_to_server")
                    process.stdin.write(raw)
                    process.stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                try:
                    process.stdin.close()
                except OSError:
                    pass
        threading.Thread(target=upstream, daemon=True).start()
        try:
            while raw := process.stdout.readline():
                capture(raw, "server_to_client")
                sys.stdout.buffer.write(raw)
                sys.stdout.buffer.flush()
            code = process.wait(timeout=15)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
        life("provider_exit", returncode=code)
        sys.stdout.buffer.flush()
        os._exit(code if code >= 0 else 1)


if __name__ == "__main__":
    main()
