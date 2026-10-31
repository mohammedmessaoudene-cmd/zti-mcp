"""Transparent stdio recording relay. No policy or invented protocol responses.

Each received newline-delimited SDK frame is forwarded byte-for-byte. A relay
PID is recorded separately from the actual provider PID. Diagnostics go to a
dedicated stderr file; stdout carries only the provider's original bytes.
"""
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
    p = argparse.ArgumentParser()
    p.add_argument('--config', required=True)
    p.add_argument('--wire', required=True)
    p.add_argument('--lifecycle', required=True)
    args = p.parse_args()
    config = json.loads(Path(args.config).read_text(encoding='utf-8'))
    wire = Path(args.wire)
    lifecycle = Path(args.lifecycle)
    wire.parent.mkdir(parents=True, exist_ok=True)
    stderr_path = lifecycle.with_suffix('.stderr.txt')
    lock = threading.Lock()
    sequence = 0
    with stderr_path.open('ab', buffering=0) as stderr:
        process = subprocess.Popen([sys.executable, '-I', str(Path(__file__).with_name('endpoint.py')), '--config', str(Path(args.config).resolve())], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, bufsize=0)
        # On Windows a venv executable can be a redirector process. Obtain the
        # actual interpreter PID from its trusted startup event, never infer it
        # from the redirector/relay PID. This handshake makes no policy decision.
        ready_path = Path(config['control_dir'])/'events.jsonl'
        deadline = time.monotonic()+30
        actual_pid = None
        while actual_pid is None:
            if ready_path.exists():
                for line in ready_path.read_text(encoding='utf-8').splitlines():
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if event.get('event') == 'endpoint_ready' and event.get('endpoint_instance_id') == config['endpoint_instance_id']:
                        actual_pid = event['provider_pid']
            if actual_pid is not None:
                break
            if process.poll() is not None or time.monotonic()>deadline:
                raise RuntimeError('Provider did not produce its trusted startup identity')
            time.sleep(0.01)
        identity = {'endpoint_instance_id':config['endpoint_instance_id'],'provider_pid':actual_pid,'launcher_pid':process.pid,'relay_pid':os.getpid()}
        def life(event, **values):
            with lifecycle.open('a', encoding='utf-8', newline='\n') as f:
                f.write(json.dumps({**identity,'type':event,'timestamp_ns':time.monotonic_ns(),**values},sort_keys=True)+'\n')
        life('provider_start')
        def capture(raw, direction):
            nonlocal sequence
            with lock:
                sequence += 1
                record = {**identity,'direction':direction,'sequence':sequence,'timestamp_ns':time.monotonic_ns(),'raw_base64':base64.b64encode(raw).decode('ascii')}
                try:
                    record['frame'] = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    record['frame'] = None
                    record['parse_error'] = True
                with wire.open('a', encoding='utf-8', newline='\n') as f:
                    f.write(json.dumps(record,sort_keys=True)+'\n')
        def upstream():
            try:
                while raw := sys.stdin.buffer.readline():
                    capture(raw,'client_to_server')
                    process.stdin.write(raw)
                    process.stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                try:
                    process.stdin.close()
                except OSError:
                    pass
        thread = threading.Thread(target=upstream, daemon=True)
        thread.start()
        try:
            while raw := process.stdout.readline():
                capture(raw,'server_to_client')
                sys.stdout.buffer.write(raw)
                sys.stdout.buffer.flush()
            code = process.wait(timeout=15)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
        life('provider_exit', returncode=code)
        sys.stdout.buffer.flush()
        # Avoid interpreter shutdown contending with a blocked daemon stdin read.
        os._exit(code if code >= 0 else 1)

if __name__ == '__main__':
    main()
