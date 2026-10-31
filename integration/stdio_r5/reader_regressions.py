"""Separate, explicitly synthetic regressions for R5 discovery evidence checks.

This program re-reads one completed S01/nominal variant and mutates COPIES of
its discovery evidence. It starts no MCP process, imports no provider/controller,
and does not establish whether the SDK would accept either synthetic response.
These checks are separate from the frozen 20 variants and two integration mutants.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
VERSION = '2026-07-28'
MUTATIONS = ('wrong_modern_with_matching_legacy', 'missing_modern_with_matching_legacy')


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def inventory(directory):
    return {p.relative_to(directory).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(directory.rglob('*')) if p.is_file()}


def load_reader(path):
    spec = importlib.util.spec_from_file_location('r5_discovery_regression_reader', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def changed_discovery(result, mutation):
    changed = copy.deepcopy(result)
    if mutation == 'wrong_modern_with_matching_legacy':
        changed['supportedVersions'] = ['2025-11-25']
    elif mutation == 'missing_modern_with_matching_legacy':
        changed.pop('supportedVersions', None)
    else:
        raise ValueError('Unknown synthetic reader mutation')
    changed['protocolVersion'] = VERSION
    return changed


def mutate_copy(directory, mutation):
    """Alter raw bytes, parsed frames and corresponding step views consistently."""
    discovery_ids = set()
    logs = []
    for path in sorted((directory/'wire').glob('*.jsonl')):
        rows = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line]
        for row in rows:
            frame = row.get('frame') or {}
            if row.get('direction') == 'client_to_server' and frame.get('method') == 'server/discover':
                discovery_ids.add((row['endpoint_instance_id'], frame['id']))
        logs.append((path, rows))
    changed = {}
    for path, rows in logs:
        for row in rows:
            frame = row.get('frame') or {}
            identity = (row.get('endpoint_instance_id'), frame.get('id'))
            if row.get('direction') == 'server_to_client' and identity in discovery_ids and 'result' in frame:
                frame['result'] = changed_discovery(frame['result'], mutation)
                # This is a clearly synthetic copied-evidence tamper, never an
                # invented claim of an actual SDK/stdio exchange.
                raw = (json.dumps(frame, ensure_ascii=False, separators=(',', ':'))+'\n').encode('utf-8')
                row['raw_base64'] = base64.b64encode(raw).decode('ascii')
                changed[identity] = frame['result']
        path.write_text(''.join(json.dumps(row, sort_keys=True)+'\n' for row in rows), encoding='utf-8', newline='\n')
    if not changed:
        raise ValueError('No actual source discovery response was available to copy/mutate')
    obs_path = directory/'observation.json'
    obs = load(obs_path)
    updated_steps = 0
    for step in obs['steps'].values():
        identity = (step.get('endpoint_instance_id'), step.get('request_id'))
        if step.get('method') == 'server/discover' and identity in changed:
            step['result'] = copy.deepcopy(changed[identity])
            if 'sdk_result' in step:
                step['sdk_result'] = copy.deepcopy(changed[identity])
            updated_steps += 1
    if updated_steps != 1:
        raise ValueError('Expected exactly the explicit S01 discovery step in copied evidence')
    obs['synthetic_reader_regression'] = {'mutation':mutation,'actual_sdk_execution':False}
    obs_path.write_text(json.dumps(obs, indent=2, sort_keys=True)+'\n', encoding='utf-8', newline='\n')
    return {'synthetic_discovery_responses_changed':len(changed), 'explicit_step_views_changed':updated_steps}


def run_regressions(source_variant, output_dir, reader=None):
    source = Path(source_variant).resolve()
    output = Path(output_dir).resolve()
    if not source.is_dir() or source.name != 'S01_nominal':
        raise ValueError('Use a completed S01_nominal variant directory')
    if output == source or output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError('Regression output must be separate from the source evidence tree')
    if output.exists() and any(output.iterdir()):
        raise ValueError('Use a fresh regression output directory; existing evidence is preserved')
    output.mkdir(parents=True, exist_ok=True)
    reader = reader or load_reader(HERE/'readback.py')
    original_hashes = inventory(source)
    baseline = reader.verify_variant(source, 'S01', 'nominal')
    baseline_ok = baseline['matches_oracle'] and not baseline['infrastructure_errors']
    results = []
    if baseline_ok:
        for mutation in MUTATIONS:
            dest = output/mutation
            shutil.copytree(source, dest)
            changes = mutate_copy(dest, mutation)
            actual = reader.verify_variant(dest, 'S01', 'nominal')
            reasons = actual['semantic_failures']
            discovery_reason = any('discovery' in r.lower() or 'protocol_version' in r for r in reasons)
            rejected = not actual['matches_oracle'] and not actual['infrastructure_errors'] and discovery_reason
            results.append({'id':mutation,'kind':'SYNTHETIC_COPIED_EVIDENCE_NOT_MCP_EXECUTION',
                            'matches_normal_oracle':actual['matches_oracle'],
                            'rejected_for_discovery_semantics':rejected,
                            'semantic_failures':reasons,'infrastructure_errors':actual['infrastructure_errors'],**changes})
            (dest/'REGRESSION_READBACK.json').write_text(json.dumps(actual,indent=2)+'\n',encoding='utf-8',newline='\n')
    unchanged = original_hashes == inventory(source)
    passed = baseline_ok and unchanged and len(results) == 2 and all(r['rejected_for_discovery_semantics'] for r in results)
    repo = HERE.parents[1]
    commit = subprocess.run(['git','-C',str(repo),'rev-parse','HEAD'],check=True,capture_output=True).stdout.decode().strip()
    git_status = subprocess.run(['git','-C',str(repo),'status','--porcelain'],check=True,capture_output=True).stdout.decode()
    report = {'status':'PASS' if passed else 'FAIL',
              'kind':'SEPARATE_SYNTHETIC_READER_REGRESSIONS_NOT_MCP_CAMPAIGN',
              'source_variant':'S01_nominal','source_evidence_unchanged':unchanged,
              'source_evidence_inventory_sha256':hashlib.sha256(json.dumps(original_hashes,sort_keys=True).encode()).hexdigest(),
              'reader_sha256':hashlib.sha256(Path(reader.__file__).read_bytes()).hexdigest(),
              'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'source_commit':commit,'source_git_status':git_status,
              'frozen_scenarios_sha256':hashlib.sha256(HERE.joinpath('scenarios.json').read_bytes()).hexdigest(),
              'frozen_contract_sha256':hashlib.sha256(HERE.joinpath('contract.md').read_bytes()).hexdigest(),
              'original_positive_accepted':baseline_ok,'original_positive_infrastructure_errors':baseline['infrastructure_errors'],
              'synthetic_regressions':len(results),'synthetic_regressions_rejected':sum(r['rejected_for_discovery_semantics'] for r in results),
              'results':results,
              'interpretation':'Original actual SDK evidence is preserved and accepted. Synthetic copied replies exercise only reader sensitivity; no assertion of malformed-reply acceptance by the SDK, new R5 scenarios or new integration mutants.'}
    (output/'SUMMARY.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-variant', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    report = run_regressions(args.source_variant,args.output_dir)
    print(json.dumps(report,indent=2))
    raise SystemExit(0 if report['status'] == 'PASS' else 1)


if __name__ == '__main__':
    main()
