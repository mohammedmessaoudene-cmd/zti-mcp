#!/usr/bin/env python3
"""Inspect the bounded R6 archives before installing or importing their code.

Only stdlib ZIP/TAR/JSON/metadata readers are used. The caller first verifies the
public source manifest. This guard checks archive contents against its closed
source map; BUILD.json is not an authenticity mechanism. No archive is extracted
or executed. Receipts contain relative names, hashes and counts only.
"""
from __future__ import annotations
import argparse
import base64
import configparser
import csv
from email.parser import Parser
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import zipfile

WHEELS = {
    'zti_mcp_r6-0.3.0-py3-none-any.whl': ('zti_mcp_r6', 'zti-mcp-r6', 'provider'),
    'zti_r6_demo-0.3.0-py3-none-any.whl': ('zti_r6_demo', 'zti-r6-demo', 'consumer'),
}
CLIENT = 'zti-r6-clients-0.3.0-research.tgz'
MAX_BYTES, MAX_MEMBER, MAX_FILES = 20_000_000, 2_000_000, 1000
RESERVED = re.compile(r'^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', re.I)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def portable_name(name, *, directory=False):
    need(type(name) is str and 0 < len(name) <= 1024, 'Invalid archive name length')
    raw = name[:-1] if directory and name.endswith('/') else name
    need(raw and not raw.startswith('/') and '\\' not in raw and ':' not in raw, 'Nonportable archive name')
    parts = raw.split('/')
    need(all(part not in ('', '.', '..') for part in parts), 'Noncanonical archive name')
    for part in parts:
        need(not part.endswith(('.', ' ')) and not RESERVED.match(part), 'Windows path alias or device name')
        need(not any(ord(ch) < 32 or ch in '<>"|?*' for ch in part), 'Invalid archive filename character')
        need(not part.casefold().endswith(('.pth', '.data')), 'Interpreter path/control payload is forbidden')
    need(PurePosixPath(raw).as_posix() == raw, 'Archive path normalization changed its name')
    return raw


def archive_entries(path):
    need(path.is_file() and not path.is_symlink() and
         not (hasattr(path, 'is_junction') and path.is_junction()), 'Ordinary archive file required')
    need(path.stat().st_size <= MAX_BYTES, 'Archive size limit exceeded')
    result, seen, total, count = {}, set(), 0, 0

    def accept(name, size, directory):
        nonlocal total, count
        name = portable_name(name, directory=directory)
        alias = name.casefold()
        need(alias not in seen, 'Duplicate or Windows case-alias archive member')
        seen.add(alias)
        count += 1
        total += size
        need(count <= MAX_FILES and 0 <= size <= MAX_MEMBER and total <= MAX_BYTES,
             'Expanded archive limit exceeded')
        return name

    if path.suffix == '.whl':
        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                kind = stat.S_IFMT(entry.external_attr >> 16)
                need(kind in (0, stat.S_IFREG, stat.S_IFDIR) and not entry.external_attr & 0x400,
                     'Archive links or special files are forbidden')
                need(not entry.flag_bits & 1, 'Encrypted archive member is forbidden')
                name = accept(entry.filename, entry.file_size, entry.is_dir())
                if not entry.is_dir():
                    result[name] = archive.read(entry)
    else:
        with tarfile.open(path, 'r:gz') as archive:
            for entry in archive:
                need(entry.isfile() or entry.isdir(), 'TAR links or special files are forbidden')
                name = accept(entry.name, entry.size, entry.isdir())
                if entry.isfile():
                    result[name] = archive.extractfile(entry).read()
    return result


def check_hash(raw, source_name, public_files):
    need(public_files.get(source_name) == digest(raw), 'Archive bytes differ from verified source: '+source_name)


def single_header(message, name, expected):
    need(message.get_all(name) == [expected], 'Wrong or duplicate distribution metadata: '+name)


def record_matches(entries, record_name):
    rows = list(csv.reader(io.StringIO(entries[record_name].decode('utf-8'))))
    seen = set()
    for row in rows:
        need(len(row) == 3, 'Invalid wheel RECORD row')
        name = portable_name(row[0])
        need(name not in seen and name in entries, 'Wheel RECORD path missing or duplicated')
        seen.add(name)
        if name == record_name:
            need(row[1:] == ['', ''], 'Wheel RECORD self-entry must be unhashed')
        else:
            raw = entries[name]
            encoded_hash = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode('ascii').rstrip('=')
            need(row[1] == 'sha256='+encoded_hash and row[2] == str(len(raw)), 'Wheel RECORD bytes/hash/size differ')
    need(seen == set(entries), 'Wheel RECORD file set differs from archive')


def check_wheel(path, public_files):
    module, distribution, project = WHEELS[path.name]
    entries = archive_entries(path)
    prefix = f'successor/r6/{project}/src/{module}/'
    expected = {name.removeprefix(prefix):value for name,value in public_files.items()
                if name.startswith(prefix) and name.endswith('.py')}
    need('__init__.py' in expected, 'Verified source lacks expected package')
    package_prefix = module+'/'
    info = module+'-0.3.0.dist-info/'
    metadata = {'METADATA','WHEEL','top_level.txt','RECORD','licenses/LICENSE','licenses/NOTICE'}
    optional = {'entry_points.txt'}
    actual = {}
    for name, raw in entries.items():
        if name.startswith(package_prefix):
            relative = name.removeprefix(package_prefix)
            need(relative in expected, 'Unexpected package source/resource or executable')
            need(digest(raw) == expected[relative], 'Installed Python source bytes differ: '+relative)
            actual[relative] = digest(raw)
        else:
            need(name.startswith(info) and name.removeprefix(info) in metadata | optional,
                 'Wheel code/data outside the authorized package or standard dist-info')
    need(actual == expected, 'Wheel closed Python source set differs')
    need({info+name for name in metadata} <= set(entries), 'Required wheel metadata or notices missing')
    parser = Parser()
    meta = parser.parsestr(entries[info+'METADATA'].decode('utf-8'))
    single_header(meta, 'Name', distribution)
    single_header(meta, 'Version', '0.3.0')
    single_header(meta, 'License-Expression', 'Apache-2.0')
    need(meta.get_all('License-File') == ['LICENSE','NOTICE'], 'Wheel license-file metadata differs')
    wheel = parser.parsestr(entries[info+'WHEEL'].decode('utf-8'))
    for name,value in [('Wheel-Version','1.0'),('Root-Is-Purelib','true'),('Tag','py3-none-any')]:
        single_header(wheel, name, value)
    need(entries[info+'top_level.txt'].decode('utf-8').strip() == module, 'Wrong top-level package')
    points = configparser.ConfigParser(interpolation=None, strict=True)
    points.optionxform = str
    points.read_string(entries.get(info+'entry_points.txt', b'').decode('utf-8'))
    need(not points.defaults(), 'Default entry-point definitions forbidden')
    if project == 'provider':
        need(points.sections() == ['console_scripts'] and dict(points['console_scripts']) ==
             {'zti-mcp-r6':'zti_mcp_r6.endpoint:main'}, 'Unexpected provider entry point')
    else:
        need(not points.sections(), 'Consumer must have no executable entry points')
    for name in ('LICENSE','NOTICE'):
        check_hash(entries[info+'licenses/'+name], f'successor/r6/{project}/'+name, public_files)
    record_matches(entries, info+'RECORD')
    return {'files':len(entries),'python_source_files':len(actual),'metadata_checked':True,'notices_checked':True}


def check_client(path, public_files):
    entries = archive_entries(path)
    source_prefix = 'successor/r6/clients/'
    expected = {name.removeprefix(source_prefix):value for name,value in public_files.items()
                if name.startswith(source_prefix)}
    required = {'client.ts','binding.ts','runtime-lock.json','package.json','LICENSE','NOTICE'}
    actual = set()
    for name, raw in entries.items():
        need(name.startswith('package/'), 'Client archive file outside package root')
        relative = name.removeprefix('package/')
        need(relative in expected, 'Client archive contains uninventoried file')
        check_hash(raw, source_prefix+relative, public_files)
        actual.add(relative)
    need(required <= actual, 'Client archive required source/lock/notice missing')
    package = json.loads(entries['package/package.json'])
    need(package.get('name') == 'zti-r6-clients' and package.get('version') == '0.3.0-research' and
         package.get('private') is True and package.get('type') == 'module', 'Client application metadata differs')
    return {'files':len(entries),'required_files_checked':len(required),'all_included_files_match_source':True}


def check_distributions(distributions, public_files):
    distributions = Path(distributions).resolve()
    need(type(public_files) is dict, 'Expected verified public source hash map')
    artifacts = [*distributions.glob('*.whl'), *distributions.glob('*.tgz')]
    need({path.name for path in artifacts} == set(WHEELS) | {CLIENT} and len(artifacts) == 3,
         'Exact two wheels and one client archive required')
    result = {}
    for path in sorted(artifacts):
        details = check_wheel(path, public_files) if path.name in WHEELS else check_client(path, public_files)
        result[path.name] = {'sha256':digest(path.read_bytes()),'size':path.stat().st_size,**details}
    return {'format':'zti-r6-distribution-guard/1','status':'PASS','archives':result,
            'archive_count':3,'source_bound_before_install_or_import':True,
            'code_imported':False,'archives_extracted':False,
            'notice':'Content/source consistency against caller-verified manifest; not artifact authenticity or outside attestation.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--distributions', type=Path, required=True)
    parser.add_argument('--public-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not args.output.exists(), 'Fresh distribution guard receipt required')
    try:
        manifest_bytes = args.public_manifest.read_bytes()
        report = check_distributions(args.distributions, json.loads(manifest_bytes)['files'])
        report['public_manifest_sha256'] = digest(manifest_bytes)
    except Exception as error:
        report = {'format':'zti-r6-distribution-guard/1','status':'FAIL',
                  'reason':'DISTRIBUTION_CONTENT_CHECK_FAILED','error_type':type(error).__name__,
                  'code_imported':False,'archives_extracted':False}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x', encoding='utf-8') as stream:
            json.dump(report,stream,indent=2,sort_keys=True)
        raise
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'status':'PASS','archive_count':3,'code_imported':False}))


if __name__ == '__main__':
    main()
