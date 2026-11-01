#!/usr/bin/env python3
"""Observe installed runtime identity without constructing a provider or signing.

The caller must verify the supplied public source manifest before invoking this
script with the installed Python -I. This receipt compares installed own Python
source bytes against that map. It is runtime attribution, not a business test or
an independent authenticity/attestation mechanism. Only the explicit portable
projection is suitable for public evidence; full paths remain in the private
receipt. No environment dump, configuration, issuer or key files are read.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import sysconfig

sys.dont_write_bytecode = True

CHECKOUT = Path(__file__).resolve().parents[2]
OWN = {
    'zti_mcp_r6': ('zti-mcp-r6', '0.3.0', 'successor/r6/provider/src/zti_mcp_r6/'),
    'zti_r6_demo': ('zti-r6-demo', '0.3.0', 'successor/r6/consumer/src/zti_r6_demo/'),
}
SDK = {'mcp': ('mcp', '2.3.0'), 'mcp_types': ('mcp-types', '2.3.0'),
       'cryptography': ('cryptography', '50.0.2')}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def need(condition, message):
    if not condition:
        raise ValueError(message)


def no_links(path):
    for item in (path, *path.parents):
        need(not item.is_symlink() and not (hasattr(item, 'is_junction') and item.is_junction()),
             'Linked package source is not an ordinary installed file')


def expected_tree(files, prefix):
    expected = {}
    for name, digest in files.items():
        if not name.startswith(prefix) or not name.endswith('.py'):
            continue
        relative = name.removeprefix(prefix)
        path = PurePosixPath(relative)
        need(bool(relative) and not path.is_absolute() and '..' not in path.parts and
             '\\' not in relative and ':' not in relative, 'Invalid manifest package path')
        need(type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest) is not None,
             'Invalid source hash in public manifest')
        expected[relative] = digest
    need('__init__.py' in expected, 'Public manifest lacks own package source set')
    return expected


def source_tree(root, expected):
    """Closed source path-set and exact bytes, without importing every module."""
    actual = {}
    for path in root.rglob('*.py'):
        no_links(path)
        need(path.is_file() and path.resolve().is_relative_to(root), 'Package source escaped its installation')
        relative = path.relative_to(root).as_posix()
        actual[relative] = sha(path)
    need(set(actual) == set(expected), 'Installed own package Python file set differs from source manifest')
    need(actual == expected, 'Installed own package Python bytes differ from source manifest')
    return actual


def ordinary_install(module, distribution, site_roots):
    origin = Path(module.__file__).absolute()
    no_links(origin)
    root = origin.parent.resolve()
    need(origin.name == '__init__.py' and origin.is_file(), 'Expected ordinary installed Python package')
    need(not root.is_relative_to(CHECKOUT), 'Own/SDK module loaded from checkout')
    need(any(root.is_relative_to(site) for site in site_roots), 'Module is outside this interpreter installation')
    expected_location = Path(distribution.locate_file(module.__name__)).resolve()
    need(root == expected_location, 'Imported module does not belong to observed distribution location')
    paths = list(module.__path__)
    need(len(paths) == 1 and Path(paths[0]).resolve() == root, 'Namespace or multi-root package not permitted')
    direct_url = distribution.read_text('direct_url.json')
    install = json.loads(direct_url) if direct_url else {}
    need(not install.get('dir_info', {}).get('editable', False), 'Editable installation is not permitted')
    # An own package must have been installed from the built archive, not merely
    # copied into site-packages or installed directly from a source directory.
    if module.__name__ in OWN:
        need('archive_info' in install and 'dir_info' not in install,
             'Own package needs an archive installation receipt')
    return origin.resolve(), root, install


def collect(expected_public_manifest):
    need(sys.version_info[:2] == (3, 12), 'Python 3.12 required')
    need(sys.flags.isolated == 1 and sys.flags.ignore_environment == 1 and sys.flags.no_user_site == 1,
         'Invoke this receipt with Python -I')
    need(not os.environ.get('PYTHONPATH') and not os.environ.get('PYTHONHOME'),
         'Runtime path injection variables must be absent')
    manifest_path = expected_public_manifest.resolve()
    source = json.loads(manifest_path.read_text(encoding='utf-8'))
    need(type(source.get('files')) is dict, 'Expected public manifest files map')
    site_roots = {Path(sysconfig.get_paths()[name]).resolve() for name in ('purelib', 'platlib')}
    need(all(site.is_relative_to(Path(sys.prefix).resolve()) for site in site_roots),
         'Unexpected interpreter installation root')
    executable = Path(sys.executable).absolute()
    need(not executable.resolve().is_relative_to(CHECKOUT), 'Installed interpreter must be outside checkout')
    private = {'executable': str(executable), 'resolved_executable': str(executable.resolve()), 'python_version':sys.version,
               'prefix': sys.prefix, 'base_prefix': sys.base_prefix, 'manifest_path': str(manifest_path),
               'packages': {}}
    portable = {'format': 'zti-r6-runtime-portable/1', 'status': 'PASS',
        'python': {'version': '.'.join(str(value) for value in sys.version_info[:3]), 'version_info': list(sys.version_info[:3]),
                   'implementation': sys.implementation.name, 'executable_sha256': sha(executable.resolve()),
                   'isolated': True, 'environment_paths_disabled': True, 'user_site_disabled': True},
        'expected_public_manifest_sha256': sha(manifest_path), 'packages': {}, 'entrypoints': {},
        'own_modules_outside_checkout': True, 'own_installations_editable': False,
        'own_source_closed_sets_match': True, 'provider_constructed': False,
        'signing_performed': False, 'secret_material_read': False,
        'notice': 'Runtime identity and source-byte attribution only; no provider execution or outside attestation.'}
    for module_name, specification in {**OWN, **SDK}.items():
        distribution_name, expected_version = specification[:2]
        distribution = importlib.metadata.distribution(distribution_name)
        need(distribution.version == expected_version, 'Actual package version differs: '+distribution_name)
        module = importlib.import_module(module_name)
        origin, root, installation = ordinary_install(module, distribution, site_roots)
        private['packages'][module_name] = {'module_file': str(origin), 'package_root': str(root),
            'distribution_location': str(Path(distribution.locate_file('')).resolve()),
            'installation_receipt': installation}
        identity = {'distribution': distribution_name, 'version': distribution.version,
                    'module_entry_sha256': sha(origin), 'module_entry_relative': '__init__.py'}
        if module_name in OWN:
            prefix = specification[2]
            expected = expected_tree(source['files'], prefix)
            actual = source_tree(root, expected)
            identity['source_prefix'] = prefix
            identity['files'] = actual
            identity['installation_kind'] = 'archive'
            identity['editable'] = False
            archive = installation['archive_info']
            archive_hash = archive.get('hashes', {}).get('sha256')
            if archive_hash is None and archive.get('hash', '').startswith('sha256='):
                archive_hash = archive['hash'].removeprefix('sha256=')
            need(type(archive_hash) is str and re.fullmatch(r'[0-9a-f]{64}', archive_hash) is not None,
                 'Installed own archive SHA256 receipt missing')
            identity['installed_archive_sha256'] = archive_hash
            private['packages'][module_name]['file_paths'] = {name:str(root/name) for name in actual}
        portable['packages'][module_name] = identity
    for name, module_name in (('provider', 'zti_mcp_r6.__main__'), ('consumer', 'zti_r6_demo.client')):
        module_spec = importlib.util.find_spec(module_name)
        need(module_spec is not None and module_spec.origin is not None, 'Installed module entry point missing')
        origin = Path(module_spec.origin).resolve()
        package_name = module_name.split('.')[0]
        package_root = Path(private['packages'][package_name]['package_root'])
        need(origin.is_relative_to(package_root) and origin.is_file(), 'Entry point escaped installed package')
        relative = origin.relative_to(package_root).as_posix()
        need(portable['packages'][package_name]['files'].get(relative) == sha(origin),
             'Installed module entry point bytes differ')
        private.setdefault('entrypoint_paths', {})[name] = str(origin)
        portable['entrypoints'][name] = {'module': module_name.removesuffix('.__main__'),
                                       'relative_file': relative, 'sha256': sha(origin), 'executed': False}
    return {'format': 'zti-r6-runtime-private/1', 'status': 'PASS', 'private': private, 'portable': portable}


def write_fresh(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected-public-manifest', type=Path, required=True)
    parser.add_argument('--portable-output', type=Path)
    args = parser.parse_args()
    need(not args.output.exists() and (args.portable_output is None or not args.portable_output.exists()),
         'Fresh receipt files required')
    need(args.portable_output is None or args.output.resolve() != args.portable_output.resolve(),
         'Private and portable outputs must differ')
    try:
        report = collect(args.expected_public_manifest)
    except Exception as error:
        portable = {'format':'zti-r6-runtime-portable/1','status':'FAIL',
                    'reason':'RUNTIME_IDENTITY_CHECK_FAILED','error_type':type(error).__name__}
        write_fresh(args.output, {'format':'zti-r6-runtime-private/1','status':'FAIL',
                    'private_error':str(error),'portable':portable})
        if args.portable_output is not None:
            write_fresh(args.portable_output, portable)
        raise
    write_fresh(args.output, report)
    if args.portable_output is not None:
        write_fresh(args.portable_output, report['portable'])
    print(json.dumps({'status':'PASS','kind':'RUNTIME_IDENTITY_ONLY','own_packages':len(OWN),
                      'sdk_packages':len(SDK),'source_files':sum(len(report['portable']['packages'][name]['files']) for name in OWN)}))


if __name__ == '__main__':
    main()
