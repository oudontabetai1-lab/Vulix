"""Static dependency contract: no application imports, browsers or network required."""
import ast
import copy
from pathlib import Path
import re
import sys
import tomllib

import yaml


ROOT = Path(__file__).resolve().parents[1]


def import_inventory(sources, stdlib_names):
    """Classify every import, including function-local and guarded imports."""
    standard, external = set(), {}
    for path, source in sources.items():
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                name = name.split('.')[0]
                if name in stdlib_names:
                    standard.add(name)
                elif name != 'wscan':
                    external.setdefault(name, set()).add(path)
    return standard, external


def requirement_names(text):
    """Normalize distribution names, extras and version constraints in these files."""
    return {
        re.sub(r'[-_.]+', '-', match.group().lower())
        for line in text.splitlines()
        if (match := re.match(r'[A-Za-z0-9][A-Za-z0-9_.-]*', line.strip()))
    }


def scanner_registry(source):
    """Read registry keys and source modules without importing scanner classes."""
    tree = ast.parse(source)
    modules = {
        alias.asname or alias.name: node.module
        for node in tree.body if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    registry = next(
        node.value for node in tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name) and node.target.id == 'SCANNERS'
    )
    return {
        key.value: f'wscan/scanners/{modules[value.id]}.py'
        for key, value in zip(registry.keys, registry.values)
    }


def feature_dependencies(features, name, trail=()):
    """Resolve additive feature inheritance; reject cycles rather than hiding them."""
    if name in trail:
        raise ValueError(f'Feature cycle: {trail + (name,)}')
    feature = features[name]
    packages = set(feature.get('required_pip', [])) | set(feature.get('optional_pip', []))
    runtimes = set(feature.get('required_runtimes', [])) | set(feature.get('optional_runtimes', []))
    for parent in feature.get('requires_features', []):
        inherited_packages, inherited_runtimes = feature_dependencies(features, parent, trail + (name,))
        packages |= inherited_packages
        runtimes |= inherited_runtimes
    return packages, runtimes


def test_manifest_covers_imports_requirements_and_features():
    manifest = yaml.safe_load((ROOT / 'config/feature_manifest.yaml').read_text())
    sources = {p.relative_to(ROOT).as_posix(): p.read_text(encoding='utf-8')
               for p in (ROOT / 'wscan').rglob('*.py')}
    standard, external = import_inventory(sources, sys.stdlib_module_names)
    assert manifest['schema_version'] == 1
    assert set(manifest['stdlib_imports']) == standard
    assert {name: set(paths) for name, paths in manifest['import_sources'].items()} == external
    packages = manifest['packages']
    mapped_imports = [name for entry in packages.values() for name in entry['imports']]
    assert len(mapped_imports) == len(set(mapped_imports))
    assert set(mapped_imports) == set(external)

    files = manifest['scope']['requirements_files']
    assert set(files) == {p.name for p in ROOT.glob('requirements*.txt')}
    requirements = {name: requirement_names((ROOT / name).read_text()) for name in files}
    assert set().union(*requirements.values()) <= set(packages)
    gaps = {entry['package']: entry for entry in manifest['gaps']}
    assert len(gaps) == len(manifest['gaps'])
    for name, entry in packages.items():
        declared_in = {file for file, names in requirements.items() if name in names}
        assert set(entry['requirements']) == declared_in, name
        if declared_in:
            assert entry['status'] == 'declared', name
        else:
            assert entry['status'] in {'gap', 'transitive'}, name
            assert gaps[name]['reason'] and gaps[name]['follow_up']
            assert entry['install_commands'], name
            if entry['status'] == 'transitive':
                assert entry['provided_by'] in packages, name
                assert packages[entry['provided_by']]['status'] == 'declared', name
    assert set(gaps) == {name for name, entry in packages.items() if not entry['requirements']}

    features = manifest['features']
    used_packages, used_runtimes = set(), set()
    for name, feature in features.items():
        assert all(path in sources for path in feature.get('sources', [])), name
        assert not set(feature.get('required_pip', [])) & set(feature.get('optional_pip', [])), name
        pip, runtimes = feature_dependencies(features, name)
        assert pip <= set(packages), name
        assert runtimes <= set(manifest['external_runtimes']), name
        used_packages |= pip
        used_runtimes |= runtimes
    assert used_packages == set(packages)
    assert used_runtimes == set(manifest['external_runtimes'])
    assert set(features['base_install']['required_pip']) == requirements['requirements.txt']
    registry = scanner_registry(sources['wscan/scanners/__init__.py'])
    assert {name.removeprefix('scanner.') for name in features if name.startswith('scanner.')} == set(registry)
    for check, path in registry.items():
        assert features[f'scanner.{check}']['sources'] == [path]
        assert 'scan' in features[f'scanner.{check}']['requires_features']
        scanner_pip, _ = feature_dependencies(features, f'scanner.{check}')
        _, scanner_imports = import_inventory({path: sources[path]}, sys.stdlib_module_names)
        explained = {module for package in scanner_pip for module in packages[package]['imports']}
        assert set(scanner_imports) <= explained


def test_import_inventory_includes_optional_and_new_dependencies():
    source = '''
import os
from wscan.engine import ScanEngine
from . import internal
try:
    from PIL import Image
except ImportError:
    pass
def delayed():
    import newly_added.client
'''
    assert import_inventory({'wscan/example.py': source}, {'os'}) == (
        {'os'}, {'PIL': {'wscan/example.py'}, 'newly_added': {'wscan/example.py'}}
    )


def test_requirement_names_handle_extras_and_spelling():
    assert requirement_names('# comment\nuvicorn[standard]>=0.24\nPyYAML>=6\nbrowser_use==0.12.6\n') == {
        'uvicorn', 'pyyaml', 'browser-use'
    }


def test_feature_inheritance_and_cycles():
    features = {'base': {'required_pip': ['httpx'], 'required_runtimes': ['python']},
                'qr': {'requires_features': ['base'], 'optional_pip': ['pillow']}}
    original = copy.deepcopy(features)
    assert feature_dependencies(features, 'qr') == ({'httpx', 'pillow'}, {'python'})
    assert features == original
    features['base']['requires_features'] = ['qr']
    try:
        feature_dependencies(features, 'qr')
    except ValueError as exc:
        assert 'Feature cycle' in str(exc)
    else:
        raise AssertionError('Feature cycles must fail validation')


def test_optional_feature_boundaries():
    manifest = yaml.safe_load((ROOT / 'config/feature_manifest.yaml').read_text())
    features = manifest['features']
    assert features['mfa_totp_qr']['required_pip'] == ['opencv-python-headless', 'numpy']
    assert features['mfa_totp_qr']['optional_pip'] == ['pillow']
    assert features['scanner.transport_security']['optional_pip'] == ['cryptography']
    assert features['scanner.tls_scan']['required_pip'] == ['sslyze']
    assert features['mfa_totp_mcp']['required_runtimes'] == ['totp_mcp']
    assert features['mfa_email_mcp']['required_runtimes'] == ['email_mcp']
    assert features['oob_email_mcp']['required_pip'] == ['mcp']
    assert not feature_dependencies(features, 'mfa_totp_native')[0]
    for entry in manifest['resolved_gaps']:
        assert entry['original_gap']
        assert entry['resolution'] == manifest['packages'][entry['package']]['requirements']
    assert all(entry['setup'] for entry in manifest['external_runtimes'].values())


def test_packaging_extras_cover_manifest_requirements():
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text())
    manifest = yaml.safe_load((ROOT / 'config/feature_manifest.yaml').read_text())
    dynamic = project['tool']['setuptools']['dynamic']
    assert 'optional-dependencies' in project['project']['dynamic']
    assert dynamic['dependencies'] == {'file': ['requirements.txt']}
    extras = dynamic['optional-dependencies']
    optional_files = set(manifest['scope']['requirements_files']) - {'requirements.txt'}
    assert optional_files == {p.name for p in ROOT.glob('requirements-*.txt')}
    assert set(extras) == {name.removeprefix('requirements-').removesuffix('.txt')
                           for name in optional_files}
    for extra, source in extras.items():
        filename = f'requirements-{extra}.txt'
        assert source == {'file': [filename]}
        declared = {name for name, entry in manifest['packages'].items()
                    if filename in entry['requirements']}
        assert declared == requirement_names((ROOT / filename).read_text()), extra
