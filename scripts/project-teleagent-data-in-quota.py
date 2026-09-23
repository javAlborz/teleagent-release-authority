#!/usr/bin/python3 -I
"""Project pinned Teleagent inputs as data inside one disposable 32 GiB volume."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess

MATERIAL_SOURCE_SHA256 = 'a548aad7e6018d57bbddad2eaf99a2fc7ffe1f69ae328982a9d97925448c9cf0'
ENGINE_SOURCE_SHA256 = '0f976d28a4d774346df1942c07fcb40ea1c5d055be9d906e877f4b2428843857'
TRIVY_MANIFEST_SHA256 = '0d044673603e2e2c9c0ac23a8d0d9c7d694bae4f22542559e3f2fafe2012675c'
MATERIAL_PLAN_SHA256 = '1bee8f8df904286a1dcddcc23471fa10cfb96b662b4af68feb866cfc18114cd5'
ENGINE_PLAN_SHA256 = '5c2dfee0e305d5a84a7debb142b7ddbae3b4dc855a89126622449ebbd2c6e993'


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def same_file(path, expected):
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    need(actual == expected, 'pinned data or source hash differs: ' + path.name)


def fixed(argv, maximum=16384):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=1800, check=False)
    need(len(result.stdout) <= maximum and len(result.stderr) <= maximum,
         'data projection output exceeded bound')
    need(result.returncode == 0,
         'data projection refused: ' + Path(argv[1]).name +
         ' exit=' + str(result.returncode) +
         ' stderr=' + result.stderr.decode('utf-8', 'replace')[-2048:])
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--runner-temp', required=True, type=Path)
    args = parser.parse_args()
    workspace = args.workspace
    runner_temp = args.runner_temp
    need(workspace.is_absolute() and runner_temp.is_absolute() and
         workspace.is_dir() and runner_temp.is_dir() and
         workspace.name == 'teleagent-release-authority' and
         runner_temp.name == '_temp', 'hosted workspace or temporary root differs')
    authority = workspace / 'authority'
    infra = workspace / 'infrastructure'
    app = workspace / 'app'
    inputs = runner_temp / 'teleagent-inputs'
    need(all(item.is_dir() for item in (authority, infra, app, inputs)),
         'exact checked-out source and input roots required')
    release = infra / 'scripts/release'
    same_file(release / 'teleagent-offline-materials.py', MATERIAL_SOURCE_SHA256)
    same_file(release / 'teleagent-offline-engine-materials.py', ENGINE_SOURCE_SHA256)
    same_file(inputs / 'trivy/manifest.json', TRIVY_MANIFEST_SHA256)
    storage = runpy.run_path(str(authority / 'scripts/hosted-storage-admission.py'),
                             run_name='teleagent_projected_storage')
    with storage['admitted_storage']() as (mounted, result):
        materials = mounted / 'teleagent-materials'
        engines = mounted / 'teleagent-engines'
        fixed(['/usr/bin/python3', '-I', str(release / 'teleagent-offline-materials.py'),
               '--oci', str(inputs / 'oci'), '--npm', str(inputs / 'npm'),
               '--trivy', str(inputs / 'trivy'),
               '--tools', str(inputs / 'fixed/tools'),
               '--indexes', str(inputs / 'fixed/indexes'),
               '--apk', str(inputs / 'fixed/apk'),
               '--providers', str(inputs / 'fixed/providers'),
               '--app-source', str(app),
               '--candidate-trivy-manifest-sha256', TRIVY_MANIFEST_SHA256,
               '--output', str(materials)])
        fixed(['/usr/bin/python3', '-I', str(release / 'teleagent-offline-engine-materials.py'),
               '--input', str(inputs / 'fixed/engine'), '--output', str(engines)])
        verified = json.loads(fixed(
            ['/usr/bin/python3', '-I', str(authority / 'scripts/verify-teleagent-data-projection.py'),
            '--infra', str(infra), '--materials', str(materials), '--engines', str(engines)],
            maximum=65536))
        same_file(materials / 'material-plan.json', MATERIAL_PLAN_SHA256)
        same_file(engines / 'engine-plan.json', ENGINE_PLAN_SHA256)
        need(verified['materialProjection']['dataOnly'] is True and
             verified['engineProjection']['dataOnly'] is True and
             verified['buildExecuted'] is False and verified['signatureVerified'] is False,
             'bounded projection evidence differs')
        result['purpose'] = 'bounded-teleagent-data-projection'
        result['materialPlanSha256'] = MATERIAL_PLAN_SHA256
        result['enginePlanSha256'] = ENGINE_PLAN_SHA256
        result['trivyFreshnessAcceptedForBuild'] = False
        result['teleagentBuildExecuted'] = False
    need(result['cleanupVerified'] is True and result['afterWorkloadQuota']['availableBytes'] >=
         20 * 1024 ** 3, 'bounded material projection consumed unexpected quota')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
