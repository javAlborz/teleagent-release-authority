#!/usr/bin/python3 -I
"""Compare four unsigned hosted observations as data, without release authority."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

TARGETS = ('glibc', 'musl')
REPLICAS = ('1', '2')
MAX_JSON = 65536
MIN_QUOTA_REMAINING = 20 * 1024 ** 3
SHA = re.compile(r'[a-f0-9]{64}\Z')


def need(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate observation field')
        result[key] = value
    return result


def load(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 < before.st_size <= MAX_JSON, 'observation file metadata differs')
        data = os.read(fd, MAX_JSON + 1)
        after = os.fstat(fd)
        need(len(data) == before.st_size and
             (before.st_dev, before.st_ino, before.st_mode, before.st_nlink,
              before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_mode, after.st_nlink,
              after.st_size, after.st_mtime_ns, after.st_ctime_ns),
             'observation file changed while reading')
    finally:
        os.close(fd)
    value = json.loads(data, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(
                           ValueError('nonfinite observation value')))
    need(type(value) is dict and data ==
         (json.dumps(value, sort_keys=True) + '\n').encode('ascii'),
         'observation JSON is not the canonical diagnostic output')
    return value


def subject(value, target, plan_sha):
    need(value.get('cleanupVerified') is True and
         value.get('purpose') == 'bounded-teleagent-data-projection' and
         type(value.get('materialPlanSha256')) is str and
         SHA.fullmatch(value['materialPlanSha256']) and
         type(value.get('enginePlanSha256')) is str and
         SHA.fullmatch(value['enginePlanSha256']) and
         value.get('sourceEpoch') == 1790204008 and
         value.get('appSourcePairFilesProjected') == 12 and
         value.get('payloadSourceFilesProjected') == 3 and
         value.get('privateInputReadOnlyAliasesVerified') is True and
         value.get('payloadMaterialPinsMatched') is True and
         value.get('teleagentBuildExecuted') is True and
         value.get('buildPeakMeasured') is False and
         value.get('trivyFreshnessAcceptedForBuild') is False and
         value.get('unsignedBuildPlanSha256') == plan_sha and
         type(value.get('afterWorkloadQuota')) is dict and
         type(value['afterWorkloadQuota'].get('availableBytes')) is int and
         value['afterWorkloadQuota']['availableBytes'] >= MIN_QUOTA_REMAINING,
         'diagnostic storage, input or plan evidence differs')
    result = value.get('projectedCallbackResult')
    need(type(result) is dict and result.get('target') == target and
         result.get('unsignedNativeBuildDiagnostic') is True and
         result.get('releaseAuthority') is False and
         type(result.get('dependencySubjectSha256')) is str and
         SHA.fullmatch(result['dependencySubjectSha256']) and
         type(result.get('dependencyBytes')) is int and result['dependencyBytes'] > 0 and
         type(result.get('dependencyEntries')) is int and result['dependencyEntries'] > 0 and
         type(result.get('runLogFiles')) is int and result['runLogFiles'] > 0 and
         type(result.get('phases')) is list and len(result['phases']) == 2,
         'diagnostic native export differs')
    phases = []
    for phase, name in zip(result['phases'], ('prepare', 'payload')):
        expected_inputs = ({'/materials'} if name == 'prepare' else
                           {'/materials', '/payload', '/work/source'})
        need(type(phase) is dict and phase.get('phase') == name and
             type(phase.get('projectedSha256')) is str and
             SHA.fullmatch(phase['projectedSha256']) and
             type(phase.get('snapshotEquivalence')) is dict and
             set(phase['snapshotEquivalence']) == expected_inputs and
             all(type(row) is dict and row.get('equalAtReadTime') is True and
                 row.get('immutableThroughRun') is False and
                 type(row.get('treeSha256')) is str and SHA.fullmatch(row['treeSha256'])
                 for row in phase['snapshotEquivalence'].values()),
             'diagnostic RUN or input snapshot differs')
        # The projected OCI record binds ephemeral BuildKit IDs and paths.
        # Validate each digest's shape, then compare only retained input bytes.
        phases.append({'phase': name,
                       'snapshotEquivalence': phase['snapshotEquivalence']})
    return {'target': target, 'materialPlanSha256': value['materialPlanSha256'],
            'enginePlanSha256': value['enginePlanSha256'],
            'sourceEpoch': value['sourceEpoch'],
            'dependencySubjectSha256': result['dependencySubjectSha256'],
            'dependencyBytes': result['dependencyBytes'],
            'dependencyEntries': result['dependencyEntries'],
            'runLogFiles': result['runLogFiles'], 'phases': phases}


def compare(root, plan_sha):
    need(type(plan_sha) is str and SHA.fullmatch(plan_sha), 'plan digest syntax differs')
    need(root.is_absolute() and root.is_dir() and root.resolve() == root and
         not root.is_symlink(),
         'observation directory differs')
    expected = {f'{target}-{replica}.json' for target in TARGETS for replica in REPLICAS}
    need({entry.name for entry in root.iterdir()} == expected,
         'observation file set differs')
    summary = {}
    for target in TARGETS:
        values = [subject(load(root / f'{target}-{replica}.json'), target, plan_sha)
                  for replica in REPLICAS]
        need(values[0] == values[1], 'independent ' + target + ' dependency subject differs')
        summary[target] = {key: value for key, value in values[0].items()
                           if key != 'phases'}
    return {'schema': 'teleagent.unsigned-native-comparison.v1',
            'authorization': 'diagnostic-data-only-no-release-authority',
            'unsignedBuildPlanSha256': plan_sha,
            'matchingDependencySubjects': summary,
            'artifactRetained': False, 'signatureVerified': False,
            'releaseApproved': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--plan-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(compare(args.root, args.plan_sha256), sort_keys=True))


if __name__ == '__main__':
    main()
