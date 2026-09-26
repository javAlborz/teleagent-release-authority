#!/usr/bin/python3 -I
"""Emit the fixed, unsigned v24 voice-image build recipe as data only."""
import hashlib
import json
import sys

APP_REVISION = '0c1630f3bca6df97ed127c1eeae0d2df52307a3a'
APP_TREE = 'e558a74a6890614dbaa7b6343cb605b7e9f2789b'
APP_EPOCH = 1790438153
MATERIAL_PLAN = '9eb9d2a625817ce9b08107bc6a864d159084aff33bbbb31ddf9e0192647f0ff8'
VOICE_BASE = '2a49bdf71e9fd965a58c1703fd9ddd205b34e5782b692a72dd1d248abb0beb43'
MUSL_DEPENDENCY_SUBJECT = 'd5645fa7e268a92f5e9c2442d9c68f70a1ace456e44e81190047b028fe8ce7cb'
MUSL_DEPENDENCY_TAR = '7f5f674aa3c1fb890747e9f8b3dc3c68e9e80633b969dc8f1636303655cfc925'
APK_PACKAGES = ('libcrypto3=3.5.8-r0', 'libssl3=3.5.8-r0')
PLAN_SCHEMA = 'teleagent.offline-voice-image-plan.v24'


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def sha(value):
    return hashlib.sha256(value).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def source_policy():
    return {'version': 1, 'rules': [
        {'action': 'DENY', 'selector': {'identifier': '*', 'match_type': 'WILDCARD'}},
        *({'action': 'ALLOW', 'selector': {'identifier': 'local://' + name, 'match_type': 'EXACT'}}
          for name in ('context', 'dockerfile', 'app', 'dependencies', 'materials')),
        {'action': 'ALLOW', 'selector': {
            'identifier': 'oci-layout://docker.io/library/voice-base@sha256:' + VOICE_BASE,
            'match_type': 'EXACT',
            'constraints': [{'key': 'oci.store', 'value': 'materials', 'condition': 'EQUAL'}]}},
    ]}


def dockerfile():
    command = ('/sbin/apk --no-network --repositories-file /materials/apk/repositories '
               'add --no-cache --no-scripts --upgrade ' + ' '.join(APK_PACKAGES) +
               ' && rm -f /var/log/apk.log' +
               ' && rm -rf /usr/local/lib/node_modules/npm /opt/yarn-v*' +
               ' && rm -f /usr/local/bin/corepack /usr/local/bin/npm /usr/local/bin/npx '
               '/usr/local/bin/yarn /usr/local/bin/yarnpkg' +
               ' && chmod -R go-w /app')
    return ('FROM voice-base AS voice\n'
            'USER 0:0\n'
            'WORKDIR /app/voice-app\n'
            'COPY --chown=0:0 --from=app /voice-app/ /app/voice-app/\n'
            'COPY --chown=0:0 --from=app /lib/ /app/lib/\n'
            'COPY --chown=0:0 --from=dependencies /voice-app/node_modules/ /app/voice-app/node_modules/\n'
            'RUN --network=none --mount=type=bind,from=materials,target=/materials,ro ' +
            json.dumps(['/bin/sh', '-euc', command], separators=(',', ':')) + '\n'
            'LABEL org.opencontainers.image.revision="' + APP_REVISION + '"\n'
            'EXPOSE 3000 3001\n'
            'CMD ["node","index.js"]\n')


def build_plan(epoch, material_plan_sha256, app_tree):
    require(type(epoch) is int and epoch == APP_EPOCH, 'source epoch differs')
    require(type(material_plan_sha256) is str and material_plan_sha256 == MATERIAL_PLAN,
            'material plan differs')
    require(type(app_tree) is str and app_tree == APP_TREE, 'application tree differs')
    generated = {'Dockerfile': dockerfile(),
                 'source-policy.json': canonical(source_policy()).decode('ascii')}
    argv = ['/engines/bin/buildctl', '--addr', 'unix:///run/teleagent-build/buildkitd.sock', 'build',
            '--frontend', 'dockerfile.v0', '--no-cache', '--progress', 'rawjson',
            '--oci-layout', 'materials=/materials/oci',
            '--opt', 'context:voice-base=oci-layout://materials@sha256:' + VOICE_BASE,
            '--local', 'context=/infra/context', '--local', 'dockerfile=/infra/voice-image',
            '--local', 'app=/inputs/app', '--opt', 'context:app=local:app',
            '--local', 'dependencies=/inputs/dependencies', '--opt', 'context:dependencies=local:dependencies',
            '--local', 'materials=/materials', '--opt', 'context:materials=local:materials',
            '--opt', 'platform=linux/amd64', '--opt', 'target=voice',
            '--opt', 'force-network-mode=none', '--opt', 'memory=4294967296',
            '--opt', 'memswap=4294967296', '--opt', 'cpuquota=200000', '--opt', 'cpuperiod=100000',
            '--opt', 'cgroup-parent=/jobs', '--opt', 'build-arg:SOURCE_DATE_EPOCH=' + str(APP_EPOCH),
            '--source-policy-file', '/infra/voice-image/source-policy.json',
            '--output', 'type=docker,dest=/outputs/voice-image.docker.tar,rewrite-timestamp=true',
            '--metadata-file', '/outputs/voice-image-metadata.json']
    return {'schema': PLAN_SCHEMA, 'authorization': 'source-candidate-no-execution-authority',
            'runtimeAccepted': False, 'buildExecuted': False, 'scanAccepted': False,
            'signatureVerified': False, 'releaseApproved': False,
            'appRevision': APP_REVISION, 'appTree': APP_TREE,
            'materialPlanSha256': MATERIAL_PLAN, 'voiceBaseDigest': VOICE_BASE,
            'muslDependencySubjectSha256': MUSL_DEPENDENCY_SUBJECT,
            'muslDependencyTarSha256': MUSL_DEPENDENCY_TAR,
            'apkPackages': list(APK_PACKAGES), 'sourceEpoch': APP_EPOCH,
            'expectedRunCount': 1, 'network': 'none',
            'generatedFiles': [{'path': name, 'sha256': sha(body.encode('ascii')), 'content': body}
                               for name, body in sorted(generated.items())],
            'buildctlArgv': argv,
            'unresolved': ['dependency-tar-consumer-revalidation', 'isolated-runtime-adapter-acceptance',
                           'actual-offline-apk-solve', 'deterministic-image-rebuild-comparison',
                           'fresh-scan-and-independent-release-signing']}


if __name__ == '__main__':
    print('offline voice image plan is a library-only source candidate', file=sys.stderr)
    raise SystemExit(77)
