#!/usr/bin/python3 -I
"""Recheck an exact unsigned Teleagent material projection as data only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy

PLAN_SHA256 = '9eb9d2a625817ce9b08107bc6a864d159084aff33bbbb31ddf9e0192647f0ff8'
SCHEMA = 'teleagent.offline-material-projection.v1'
ENGINE_PLAN_SHA256 = '5c2dfee0e305d5a84a7debb142b7ddbae3b4dc855a89126622449ebbd2c6e993'
ENGINE_SCHEMA = 'teleagent.offline-engine-projection.v1'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--infra', type=Path, required=True)
    parser.add_argument('--materials', type=Path, required=True)
    parser.add_argument('--engines', type=Path, required=True)
    args = parser.parse_args()
    source = args.infra / 'scripts/release'
    preflight = runpy.run_path(str(source / 'teleagent-offline-supervisor-preflight.py'))
    freshness = runpy.run_path(str(source / 'teleagent-offline-trivy-freshness.py'))
    root_fd = os.open(args.materials, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        result = preflight['verify_projection'](
            root_fd, plan_name='material-plan.json', schema=SCHEMA,
            expected_plan_sha256=PLAN_SHA256)
        plan_fd = os.open('material-plan.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=root_fd)
        try:
            plan_bytes = os.read(plan_fd, preflight['MAX_PLAN'] + 1)
            if os.read(plan_fd, 1) or hashlib.sha256(plan_bytes).hexdigest() != PLAN_SHA256:
                raise ValueError('material plan changed after read-time preflight')
        finally:
            os.close(plan_fd)
        _plan, rows, _size = preflight['parse_plan'](plan_bytes, SCHEMA)
        current = freshness['check_projected'](root_fd, rows)
        engine_fd = os.open(args.engines, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            engine = preflight['verify_projection'](
                engine_fd, plan_name='engine-plan.json', schema=ENGINE_SCHEMA,
                expected_plan_sha256=ENGINE_PLAN_SHA256)
        finally:
            os.close(engine_fd)
        print(json.dumps({'materialProjection': result, 'engineProjection': engine,
                          'trivyFreshness': current, 'signatureVerified': False,
                          'buildExecuted': False}, sort_keys=True))
    finally:
        os.close(root_fd)


if __name__ == '__main__':
    main()
