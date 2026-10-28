# Maintaining the release authority

Use `POLICY.md` for trust and signing rules. This guide owns release-tool usage.
Host operations, storage decisions and handset acceptance belong to the private
homelab repository's Teleagent operations runbooks. Do not infer live state here.

## Release records and common code

`releases/vN.json` is the reviewed source of release-specific verification data:
application revision/tree, bundle and manifest hashes, size/counts, image and
SBOM identities, scanner report/check/source hashes, selected input manifests,
scan coverage and complete source-run identities. Repository identity, protected
main, hosted execution and the predicate type are fixed in the engine; a release
record cannot override them. Unknown fields and malformed or conflicting records
are rejected. The signing workflow name is derived from the version.

`scripts/release_engine.py` contains common bundle, input, decision and consumer
checks. `scripts/release-tool.py` provides one entry point. They use only the
Python standard library and the already used `gh` command. V85 is the migration
reference; its original versioned scripts and signed workflow remain unchanged.
The shared engine is available for adoption by a reviewed future workflow. Its
existence does not change an installed release or retroactively sign old evidence.

```bash
python3 -I -B scripts/release-tool.py --release v85 check
python3 -I -B scripts/test_release_engine.py
```

`check` validates local record/input/scanner-source bindings with no network and
reports `releaseApproved=false`, `liveStateInspected=false`. It is not a scan or
an attestation check. Historical records may intentionally refuse against a
later checkout's changed input set; inspect their exact authority revision.
Tests isolate V85's input set so adding a future release does not require
loosening that production guard.

## Common workflow commands

On a disposable hosted authority runner with the normal read-only GitHub token:

```bash
python3 -I -B scripts/release-tool.py --release "$RELEASE" fetch \
  --destination "$RUNNER_TEMP/release-inputs"
python3 -I -B scripts/release-tool.py --release "$RELEASE" verify \
  --bundle-a "$RUNNER_TEMP/release-inputs/bundle-a/teleagent-release.diagnostic.tar" \
  --bundle-b "$RUNNER_TEMP/release-inputs/bundle-b/teleagent-release.diagnostic.tar" \
  --summary-a "$RUNNER_TEMP/release-inputs/bundle-a/summary.json" \
  --summary-b "$RUNNER_TEMP/release-inputs/bundle-b/summary.json" \
  --voice-image "$RUNNER_TEMP/release-inputs/image/teleagent-$RELEASE-voice-image.docker.tar" \
  --scan-report "$RUNNER_TEMP/release-inputs/scan/scan.json" \
  --scan-metadata "$RUNNER_TEMP/release-inputs/scan/db-metadata.json" \
  --scan-check "$RUNNER_TEMP/release-inputs/scan/scan-check.json" \
  --output "$RUNNER_TEMP/decision.json"
```

Set `RELEASE` to one reviewed name such as `v85`; this is not an input for an
arbitrary branch, script or URL. `fetch` requires the hosted authority context,
at least 5 GiB available and a new directory directly under `RUNNER_TEMP`.
Every source run must match its ID, revision, branch, first attempt, repository,
workflow, event and completed-success state. Only failed read-only API transport
is retried, at most three times. Conflicting metadata fails immediately. Partial
downloads are retained and never overwritten or silently retried.

The default decision is diagnostic. A future reviewed signing workflow may add
`--authorize` only in its protected-main signing job. The common engine requires
the exact version-derived workflow, repository ID, hosted context, protected
main, workflow-dispatch event and full authority revision. It also rechecks the
complete independent bundles, selected inputs and fresh scan. Do not replace
those checks with a successful exit from an earlier job.

The consuming job must first run the existing **cryptographic** `gh attestation
verify` command with exact signer/source digests, protected-main ref, hosted
runner restriction, OIDC issuer and predicate type. Then pass that verified JSON
to the common consumer:

```bash
python3 -I -B scripts/release-tool.py --release "$RELEASE" consume \
  --verified "$RUNNER_TEMP/verified-attestation.json" \
  --decision "$RUNNER_TEMP/consumed/decision.json" \
  --bundle "$RUNNER_TEMP/consumed/teleagent-release.tar" \
  --approval "$RUNNER_TEMP/consumed/release-approval.json"
```

`consume` does not perform cryptography or contact GitHub. A JSON object that
resembles verification output is not signature evidence. Keep the separately
isolated signer and consumer jobs, exact artifact handoff and workflow permission
boundaries. No tool here installs software, alters retention or activates services.

## Prove compatibility before adoption

The ordinary PR workflow runs small offline contract tests. They compare V85
policy fields, complete decision/approval encodings and refusal behavior against
the frozen implementation. They cover protected context, changed signed fields,
expiry, scan coverage, source metadata, same-inode replicas, unsafe record files,
scanner source substitution and interrupted downloads. Synthetic attestation
fixtures are explicitly not cryptographic signature tests.

The manually dispatched `Release maintenance validation` workflow additionally
retrieves actual pinned V85 evidence on a hosted runner and runs both verifiers
against the same complete artifacts and the same current time. It requires fresh
scan evidence and keeps only a small comparison receipt for 30 days. It has read
permissions only: no OIDC, attestation write, installation or service credentials.
An expired scan should fail; never freeze the production clock to get a pass.

```bash
gh workflow run release-maintenance-validation.yml \
  --repo javAlborz/teleagent-release-authority --ref main -f release=v85
```

Frozen reference file hashes are in `scripts/fixtures/v85-engine-reference.json`.
Do not rewrite them merely to make a comparison pass. A deliberate semantic
change needs its own reviewed tests and policy decision, not a false equivalence
claim. Preserve historical scripts and manifests referenced by signed releases.

## Prepare the next release

1. Bind the checked app main revision and exact package/lock changes. Measure
   eventual host capacity before downloading or extracting large artifacts.
2. Build two hosted images, compare, scan with fresh complete evidence, compare
   SBOMs, then build and compare both complete bundles. Observe every new hash,
   count and run identity; never globally replace version strings in old scripts.
3. Add the new validated release record. Its workflow and scanner filename are
   version-derived, and the scanner source is independently hash-bound. Validate
   the record locally, including exact selected input files.
4. Prepare the version's workflow using the common fetch/verify/consume commands.
   Image construction, package projections, scanner policy and host authorities
   still need their own review; this migration does not generalize those stages.
5. Run contract tests and hosted diagnostic verification without signing. Review
   source and all evidence, merge, then dispatch the protected signing workflow.
6. Hand off the exact accepted artifact, revisions, checks, scan freshness and
   artifact expiry. Stage only after the matching reviewed host capacity and
   installation gates pass. Record storage/retention completion separately.

Keep preparation remote and small on Hermes: source, manifests and receipts are
enough until staging is admitted. Do not keep another bundle/image download for
each diagnostic run. Never remove archives, extracted releases, runtime images,
session state or incident evidence based on this guide alone.
