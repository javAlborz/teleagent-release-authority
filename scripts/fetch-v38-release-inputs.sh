#!/usr/bin/env bash
# Fetch only the exact hosted v38 release evidence for a protected decision.
set -euo pipefail

[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == javAlborz/teleagent-release-authority &&
   ${GITHUB_REPOSITORY_ID:-} == 1383172221 && -n ${GH_TOKEN:-} ]] || {
  echo 'v38 release inputs require the hosted authority workflow' >&2
  exit 1
}
[[ -n ${RUNNER_TEMP:-} && -d ${RUNNER_TEMP:-} ]] || exit 1

while read -r run_id head expected_branch attempt expected_path expected_event; do
  [[ -n $run_id ]] || continue
  response=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run_id" \
    --jq '[.status,.conclusion,.head_sha,.head_branch,.run_attempt,.repository.id,.path,.event] | @tsv')
  IFS=$'\t' read -r status conclusion observed branch observed_attempt repository_id path event <<< "$response"
  [[ $status == completed && $conclusion == success && $observed == "$head" &&
     $branch == "$expected_branch" && $observed_attempt == "$attempt" &&
     $repository_id == 1383172221 && $path == "$expected_path" &&
     $event == "$expected_event" ]] || {
    echo "fixed v38 release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 feat/hosted-capacity-probe-20260923 1 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
36306307348 a435bc094fda5ba1077bcd1109bbf4ef66dc0f3a feat/teleagent-v38-release-authority-20260927 1 .github/workflows/teleagent-v38-hosted-voice-image.yml push
36306406298 f332b5913468aaa2860cbae8ece28592dc55e2fa feat/teleagent-v38-release-authority-20260927 1 .github/workflows/teleagent-v38-hosted-voice-sbom.yml push
36306462572 b8a57b5cb02cb2a126608dc0480aa991c90d8c40 feat/teleagent-v38-release-authority-20260927 1 .github/workflows/teleagent-v38-hosted-voice-scan.yml push
36306531619 f719f8f53b4567b71ff9120554bccfdd915ea5d3 feat/teleagent-v38-release-authority-20260927 1 .github/workflows/teleagent-v38-hosted-release-bundle.yml push
RUNS

base="$RUNNER_TEMP/teleagent-v38-release-inputs"
[[ ! -e $base && ! -L $base ]] || {
  echo 'v38 release input root already exists' >&2
  exit 1
}
mkdir -m 0700 -- "$base"
for name in bundle-a bundle-b image scan; do
  mkdir -m 0700 -- "$base/$name"
done
gh run download 36306531619 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v38-release-bundle-1 --dir "$base/bundle-a"
gh run download 36306531619 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v38-release-bundle-2 --dir "$base/bundle-b"
gh run download 36306307348 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v38-voice-image-1 --dir "$base/image"
gh run download 36306462572 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v38-voice-image-scan --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 3 ]] || {
  echo 'v38 release input artifact members differ' >&2
  exit 1
}
echo 'Pinned v38 release input artifacts downloaded for independent verification.'
