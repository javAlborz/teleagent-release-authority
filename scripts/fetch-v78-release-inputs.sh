#!/usr/bin/env bash
# Fetch only the exact hosted v78 release evidence for a protected decision.
set -euo pipefail

[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == javAlborz/teleagent-release-authority &&
   ${GITHUB_REPOSITORY_ID:-} == 1383172221 && -n ${GH_TOKEN:-} ]] || {
  echo 'v78 release inputs require the hosted authority workflow' >&2
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
    echo "fixed v78 release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 feat/hosted-capacity-probe-20260923 1 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
38797371869 501419bc4f8a31dbd0675d8cfee40a6be0dee57c feat/teleagent-v78-release-authority-20261015 1 .github/workflows/teleagent-v78-hosted-voice-image.yml push
38797765677 4d5f1b6ddf10117615d3df53a7c45eb5543fbb95 feat/teleagent-v78-release-authority-20261015 1 .github/workflows/teleagent-v78-hosted-voice-sbom.yml push
38797665048 0569b23dcac456d507ac099157259963e5101839 feat/teleagent-v78-release-authority-20261015 1 .github/workflows/teleagent-v78-hosted-voice-scan.yml push
38797931633 0a179e84c3c3e118bf4990327dd8d4c8d812b496 feat/teleagent-v78-release-authority-20261015 1 .github/workflows/teleagent-v78-hosted-release-bundle.yml push
RUNS

base="$RUNNER_TEMP/teleagent-v78-release-inputs"
[[ ! -e $base && ! -L $base ]] || {
  echo 'v78 release input root already exists' >&2
  exit 1
}
mkdir -m 0700 -- "$base"
for name in bundle-a bundle-b image scan; do
  mkdir -m 0700 -- "$base/$name"
done
gh run download 38797931633 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v78-release-bundle-1 --dir "$base/bundle-a"
gh run download 38797931633 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v78-release-bundle-2 --dir "$base/bundle-b"
gh run download 38797371869 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v78-voice-image-1 --dir "$base/image"
gh run download 38797665048 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v78-voice-image-scan --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 3 ]] || {
  echo 'v78 release input artifact members differ' >&2
  exit 1
}
echo 'Pinned v78 release input artifacts downloaded for independent verification.'
