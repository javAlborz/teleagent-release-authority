#!/usr/bin/env bash
# Fetch only the exact hosted v26 release evidence for a protected decision.
set -euo pipefail

[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == javAlborz/teleagent-release-authority &&
   ${GITHUB_REPOSITORY_ID:-} == 1383172221 && -n ${GH_TOKEN:-} ]] || {
  echo 'v26 release inputs require the hosted authority workflow' >&2
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
    echo "fixed v26 release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 feat/hosted-capacity-probe-20260923 1 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
36260248815 2b729daab711edca350b6a21741ef87b52091a9b feat/teleagent-v26-release-authority-20260926 1 .github/workflows/teleagent-v26-hosted-voice-image.yml push
36260339919 96ed5c0089a9c203d196db5e4e148a5328feba2f feat/teleagent-v26-release-authority-20260926 1 .github/workflows/teleagent-v26-hosted-voice-sbom.yml push
36260424770 b3ef65057ccf455c969a0754a5e87a94068a4f39 feat/teleagent-v26-release-authority-20260926 1 .github/workflows/teleagent-v26-hosted-voice-scan.yml push
36260463221 0dfbf7a290d492b2ca11589dcc377224b1fff48a feat/teleagent-v26-release-authority-20260926 1 .github/workflows/teleagent-v26-hosted-release-bundle.yml push
RUNS

base="$RUNNER_TEMP/teleagent-v26-release-inputs"
[[ ! -e $base && ! -L $base ]] || {
  echo 'v26 release input root already exists' >&2
  exit 1
}
mkdir -m 0700 -- "$base"
for name in bundle-a bundle-b image scan; do
  mkdir -m 0700 -- "$base/$name"
done
gh run download 36260463221 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v26-release-bundle-1 --dir "$base/bundle-a"
gh run download 36260463221 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v26-release-bundle-2 --dir "$base/bundle-b"
gh run download 36260248815 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v26-voice-image-1 --dir "$base/image"
gh run download 36260424770 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v26-voice-image-scan --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 3 ]] || {
  echo 'v26 release input artifact members differ' >&2
  exit 1
}
echo 'Pinned v26 release input artifacts downloaded for independent verification.'
