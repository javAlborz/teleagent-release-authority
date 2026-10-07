#!/usr/bin/env bash
# Fetch only the exact hosted v71 release evidence for a protected decision.
set -euo pipefail

[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == javAlborz/teleagent-release-authority &&
   ${GITHUB_REPOSITORY_ID:-} == 1383172221 && -n ${GH_TOKEN:-} ]] || {
  echo 'v71 release inputs require the hosted authority workflow' >&2
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
    echo "fixed v71 release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 feat/hosted-capacity-probe-20260923 1 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
37688214148 1429c0b2e05bd0b77f28fc77c8ba108e32bb52b3 feat/teleagent-v71-release-authority-20261007 1 .github/workflows/teleagent-v71-hosted-voice-image.yml push
37688910887 9acba2c5a9f8659cf673871cdb5a1857ae4d451d feat/teleagent-v71-release-authority-20261007 1 .github/workflows/teleagent-v71-hosted-voice-sbom.yml push
37688746063 8be827abb17612af16ee041fc70e1da27981804d feat/teleagent-v71-release-authority-20261007 1 .github/workflows/teleagent-v71-hosted-voice-scan.yml push
37689081103 74ef3d78eb720d7bb5a0d7923ef7b484f960e63f feat/teleagent-v71-release-authority-20261007 1 .github/workflows/teleagent-v71-hosted-release-bundle.yml push
RUNS

base="$RUNNER_TEMP/teleagent-v71-release-inputs"
[[ ! -e $base && ! -L $base ]] || {
  echo 'v71 release input root already exists' >&2
  exit 1
}
mkdir -m 0700 -- "$base"
for name in bundle-a bundle-b image scan; do
  mkdir -m 0700 -- "$base/$name"
done
gh run download 37689081103 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v71-release-bundle-1 --dir "$base/bundle-a"
gh run download 37689081103 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v71-release-bundle-2 --dir "$base/bundle-b"
gh run download 37688214148 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v71-voice-image-1 --dir "$base/image"
gh run download 37688746063 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v71-voice-image-scan --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 3 ]] || {
  echo 'v71 release input artifact members differ' >&2
  exit 1
}
echo 'Pinned v71 release input artifacts downloaded for independent verification.'
