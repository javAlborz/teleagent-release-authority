#!/usr/bin/env bash
# Fetch only the exact hosted v32 release evidence for a protected decision.
set -euo pipefail

[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == javAlborz/teleagent-release-authority &&
   ${GITHUB_REPOSITORY_ID:-} == 1383172221 && -n ${GH_TOKEN:-} ]] || {
  echo 'v32 release inputs require the hosted authority workflow' >&2
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
    echo "fixed v32 release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 feat/hosted-capacity-probe-20260923 1 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
36286389498 78251f76d1a1918fceb4385ffd1410f2e248faf2 feat/teleagent-v32-release-authority-20260927 1 .github/workflows/teleagent-v32-hosted-voice-image.yml push
36286467369 ef089f8e9c5fdf0dea79931086d2aa75cf81e1f7 feat/teleagent-v32-release-authority-20260927 1 .github/workflows/teleagent-v32-hosted-voice-sbom.yml push
36286612798 d4adb08a75f9494f49d7fef1a0318e7f6b5bd939 feat/teleagent-v32-release-authority-20260927 1 .github/workflows/teleagent-v32-hosted-voice-scan.yml push
36283815392 2bc5a63d6fe052bd952a6b448c83d82746c9ec7a feat/teleagent-v32-release-authority-20260927 1 .github/workflows/teleagent-v32-hosted-release-bundle.yml push
RUNS

base="$RUNNER_TEMP/teleagent-v32-release-inputs"
[[ ! -e $base && ! -L $base ]] || {
  echo 'v32 release input root already exists' >&2
  exit 1
}
mkdir -m 0700 -- "$base"
for name in bundle-a bundle-b image scan; do
  mkdir -m 0700 -- "$base/$name"
done
gh run download 36283815392 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v32-release-bundle-1 --dir "$base/bundle-a"
gh run download 36283815392 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v32-release-bundle-2 --dir "$base/bundle-b"
gh run download 36286389498 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v32-voice-image-1 --dir "$base/image"
gh run download 36286612798 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v32-voice-image-scan --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 3 ]] || {
  echo 'v32 release input artifact members differ' >&2
  exit 1
}
echo 'Pinned v32 release input artifacts downloaded for independent verification.'
