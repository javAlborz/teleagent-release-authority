#!/usr/bin/env bash
# Fetch only the exact hosted v54 release evidence for a protected decision.
set -euo pipefail

[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == javAlborz/teleagent-release-authority &&
   ${GITHUB_REPOSITORY_ID:-} == 1383172221 && -n ${GH_TOKEN:-} ]] || {
  echo 'v54 release inputs require the hosted authority workflow' >&2
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
    echo "fixed v54 release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 feat/hosted-capacity-probe-20260923 1 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
36931791670 3612d4a79acffc114e270a6ee60dcf74aab3794f feat/teleagent-v54-release-authority-20261001 1 .github/workflows/teleagent-v54-hosted-voice-image.yml push
36932265701 8ab79fd36163b691dc2bfa9cbc97c04fc8ebd97c feat/teleagent-v54-release-authority-20261001 1 .github/workflows/teleagent-v54-hosted-voice-sbom.yml push
36932129452 5e0c58bf01661508b98824896f6be52c0ed43de2 feat/teleagent-v54-release-authority-20261001 1 .github/workflows/teleagent-v54-hosted-voice-scan.yml push
36932432522 d86c33c4c482db2ab972541a03e356d5cce91033 feat/teleagent-v54-release-authority-20261001 1 .github/workflows/teleagent-v54-hosted-release-bundle.yml push
RUNS

base="$RUNNER_TEMP/teleagent-v54-release-inputs"
[[ ! -e $base && ! -L $base ]] || {
  echo 'v54 release input root already exists' >&2
  exit 1
}
mkdir -m 0700 -- "$base"
for name in bundle-a bundle-b image scan; do
  mkdir -m 0700 -- "$base/$name"
done
gh run download 36932432522 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v54-release-bundle-1 --dir "$base/bundle-a"
gh run download 36932432522 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v54-release-bundle-2 --dir "$base/bundle-b"
gh run download 36931791670 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v54-voice-image-1 --dir "$base/image"
gh run download 36932129452 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v54-voice-image-scan --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 3 ]] || {
  echo 'v54 release input artifact members differ' >&2
  exit 1
}
echo 'Pinned v54 release input artifacts downloaded for independent verification.'
