#!/usr/bin/env bash
# Fetch only the pinned, completed public diagnostics used by the current decision.
set -euo pipefail

[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == javAlborz/teleagent-release-authority &&
   ${GITHUB_REPOSITORY_ID:-} == 1383172221 && -n ${GH_TOKEN:-} ]] || {
  echo 'current release inputs require the hosted authority workflow' >&2
  exit 1
}
[[ -n ${RUNNER_TEMP:-} && -d ${RUNNER_TEMP:-} ]] || exit 1

while read -r run_id head expected_path expected_event; do
  [[ -n $run_id ]] || continue
  response=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run_id" \
    --jq '[.status,.conclusion,.head_sha,.head_branch,.run_attempt,.repository.id,.path,.event] | @tsv')
  IFS=$'\t' read -r status conclusion observed branch attempt repository_id path event <<< "$response"
  [[ $status == completed && $conclusion == success && $observed == "$head" &&
     $branch == feat/hosted-capacity-probe-20260923 && $attempt == 1 &&
     $repository_id == 1383172221 && $path == "$expected_path" &&
     $event == "$expected_event" ]] || {
    echo "fixed release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
35992034723 4faf67a03d87d1a6598790d4f690aceaf39df432 .github/workflows/teleagent-voice-image-diagnostic.yml push
35992359796 e0de0feccb93b86e86c8d304efe781ba9c3be69a .github/workflows/teleagent-private-public-voice-subject-comparison.yml push
35992468711 b7a130c9452a06c31d62541203bea101b22b4445 .github/workflows/teleagent-voice-image-scan-diagnostic.yml push
35992525759 e6bdb1ad55706ab70ae002cef62e296e39f304c7 .github/workflows/teleagent-voice-sbom-diagnostic.yml workflow_dispatch
35992626604 7c31d1bae491e7e6d126b8a962df62ede74d7027 .github/workflows/teleagent-voice-image-attestation-diagnostic.yml workflow_dispatch
35992749716 f90ae9da2527d1e46b79e18a15b4eb28601e7add .github/workflows/teleagent-release-bundle-diagnostic.yml workflow_dispatch
36028598666 e1c21547e7ba4b6938084f8434e19ced4a339b57 .github/workflows/teleagent-voice-image-scan-diagnostic.yml workflow_dispatch
RUNS

base="$RUNNER_TEMP/teleagent-current-release-inputs"
[[ ! -e $base && ! -L $base ]] || {
  echo 'release input root already exists' >&2
  exit 1
}
mkdir -m 0700 -- "$base"
for name in bundle-a bundle-b image scan; do
  mkdir -m 0700 -- "$base/$name"
done
gh run download 35992749716 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-release-bundle-1 --dir "$base/bundle-a"
gh run download 35992749716 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-release-bundle-2 --dir "$base/bundle-b"
gh run download 35992034723 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-voice-image-current-app-diagnostic --dir "$base/image"
gh run download 36028598666 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-voice-image-current-app-scan-diagnostic --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 3 ]] || {
  echo 'release input artifact members differ' >&2
  exit 1
}
echo 'Pinned release input artifacts downloaded for independent verification.'
