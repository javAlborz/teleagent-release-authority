#!/usr/bin/env bash
# Fetch only the exact hosted v17 release evidence for a protected decision.
set -euo pipefail

[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == javAlborz/teleagent-release-authority &&
   ${GITHUB_REPOSITORY_ID:-} == 1383172221 && -n ${GH_TOKEN:-} ]] || {
  echo 'v17 release inputs require the hosted authority workflow' >&2
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
    echo "fixed v17 release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 feat/hosted-capacity-probe-20260923 1 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
36232444816 157948891b179b82118308356dd587d98954df1c feat/teleagent-v17-release-authority-20260926 1 .github/workflows/teleagent-v17-hosted-voice-image.yml push
36232658164 30c310802aee107f985fa4d93ee5b60e9ff954cc feat/teleagent-v17-release-authority-20260926 1 .github/workflows/teleagent-v17-hosted-voice-sbom.yml push
36232720033 ca80234f7a2681ee5a2d89f2c3026fc4a0fe0cef feat/teleagent-v17-release-authority-20260926 1 .github/workflows/teleagent-v17-hosted-voice-scan.yml push
36232777418 4ac0a0967ab8b3b9670849f3b8d8f27db79b4176 feat/teleagent-v17-release-authority-20260926 1 .github/workflows/teleagent-v17-hosted-release-bundle.yml push
RUNS

base="$RUNNER_TEMP/teleagent-v17-release-inputs"
[[ ! -e $base && ! -L $base ]] || {
  echo 'v17 release input root already exists' >&2
  exit 1
}
mkdir -m 0700 -- "$base"
for name in bundle-a bundle-b image scan; do
  mkdir -m 0700 -- "$base/$name"
done
gh run download 36232777418 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v17-release-bundle-1 --dir "$base/bundle-a"
gh run download 36232777418 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v17-release-bundle-2 --dir "$base/bundle-b"
gh run download 36232444816 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v17-voice-image-1 --dir "$base/image"
gh run download 36232720033 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v17-voice-image-scan --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 3 ]] || {
  echo 'v17 release input artifact members differ' >&2
  exit 1
}
echo 'Pinned v17 release input artifacts downloaded for independent verification.'
