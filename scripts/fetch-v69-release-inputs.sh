#!/usr/bin/env bash
# Fetch only the exact hosted v69 release evidence for a protected decision.
set -euo pipefail

[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == javAlborz/teleagent-release-authority &&
   ${GITHUB_REPOSITORY_ID:-} == 1383172221 && -n ${GH_TOKEN:-} ]] || {
  echo 'v69 release inputs require the hosted authority workflow' >&2
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
    echo "fixed v69 release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 feat/hosted-capacity-probe-20260923 1 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
37610564193 51ac55432e4bc7aaae36368e82f36270e3f33483 feat/teleagent-v69-release-authority-20261007 1 .github/workflows/teleagent-v69-hosted-voice-image.yml push
37610977062 2f188f32dc3d24202d1a37196c34f0f5b389974b feat/teleagent-v69-release-authority-20261007 1 .github/workflows/teleagent-v69-hosted-voice-sbom.yml push
37610840269 7187e6b1c1a76939a098fc6efcf548451329729f feat/teleagent-v69-release-authority-20261007 1 .github/workflows/teleagent-v69-hosted-voice-scan.yml push
37611129402 9428dcdd5d1fbe3b34d8628f4eb788ab2b88a772 feat/teleagent-v69-release-authority-20261007 1 .github/workflows/teleagent-v69-hosted-release-bundle.yml push
RUNS

base="$RUNNER_TEMP/teleagent-v69-release-inputs"
[[ ! -e $base && ! -L $base ]] || {
  echo 'v69 release input root already exists' >&2
  exit 1
}
mkdir -m 0700 -- "$base"
for name in bundle-a bundle-b image scan; do
  mkdir -m 0700 -- "$base/$name"
done
gh run download 37611129402 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v69-release-bundle-1 --dir "$base/bundle-a"
gh run download 37611129402 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v69-release-bundle-2 --dir "$base/bundle-b"
gh run download 37610564193 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v69-voice-image-1 --dir "$base/image"
gh run download 37610840269 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v69-voice-image-scan --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 3 ]] || {
  echo 'v69 release input artifact members differ' >&2
  exit 1
}
echo 'Pinned v69 release input artifacts downloaded for independent verification.'
