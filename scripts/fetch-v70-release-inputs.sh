#!/usr/bin/env bash
# Fetch only the exact hosted v70 release evidence for a protected decision.
set -euo pipefail

[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == javAlborz/teleagent-release-authority &&
   ${GITHUB_REPOSITORY_ID:-} == 1383172221 && -n ${GH_TOKEN:-} ]] || {
  echo 'v70 release inputs require the hosted authority workflow' >&2
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
    echo "fixed v70 release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 feat/hosted-capacity-probe-20260923 1 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
37645625860 217d858482ed28fa0a8916c3923b2cc07ab46181 feat/teleagent-v70-release-authority-20261007 1 .github/workflows/teleagent-v70-hosted-voice-image.yml push
37646247713 ae6426c79ba2805a5b7e5fdc65eb4e48183bb479 feat/teleagent-v70-release-authority-20261007 1 .github/workflows/teleagent-v70-hosted-voice-sbom.yml push
37646101498 a6c3ff4e5e9239f690c83b8dda798fdc78cdd84d feat/teleagent-v70-release-authority-20261007 1 .github/workflows/teleagent-v70-hosted-voice-scan.yml push
37646463615 bb42bfd1ee8f5b30bc36cc063502b524b3909411 feat/teleagent-v70-release-authority-20261007 1 .github/workflows/teleagent-v70-hosted-release-bundle.yml push
RUNS

base="$RUNNER_TEMP/teleagent-v70-release-inputs"
[[ ! -e $base && ! -L $base ]] || {
  echo 'v70 release input root already exists' >&2
  exit 1
}
mkdir -m 0700 -- "$base"
for name in bundle-a bundle-b image scan; do
  mkdir -m 0700 -- "$base/$name"
done
gh run download 37646463615 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v70-release-bundle-1 --dir "$base/bundle-a"
gh run download 37646463615 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v70-release-bundle-2 --dir "$base/bundle-b"
gh run download 37645625860 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v70-voice-image-1 --dir "$base/image"
gh run download 37646101498 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v70-voice-image-scan --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 3 ]] || {
  echo 'v70 release input artifact members differ' >&2
  exit 1
}
echo 'Pinned v70 release input artifacts downloaded for independent verification.'
