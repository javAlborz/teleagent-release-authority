#!/usr/bin/env bash
# Fetch only the exact hosted v83 release evidence for a protected decision.
set -euo pipefail

[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == javAlborz/teleagent-release-authority &&
   ${GITHUB_REPOSITORY_ID:-} == 1383172221 && -n ${GH_TOKEN:-} ]] || {
  echo 'v83 release inputs require the hosted authority workflow' >&2
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
    echo "fixed v83 release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 feat/hosted-capacity-probe-20260923 1 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
39942012308 2fc9ee907b89d055bfba18ab1ff82da83821553a fix/teleagent-v83-unsent-authority-20261023 1 .github/workflows/teleagent-v83-hosted-voice-image.yml push
39942586582 8e473a104fb18a40046129001a55d9e6b9617d3b fix/teleagent-v83-unsent-authority-20261023 1 .github/workflows/teleagent-v83-hosted-voice-sbom.yml push
39942387372 746bab8fe4e6359bfb19ede0368938e33b25b0e5 fix/teleagent-v83-unsent-authority-20261023 1 .github/workflows/teleagent-v83-hosted-voice-scan.yml push
39942846975 218afae8298f96bd250f78b4d965d6c9811c4bdb fix/teleagent-v83-unsent-authority-20261023 1 .github/workflows/teleagent-v83-hosted-release-bundle.yml push
RUNS

base="$RUNNER_TEMP/teleagent-v83-release-inputs"
[[ ! -e $base && ! -L $base ]] || {
  echo 'v83 release input root already exists' >&2
  exit 1
}
mkdir -m 0700 -- "$base"
for name in bundle-a bundle-b image scan; do
  mkdir -m 0700 -- "$base/$name"
done
gh run download 39942846975 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v83-release-bundle-1 --dir "$base/bundle-a"
gh run download 39942846975 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v83-release-bundle-2 --dir "$base/bundle-b"
gh run download 39942012308 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v83-voice-image-2 --dir "$base/image"
gh run download 39942387372 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v83-voice-image-scan --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 3 ]] || {
  echo 'v83 release input artifact members differ' >&2
  exit 1
}
echo 'Pinned v83 release input artifacts downloaded for independent verification.'
