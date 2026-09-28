#!/usr/bin/env bash
# Fetch only the exact hosted v44 release evidence for a protected decision.
set -euo pipefail

[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == javAlborz/teleagent-release-authority &&
   ${GITHUB_REPOSITORY_ID:-} == 1383172221 && -n ${GH_TOKEN:-} ]] || {
  echo 'v44 release inputs require the hosted authority workflow' >&2
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
    echo "fixed v44 release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 feat/hosted-capacity-probe-20260923 1 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
36476340342 1965413c7e972974cdb2f87d99dd18e8e03ef4e8 feat/teleagent-v44-release-authority-20260928 1 .github/workflows/teleagent-v44-hosted-voice-image.yml push
36476570182 e08272a3f3e0f4e229b906fa8654311857481382 feat/teleagent-v44-release-authority-20260928 1 .github/workflows/teleagent-v44-hosted-voice-sbom.yml push
36476705207 783f41972c01dea4d664e4b0f6903c69edac0a50 feat/teleagent-v44-release-authority-20260928 1 .github/workflows/teleagent-v44-hosted-voice-scan.yml push
36476827792 d7a21695057365893ddc84f13488b6565ac7416c feat/teleagent-v44-release-authority-20260928 1 .github/workflows/teleagent-v44-hosted-release-bundle.yml push
RUNS

base="$RUNNER_TEMP/teleagent-v44-release-inputs"
[[ ! -e $base && ! -L $base ]] || {
  echo 'v44 release input root already exists' >&2
  exit 1
}
mkdir -m 0700 -- "$base"
for name in bundle-a bundle-b image scan; do
  mkdir -m 0700 -- "$base/$name"
done
gh run download 36476827792 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v44-release-bundle-1 --dir "$base/bundle-a"
gh run download 36476827792 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v44-release-bundle-2 --dir "$base/bundle-b"
gh run download 36476340342 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v44-voice-image-1 --dir "$base/image"
gh run download 36476705207 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v44-voice-image-scan --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 3 ]] || {
  echo 'v44 release input artifact members differ' >&2
  exit 1
}
echo 'Pinned v44 release input artifacts downloaded for independent verification.'
