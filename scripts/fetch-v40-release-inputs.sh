#!/usr/bin/env bash
# Fetch only the exact hosted v40 release evidence for a protected decision.
set -euo pipefail

[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == javAlborz/teleagent-release-authority &&
   ${GITHUB_REPOSITORY_ID:-} == 1383172221 && -n ${GH_TOKEN:-} ]] || {
  echo 'v40 release inputs require the hosted authority workflow' >&2
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
    echo "fixed v40 release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 feat/hosted-capacity-probe-20260923 1 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
36318840372 7d2fadf6d66ee0c02e59bbd074c29c25ee2e7a37 feat/teleagent-v40-release-authority-20260927 1 .github/workflows/teleagent-v40-hosted-voice-image.yml push
36318951407 0fdc51f6c220ee44ca0adeee6d124c672164eae4 feat/teleagent-v40-release-authority-20260927 1 .github/workflows/teleagent-v40-hosted-voice-sbom.yml push
36319013269 5ef9a7eb8919ec014075cd00ffdecb05f4a58cd8 feat/teleagent-v40-release-authority-20260927 1 .github/workflows/teleagent-v40-hosted-voice-scan.yml push
36319077273 c1330daa6bd75203ef19dc57c961d5d256a5c283 feat/teleagent-v40-release-authority-20260927 1 .github/workflows/teleagent-v40-hosted-release-bundle.yml push
RUNS

base="$RUNNER_TEMP/teleagent-v40-release-inputs"
[[ ! -e $base && ! -L $base ]] || {
  echo 'v40 release input root already exists' >&2
  exit 1
}
mkdir -m 0700 -- "$base"
for name in bundle-a bundle-b image scan; do
  mkdir -m 0700 -- "$base/$name"
done
gh run download 36319077273 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v40-release-bundle-1 --dir "$base/bundle-a"
gh run download 36319077273 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v40-release-bundle-2 --dir "$base/bundle-b"
gh run download 36318840372 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v40-voice-image-1 --dir "$base/image"
gh run download 36319013269 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v40-voice-image-scan --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 3 ]] || {
  echo 'v40 release input artifact members differ' >&2
  exit 1
}
echo 'Pinned v40 release input artifacts downloaded for independent verification.'
