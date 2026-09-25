#!/usr/bin/env bash
# Fetch only the exact hosted v11 release evidence for a protected decision.
set -euo pipefail

[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == javAlborz/teleagent-release-authority &&
   ${GITHUB_REPOSITORY_ID:-} == 1383172221 && -n ${GH_TOKEN:-} ]] || {
  echo 'v11 release inputs require the hosted authority workflow' >&2
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
    echo "fixed v11 release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 feat/hosted-capacity-probe-20260923 1 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
36159290820 96e1def7d2153d22ee0c0ccad65a595ca5c3c19d feat/teleagent-v11-release-authority-20260925 1 .github/workflows/teleagent-v11-hosted-voice-image.yml push
36159422712 2464d282efac57f923015ec8fa9d6b9caaa98318 feat/teleagent-v11-release-authority-20260925 1 .github/workflows/teleagent-v11-hosted-voice-sbom.yml push
36159422789 2464d282efac57f923015ec8fa9d6b9caaa98318 feat/teleagent-v11-release-authority-20260925 1 .github/workflows/teleagent-v11-hosted-voice-scan.yml push
36159517220 f06a4d94e72e79eaa622796ca4d77e7462f9ec3c feat/teleagent-v11-release-authority-20260925 1 .github/workflows/teleagent-v11-hosted-release-bundle.yml push
RUNS

base="$RUNNER_TEMP/teleagent-v11-release-inputs"
[[ ! -e $base && ! -L $base ]] || {
  echo 'v11 release input root already exists' >&2
  exit 1
}
mkdir -m 0700 -- "$base"
for name in bundle-a bundle-b image scan; do
  mkdir -m 0700 -- "$base/$name"
done
gh run download 36159517220 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v11-release-bundle-1 --dir "$base/bundle-a"
gh run download 36159517220 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v11-release-bundle-2 --dir "$base/bundle-b"
gh run download 36159290820 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v11-voice-image-1 --dir "$base/image"
gh run download 36159422789 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v11-voice-image-scan --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 3 ]] || {
  echo 'v11 release input artifact members differ' >&2
  exit 1
}
echo 'Pinned v11 release input artifacts downloaded for independent verification.'
