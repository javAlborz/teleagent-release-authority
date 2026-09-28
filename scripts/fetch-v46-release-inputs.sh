#!/usr/bin/env bash
# Fetch only the exact hosted v46 release evidence for a protected decision.
set -euo pipefail

[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == javAlborz/teleagent-release-authority &&
   ${GITHUB_REPOSITORY_ID:-} == 1383172221 && -n ${GH_TOKEN:-} ]] || {
  echo 'v46 release inputs require the hosted authority workflow' >&2
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
    echo "fixed v46 release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 feat/hosted-capacity-probe-20260923 1 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
36492111775 60ee6aa33939e282c9467a7d50ae6ae02836f9bb feat/teleagent-v46-release-authority-20260928 1 .github/workflows/teleagent-v46-hosted-voice-image.yml push
36492286417 7928ca6be259d6ef28c1e9eb202691ec5548e80b feat/teleagent-v46-release-authority-20260928 1 .github/workflows/teleagent-v46-hosted-voice-sbom.yml push
36492393509 2805676aa0bcefef3f68bf7aa3598b6ea0835327 feat/teleagent-v46-release-authority-20260928 1 .github/workflows/teleagent-v46-hosted-voice-scan.yml push
36492464019 40c221d538690318a49c484d8e1e21b9af0926c1 feat/teleagent-v46-release-authority-20260928 1 .github/workflows/teleagent-v46-hosted-release-bundle.yml push
RUNS

base="$RUNNER_TEMP/teleagent-v46-release-inputs"
[[ ! -e $base && ! -L $base ]] || {
  echo 'v46 release input root already exists' >&2
  exit 1
}
mkdir -m 0700 -- "$base"
for name in bundle-a bundle-b image scan; do
  mkdir -m 0700 -- "$base/$name"
done
gh run download 36492464019 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v46-release-bundle-1 --dir "$base/bundle-a"
gh run download 36492464019 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v46-release-bundle-2 --dir "$base/bundle-b"
gh run download 36492111775 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v46-voice-image-1 --dir "$base/image"
gh run download 36492393509 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v46-voice-image-scan --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 3 ]] || {
  echo 'v46 release input artifact members differ' >&2
  exit 1
}
echo 'Pinned v46 release input artifacts downloaded for independent verification.'
