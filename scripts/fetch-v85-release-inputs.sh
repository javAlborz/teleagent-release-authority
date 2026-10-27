#!/usr/bin/env bash
# Fetch only the exact hosted v85 release evidence for a protected decision.
set -euo pipefail

[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == javAlborz/teleagent-release-authority &&
   ${GITHUB_REPOSITORY_ID:-} == 1383172221 && -n ${GH_TOKEN:-} ]] || {
  echo 'v85 release inputs require the hosted authority workflow' >&2
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
    echo "fixed v85 release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 feat/hosted-capacity-probe-20260923 1 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
40518980758 234e1bc9e316f7f5993f78f1d53b39e379922cae fix/teleagent-v85-followups-authority-20261027 1 .github/workflows/teleagent-v85-hosted-voice-image.yml push
40519606599 9606a92f4dfa9ac5e09c73dc8a530fe8855963a0 fix/teleagent-v85-followups-authority-20261027 1 .github/workflows/teleagent-v85-hosted-voice-sbom.yml push
40519422756 14dbbd466818e984988e163468a3dba1bcd4d48b fix/teleagent-v85-followups-authority-20261027 1 .github/workflows/teleagent-v85-hosted-voice-scan.yml push
40520185621 18f6dca2ffcf8b7f3db3f0e22428d93d1ddf54d8 fix/teleagent-v85-followups-authority-20261027 1 .github/workflows/teleagent-v85-hosted-release-bundle.yml push
RUNS

base="$RUNNER_TEMP/teleagent-v85-release-inputs"
[[ ! -e $base && ! -L $base ]] || {
  echo 'v85 release input root already exists' >&2
  exit 1
}
mkdir -m 0700 -- "$base"
for name in bundle-a bundle-b image scan; do
  mkdir -m 0700 -- "$base/$name"
done
gh run download 40520185621 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v85-release-bundle-1 --dir "$base/bundle-a"
gh run download 40520185621 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v85-release-bundle-2 --dir "$base/bundle-b"
gh run download 40518980758 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v85-voice-image-2 --dir "$base/image"
gh run download 40519422756 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-v85-voice-image-scan --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 4 ]] || {
  echo 'v85 release input artifact members differ' >&2
  exit 1
}
echo 'Pinned v85 release input artifacts downloaded for independent verification.'
