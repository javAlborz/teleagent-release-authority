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

while read -r run_id head expected_branch expected_path expected_event; do
  [[ -n $run_id ]] || continue
  response=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run_id" \
    --jq '[.status,.conclusion,.head_sha,.head_branch,.run_attempt,.repository.id,.path,.event] | @tsv')
  IFS=$'\t' read -r status conclusion observed branch attempt repository_id path event <<< "$response"
  [[ $status == completed && $conclusion == success && $observed == "$head" &&
     $branch == "$expected_branch" && $attempt == 1 &&
     $repository_id == 1383172221 && $path == "$expected_path" &&
     $event == "$expected_event" ]] || {
    echo "fixed release evidence run $run_id differs" >&2
    exit 1
  }
done <<'RUNS'
35935470213 197be7276c00fb9d1eb89b4739eec6dcec9e6b14 feat/hosted-capacity-probe-20260923 .github/workflows/teleagent-native-build-diagnostic.yml workflow_dispatch
36040835605 71ab465a43025af8266f9b00903c61cc3e0d9aba fix/teleagent-v3-gate-release .github/workflows/teleagent-voice-image-diagnostic.yml workflow_dispatch
36041234613 68e876d6589e543162123f48fac00286e8a13403 fix/teleagent-v3-gate-release .github/workflows/teleagent-voice-image-diagnostic.yml workflow_dispatch
36041611475 6333a7276eb3c57ac2b913b6b597befa81499ffa fix/teleagent-v3-gate-release .github/workflows/teleagent-hosted-voice-replica-comparison.yml push
36041367429 1841ff26a897e920fcd705ecb695845159ae885c fix/teleagent-v3-gate-release .github/workflows/teleagent-voice-sbom-diagnostic.yml workflow_dispatch
36041801158 7685f6b1589e8fa100c2517a3adc7f6b17a77ecb fix/teleagent-v3-gate-release .github/workflows/teleagent-release-bundle-diagnostic.yml workflow_dispatch
36041325195 1841ff26a897e920fcd705ecb695845159ae885c fix/teleagent-v3-gate-release .github/workflows/teleagent-voice-image-scan-diagnostic.yml push
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
gh run download 36041801158 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-release-bundle-1 --dir "$base/bundle-a"
gh run download 36041801158 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-release-bundle-2 --dir "$base/bundle-b"
gh run download 36040835605 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-voice-image-current-app-diagnostic --dir "$base/image"
gh run download 36041325195 --repo "$GITHUB_REPOSITORY" \
  --name unsigned-voice-image-current-app-scan-diagnostic --dir "$base/scan"

[[ $(find "$base/bundle-a" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/bundle-b" -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 &&
   $(find "$base/image" -mindepth 1 -maxdepth 1 -type f | wc -l) == 1 &&
   $(find "$base/scan" -mindepth 1 -maxdepth 1 -type f | wc -l) == 3 ]] || {
  echo 'release input artifact members differ' >&2
  exit 1
}
echo 'Pinned release input artifacts downloaded for independent verification.'
