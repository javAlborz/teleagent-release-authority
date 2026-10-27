# Teleagent release authority

This public repository owns the independent protected-main signing workflow.
A versioned candidate is built twice on separate hosted runners, compared,
scanned and catalogued before a separate signer and consumer can approve its
exact bundle. Branch diagnostics never grant release approval. Hermes installation,
software outcome, handset acceptance and retention remain separate host decisions.
Use the matching versioned workflow and actual run evidence; this README never
establishes live host state.

The V85 candidate binds application main `6274bb9d23fa22de89011dc5059bd96e90359eea`.
It repairs repeated history readback, speaks common emoji descriptions, and
retains ambiguous caller additions for explicit continuation without duplicate
delivery. Controller and voice dependencies include verified body-parser 1.20.9
for GHSA-27r3-jxmh-p828. Hosted projections preserve nested dependencies and the
full dependency inventory remains checked against the application locks.
V85 retains V84's signed Alpine package inputs and scanner-completeness checks.
Preparing this candidate does not install it, release retention holds, or establish
handset acceptance; host capacity and coordinated deployment remain separate.

The predecessor V84 candidate binds application main `170a230cf1f11c58a4f4be8c4ac458dbaa8037e3`
and the six authenticated Alpine updates in `inputs/teleagent/runtime-apk-v84.json`.
Its first unsigned image is superseded: a nominal zero-finding scan omitted
CVE-2026-107891 details. The replacement verifies the corrected package inventory
and refuses unreviewed scanner warnings, including missing vulnerability details.
Only two exact non-failure warnings are allowed: missing Alpine EOL metadata and
vendor severity selection. The diagnostic log is hashed into the scan check and
revalidated by bundle assembly and the protected release decision.

The [release policy](POLICY.md) defines required evidence. Earlier observations
below are historical bootstrap records, not current release or deployment status.

## Historical September bootstrap observations

This public repository is the selected home for independent Teleagent release
verification and signing. **At this historical stage, release authority was not operational.** Hosted
diagnostics have independently rebuilt and compared unsigned native
dependencies, a voice image, and a complete release bundle. A separate scan
reported no vulnerabilities in the fixed unsigned voice image with a fresh
database at scan time. Separate signer and consuming-verifier diagnostics proved
GitHub OIDC attestation plumbing for the image and bundle. A private offline
voice-image build also passed on a disposable hosted runner; a separate job
rehash-verified that its image manifest, config, and all nine layers match the
scanned public image. These results are evidence for review, not acceptance of
the inputs, scanner policy, signer identity, release decision, or host runtime.
All retained artifacts are short-lived diagnostics. Nothing in this repository
currently authorizes a release or phone deployment.

The current Codex-only app candidate is
`5c0bc437ec1731bad1e8c6c348d7c72cd2b7cbfb`. Fresh private and public
voice-image builds matched across their complete image subjects; a current
scan reported zero findings; two SBOMs and two complete unsigned release
bundles matched. Separate diagnostic signer/consumer jobs passed for the image
and bundle, and a disposable host fixture accepted the exact bundle after the
independent controller-unit pin was refreshed. The bundle SHA-256 is
`35891889bd46058884f748a0901f9bba0cd593f7bc217dbfbbaf95ff49bc127b`.
These checks still report `releaseApproved=false`; the authority does not
publish a deployable release or install anything on Hermes.

The current infrastructure source integrated the dormant recovery start fence
at `d124326843047afc656b3df49e94eab661bfcf7e`. A new independent
host-contract diagnostic on the unchanged unsigned bundle passed in
[run 35997927052](https://github.com/javAlborz/teleagent-release-authority/actions/runs/35997927052),
using the recovery-fenced verifier policy SHA-256
`a9b235ee3e45884d36a1bf4f9d0f292f65ad4bad6a04add2d0d25ee9588a6807`.
Its approval and runtime gate were synthetic fixtures; no shared-host release
decision or installation followed.

The initial [release policy](POLICY.md) is a review draft. The public `main`
branch requires a pull request, including for administrators, and has linear
history; force pushes and deletion are disabled. This is a solo-owner
repository, so it requires zero approving reviews and does not require
last-push approval. Independent release evidence must come from separate
hosted builds, comparison and signing controls, not a nonexistent second
maintainer. A future implementation must verify these repository settings at
release time rather than treating this text as evidence that they remain in
force.
