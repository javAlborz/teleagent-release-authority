# Teleagent release authority

This public repository is the selected home for independent Teleagent release
verification and signing. **Release authority is not operational.** Hosted
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

The initial [release policy](POLICY.md) is a review draft. The public `main`
branch requires a pull request, including for administrators, and has linear
history; force pushes and deletion are disabled. This is a solo-owner
repository, so it requires zero approving reviews and does not require
last-push approval. Independent release evidence must come from separate
hosted builds, comparison and signing controls, not a nonexistent second
maintainer. A future implementation must verify these repository settings at
release time rather than treating this text as evidence that they remain in
force.
