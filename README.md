# Teleagent release authority

This public repository is the selected home for independent Teleagent release
verification and signing. **Release authority is not operational.** A branch-only
diagnostic builds unsigned glibc and musl dependencies in separate disposable
hosted volumes. A manual run starts two fresh jobs per target and compares their
bounded dependency observations after owned cleanup. The default retains only
those JSON observations for one day and discards compiled outputs. An explicit
experimental input also retains bounded unsigned dependency tars for one day
and reconstructs their subjects in a separate comparison job. These are
intermediate candidates, not release images or bundles. A separate three-job
fixture signs and verifies only fixed harmless text to exercise GitHub's
attestation plumbing. There is no release artifact, image comparison, release
attestation, release signing or deployment workflow here yet.
Nothing in this repository currently authorizes a release or phone deployment.

The initial [release policy](POLICY.md) is a review draft. The public `main`
branch requires a pull request, including for administrators, and has linear
history; force pushes and deletion are disabled. This is a solo-owner
repository, so it requires zero approving reviews and does not require
last-push approval. Independent release evidence must come from separate
hosted builds, comparison and signing controls, not a nonexistent second
maintainer. A future implementation must verify these repository settings at
release time rather than treating this text as evidence that they remain in
force.
