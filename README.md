# Teleagent release authority

This public repository is the selected home for independent Teleagent release
verification and signing. **It is not operational.** A branch-only
diagnostic can attempt unsigned glibc and musl dependency builds in separate disposable
hosted volume. It discards its output. There is no release build, comparison,
attestation, signing, or deployment workflow here yet. Nothing in this
repository currently authorizes a release or a phone deployment.

The initial [release policy](POLICY.md) is a review draft. The public `main`
branch requires a pull request, including for administrators, and has linear
history; force pushes and deletion are disabled. This is a solo-owner
repository, so it requires zero approving reviews and does not require
last-push approval. Independent release evidence must come from separate
hosted builds, comparison and signing controls, not a nonexistent second
maintainer. A future implementation must verify these repository settings at
release time rather than treating this text as evidence that they remain in
force.
