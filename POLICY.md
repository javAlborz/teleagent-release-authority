# Teleagent release policy candidate

Status: **draft; no accepted signer or promotable release**.

## Repository identities

| Role | Repository | GitHub repository ID | Visibility |
| --- | --- | ---: | --- |
| Application source | `javAlborz/teleagent` | `1205004484` | public |
| Infrastructure source | `javAlborz/homelab-infrastructure` | `1080013406` | private |
| Independent authority | `javAlborz/teleagent-release-authority` | `1383172221` | public |

These IDs were observed from GitHub's repository API on 2026-09-23. A future
verifier must compare them to current authenticated metadata and bind an exact
   workflow path, revision and run identity. A repository name by itself is not
   sufficient. The temporary read-only deploy key in the branch-restricted
   `teleagent-private-source-read` Actions environment permits this authority
   workflow to read the private infrastructure repository. Its sparse checkout
   reduces copied content but the key can read the whole repository. Run
   `35900580601` proved a pinned read-only checkout and five file hashes on a
   public hosted runner without executing source. This does not admit that
   source as a release or authorize a build. Revoke the key and environment
   secret after the reviewed build path no longer needs them.

## Required evidence before signing

1. An owner-selected, machine-verified source and input manifest binds the exact application and
   infrastructure commits, offline material and engine digests, payload source
   closure, base-image manifests, epoch, and build policy revision. Refresh
   time-sensitive scanner data and independently accept signatures and roots.
2. Two fresh, isolated GitHub-hosted build jobs independently construct the
   same unsigned release from the same admitted inputs. Each job proves its
   namespace, network, cgroup, filesystem, storage quota, process-lifetime and
   cleanup boundaries before acquired code runs. A persistent private runner
   does not count as either independent job.
3. Compare the deterministic image, release manifest, bundle and dependency
   inventories byte for byte or by their exact bound digests. Keep variable
   receipts, logs and measured resource peaks separate from deterministic
   subjects. A mismatched or incomplete comparison refuses signing.
4. A separate signing job on a fresh hosted runner verifies both build
   receipts, accepted source/artifact subjects, repository and workflow
   identities, trusted roots and policy revision. It signs only the compared
   release digest. The application repository cannot approve or sign itself;
   no long-lived signing key is stored on Hermes or a persistent runner.
5. A consuming verifier checks the resulting signature and full identity
   policy before accepting any artifact. Publication or a signed predicate
   alone never authorizes installation. The Hermes shared-host profile,
   recovery controls, state migration, disabled install and attended handset
   acceptance remain separate gates.

## Current refusal state

No build, comparison, signing or deployment workflow or trusted signing root
is selected or installed here. The sole Actions environment secret is the
temporary private-infrastructure read key described above; there are no
signing keys, OIDC grants, release artifacts or promotion dispatches. The
source-only draft infrastructure PRs do not meet the build or signing
requirements above. Keep the live phone locked until an independently
verified release and installation satisfy every remaining gate.

## Solo-owner source governance

The three repositories currently have one collaborator, `javAlborz`. The
authority `main` branch still requires a pull request, applies its protection
to administrators, requires linear history, and forbids force pushes and
deletion. It requires zero approving reviews and does not require approval
of the last push. A second human maintainer is not a prerequisite for a
solo-owner project. This source-governance setting grants no signing or
deployment authority: the two fresh isolated builds, exact comparison,
separate signer and consuming verifier above remain mandatory.
