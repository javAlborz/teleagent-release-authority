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
   time-sensitive scanner data. Record the selected upstream roots and exact
   digests; verify upstream signatures where available and explicitly record
   any digest-pinned origin accepted without an independently verified signature.
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

No accepted release decision, deployment workflow, or consuming host trust root
is installed here. Branch-only diagnostics have produced matching unsigned
native dependencies, voice images, and complete release bundles on fresh hosted
runners. A fresh diagnostic vulnerability scan and independent package inventory
cover the fixed public image. A private offline build produced a byte-identical
image subject under a different Docker export tag. Separate GitHub OIDC signer
and consuming-verifier jobs exercised the image and bundle, but their predicates
explicitly withhold release approval. Input and scanner policy acceptance,
release signing, host installation, and live phone acceptance remain open. The
temporary private-infrastructure read key described above is the sole Actions
environment secret; diagnostic OIDC grants do not convey release authority.
Keep the live phone locked until an independently verified release and
installation satisfy every remaining gate.

## Current candidate selection, September 24

The current candidate is application revision
`5c0bc437ec1731bad1e8c6c348d7c72cd2b7cbfb` and complete bundle
SHA-256 `35891889bd46058884f748a0901f9bba0cd593f7bc217dbfbbaf95ff49bc127b`.
The authority's current decision source selects the exact checked-in
`apk.json`, `engine.json`, `indexes.json`, patched source-pair, and `tools.json`
input manifests by full SHA-256; their canonical selection digest is
`bb2a08960b9ef3b6279920a083eea4ba1fc45fe7c9a2e5713bbe12028f3caa59`.
The older `trivy.json` is excluded from that build selection because its
database has expired. The current scan is bound separately to run
`36028598666`, its exact report and database metadata, and its
2026-09-25 13:23:01 UTC database expiry.

Successful hosted branch run `36032028804` compared both complete bundle
replicas, checked the release manifest and current scanner report, and
produced a decision with `scanApproved=false` and `releaseApproved=false`.
Its signing and consuming jobs were skipped. The source also checks eight
exact successful hosted run IDs, revisions, workflow paths, events and first
attempts before fetching artifacts. Those earlier jobs include isolated native
builds, public and private voice-image construction, image comparison, SBOM,
two independent bundle assemblies, and fresh scan. A successful run result
proves those diagnostic checks ran, but does not retroactively make their
diagnostic labels into approval.

For this single-user release, the owner policy selects the digest-pinned
BuildKit asset from the upstream GitHub release and the fresh Trivy database
from its pinned official container repository digest as roots. Their
acquisition manifests report `signatureVerified=false`; this decision makes
the transport/origin and full digest the trust boundary and does not claim
upstream signature verification. The APK indexes and packages have separately
verified Alpine signatures. The bundle still needs the protected-main signer,
independent consuming verifier, and Hermes host profile before installation.
The proposed v2 host approval carries the authority repository ID and main
revision, signed decision digest, selected input digest, and scan database
expiry alongside the exact bundle and release IDs. The Hermes host verifier
must pin this accepted authority decision and reject a copied or edited
approval before the release can be installed or started.

## Solo-owner source governance

The three repositories currently have one collaborator, `javAlborz`. The
authority `main` branch still requires a pull request, applies its protection
to administrators, requires linear history, and forbids force pushes and
deletion. It requires zero approving reviews and does not require approval
of the last push. A second human maintainer is not a prerequisite for a
solo-owner project. This source-governance setting grants no signing or
deployment authority: the two fresh isolated builds, exact comparison,
separate signer and consuming verifier above remain mandatory.
