# Teleagent release policy

Status: **the first accepted release was superseded before Hermes selection;
the corrected candidate awaits a new protected-main decision**.

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

## Current release state

Protected-main run `36033577203` signed and independently consumed the first
exact release. Before Hermes selection, host integration found that its app
aggregate parsed a version 1 boot gate while the host verifier emits version
3. That artifact is staged but unselected and cannot complete the disabled
installation. The application fix is revision
`fd254f37a3017ad3475449987197706bbdbe7be7`.

The corrected candidate has two fresh, separate hosted voice image builds with
identical complete archives and image blobs, two fresh matching complete
release builds, a matching normalized SBOM, and a fresh zero-finding scan.
The older private offline voice build covered the previous app revision; its
expired pinned database prevented a new private diagnostic before execution.
The current decision relies on the two fresh hosted image and complete release
replicas. It makes no claim that the corrected image was compared to a new
private offline build. Protected-main signing, independent consumption, Hermes
approval pinning, disabled installation and live phone acceptance are still
required. The live phone remains locked until those gates pass.

## Current candidate selection, September 24

The corrected candidate is application revision
`fd254f37a3017ad3475449987197706bbdbe7be7` and complete bundle
SHA-256 `fcbc477da5fc456e43f89a92192de414436a394833221fbcd03c85d28af23257`.
The authority selects the exact checked-in `apk.json`, `engine.json`,
`indexes.json`, patched source-pair, and `tools.json` input manifests by full
SHA-256. Their canonical selection digest remains
`bb2a08960b9ef3b6279920a083eea4ba1fc45fe7c9a2e5713bbe12028f3caa59`.
The older `trivy.json` is excluded because its database expired. The current
scan is bound separately to run `36041325195`, its exact report and metadata,
and its 2026-09-25 13:23:01 UTC database expiry.

Hosted run `36041611475` compared the two corrected image archives and every
image blob. Run `36041801158` compared the two complete release bundles,
including their bound summaries. The decision source checks exact successful
hosted run IDs, revisions, workflow paths, events and first attempts before
fetching artifacts. A successful diagnostic run does not itself grant release
approval.

For this single-user release, the owner policy selects the digest-pinned
BuildKit asset from the upstream GitHub release and the fresh Trivy database
from its official container repository as roots. Their acquisition manifests
report `signatureVerified=false`; this decision makes transport/origin and
full digest the trust boundary and does not claim upstream signature
verification. The APK indexes and packages have separately verified Alpine
signatures. The corrected bundle still needs the protected-main signer,
independent consuming verifier, and updated Hermes host profile before
installation.

## Solo-owner source governance

The three repositories currently have one collaborator, `javAlborz`. The
authority `main` branch still requires a pull request, applies its protection
to administrators, requires linear history, and forbids force pushes and
deletion. It requires zero approving reviews and does not require approval
of the last push. A second human maintainer is not a prerequisite for a
solo-owner project. This source-governance setting grants no signing or
deployment authority: the two fresh isolated builds, exact comparison,
separate signer and consuming verifier above remain mandatory.
