# Publishing a Kule release

Kule's first public version is planned as **v0.1.0**, an early single-host release.

## Release gates (all required before tagging and publication)

- [ ] Kule init and doctor pass test coverage and review.
- [ ] Built wheel installs into a clean virtual environment and its installed CLI passes first-run offline smoke tests (in addition to editable source tests).
- [ ] Install from a clean environment with a separate test OIDC client; verify the full OAuth login and client tool call.
- [ ] Verify wrong-group and anonymous denial, host execution disabled by default, audit, emergency stop, and persistent state across restart.
- [ ] Verify the refresh path beyond a token expiry without manual reconnect.
- [ ] Validate the Linux ARM64/AMD64 container image with its actual CLI and configuration; record the immutable image **index digest**.
- [ ] Document runtime dependencies and remove unrelated experimental integrations from the release artifact or clearly isolate them.
- [ ] Verify the Python package version is `0.1.0`, and README source-install instructions and release notes consistently identify the `v0.1.0` release (without implying PyPI publication).
- [ ] Verify the separate container artifact `ghcr.io/yesvus/kule:sha-<release-commit>` and record its immutable OCI index digest and supported architectures in the release notes.
- [ ] Complete code, security and CI reviews; retain a tested rollback path.

## Release procedure (after gates pass)

1. Open a reviewable PR that changes the package version from 0.1.0.dev0 to 0.1.0, drafts the release notes in `docs/releases/v0.1.0.md`, updates documentation, and records completed release evidence.
2. Require lint, Python 3.11/3.12/3.13/3.14/3.15 tests, and the multi-architecture container build on the release PR; merge after review.
3. Verify those same tests and the container build on the **landed commit on `main`**. Confirm `ghcr.io/yesvus/kule:sha-<release-commit>` was published by the main-branch workflow, inspect its ARM64/AMD64 platforms, and record the immutable OCI index digest. The SHA tag is the version's image reference; a `v0.1.0` container tag is not currently published. A passing PR head alone does not verify a squash/merge commit.
4. Before tagging, complete the fresh-install, OAuth refresh/denial, emergency-stop, and rollback gates using the exact landed artifact.
5. Tag the verified `main` commit `v0.1.0` and publish a GitHub Release using `docs/releases/v0.1.0.md`. Include the matching SHA image tag and pinned `ghcr.io/yesvus/kule@sha256:<index-digest>` reference, supported architectures, limitations, and evidence.
6. After publication, verify the GitHub Release points to the tested commit and that the immutable digest still resolves to both supported architectures.

Publishing a GitHub Release is distinct from publishing to PyPI or rolling out to a running Kubernetes cluster. Deployment promotion requires its own reviewed GitOps change. A version tag must not trigger an implicit production rollout.

The Hub–Agent–Protocol architecture is a future milestone and does not need to be complete to publish a clearly scoped single-host v0.1.0.
