# Publishing a Kule release

Kule's first public version is planned as **v0.1.0**, an early single-host release.

## Required release gates

- [ ] Kule init and doctor pass test coverage and review.
- [ ] Install from a clean environment with a separate test OIDC client; verify the full OAuth login and client tool call.
- [ ] Verify wrong-group and anonymous denial, host execution disabled by default, audit, emergency stop, and persistent state across restart.
- [ ] Verify the refresh path beyond a token expiry without manual reconnect.
- [ ] Validate the Linux ARM64/AMD64 container image with its actual CLI and configuration; record the immutable image **index digest**.
- [ ] Document runtime dependencies and remove unrelated experimental integrations from the release artifact or clearly isolate them.
- [ ] Align Python package version, README install command, release notes, and container image tag.
- [ ] Complete code, security and CI reviews; retain a tested rollback path.

## Release procedure (after gates pass)

1. Open a reviewable PR that changes the package version from 0.1.0.dev0 to 0.1.0, drafts the release notes in `docs/releases/v0.1.0.md`, updates documentation, and records completed release evidence.
2. Require lint, Python 3.11/3.12/3.13/3.15 tests, and the multi-architecture container build on the release PR; merge after review.
3. Recheck those same tests and the container build on the **landed commit on `main`** before creating its `v0.1.0` tag. A green PR head alone does not verify a squash/merge commit.
4. Tag the verified `main` commit and create a GitHub Release using `docs/releases/v0.1.0.md`, including known limitations and verification notes.
5. Verify the published GHCR image digest and its supported architectures; link the immutable digest in the release notes.
6. Validate a clean installation against the released artifact, including authentication and rollback/recovery steps.

Publishing a GitHub Release is distinct from publishing to PyPI or rolling out to a running Kubernetes cluster. Deployment promotion requires its own reviewed GitOps change. A version tag must not trigger an implicit production rollout.

The Hub–Agent–Protocol architecture is a future milestone and does not need to be complete to publish a clearly scoped single-host v0.1.0.
