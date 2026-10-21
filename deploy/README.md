# Experimental broker image

`Dockerfile` packages the three feature-gated Rust binaries with pinned build and runtime bases. It contains no SIWC credentials, local Codex authentication, account ID, or lane capability. Build it only from a clean checkout and deploy by registry digest after recording the resulting architecture and binary hashes.

The [SSH browser sign-in runbook](SSH-LOGIN.md) uses a fixed loopback callback port on the trusted VM, forwarded from Rahul's browser over SSH. It keeps the exchange and protected credential store on that VM. The fixed-port CLI path is tested locally; actual VM sign-in remains unverified.

```sh
docker build --pull=false -f deploy/Dockerfile -t siwc-isolated-broker:local .
docker image inspect siwc-isolated-broker:local --format '{{.Id}} {{.Architecture}} {{.Config.User}}'
docker run --rm --network none siwc-isolated-broker:local /usr/local/bin/siwc-serve --help
docker run --rm --network none --user 29003:29003 siwc-isolated-broker:local /usr/local/bin/siwc-agent-bridge --help
```

The trusted broker service runs as UID 29001 with a broker-owned 0700 credential volume and distinct broker-owned agent/admin socket exchanges. The networkless agent never mounts those paths. The bridge sidecar runs as UID 29003, joins only its agent container's loopback network namespace, and mounts the broker agent exchange plus one short-lived lane capability. Only the broker can reach OpenAI. `siwc-login` is for human enrollment and VM import under the trusted broker identity; a containerized browser callback on Docker Desktop has not been verified, so do not treat this image as a completed sign-in flow.

`sh scripts/probe_sidecar_namespace.sh` exercises this packaged binary with a fake broker. It asserts the agent has no mounts or direct egress, while the sidecar has exactly the two read-only mounts and a read-only root filesystem. `sh scripts/probe_packaged_codex_turn.sh` then runs Codex CLI 0.163.0 in the locked agent image, with no account credential, no network interface, no broker mount, and no lane capability. The real CLI completes one fake Responses turn through the loopback bridge and fake Unix-socket broker. Set `SIWC_CODEX_IMAGE` and `SIWC_SIDECAR_IMAGE` to repeat the probe with AMD64 images. These probes use local image tags; production must use published digests.

This is packaging for an experimental service. Complete real-account entitlement/refresh, Linux host ownership and socket boundary, external egress policy, and a harmless live model turn before enabling a campaign.

Local ARM64 packaging receipt, 2026-10-21: `sha256:876cb356aeb279ea3bc2cb18304fc5ea1d83971aad07f054ec89be4052861d53`, `Config.User=29001:29001`. The runtime image copies the CA bundle from the pinned build image and performs no live package install. All three binaries returned their expected `--help` output in networkless, read-only containers; the bridge command was also exercised under UID/GID 29003. This image ID is a local build artifact, not a published registry digest or credentialed integration test.

Local AMD64 packaging receipt, 2026-10-21: `sha256:6b3df6ccbd2b2f22ba5c90a05f92fcd5094dba7d49ea9aebbf33d8d3a05328a1`, `Config.User=29001:29001`. All three binaries returned `--help` in networkless, read-only emulated AMD64 containers; the bridge also completed the synthetic Codex turn with the AMD64 agent image. This remains a local build artifact, not a published registry digest or a real-account test.

The [native Ubuntu Linux boundary run](https://github.com/saxenism/siwc-isolated-broker/actions/runs/39581989130) passed on 2026-10-21: three distinct UIDs, the broker socket boundary, a fresh packaged AMD64 image build, and the networkless sidecar probe. It used no account credential. This establishes the synthetic bridge topology on a native Linux Docker host; it does not test a production Hetzner VM, user namespace mapping, live OAuth, or subscription entitlement.
