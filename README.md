# SIWC Isolated Broker

A small Rust project for using [Sign in with ChatGPT plan sharing](https://developers.openai.com/siwc/token-sharing-open-source) from an isolated, self-hosted agent system. Its intended boundary is simple: the process that holds OAuth credentials is separate from every process that runs untrusted shell commands or code.

## Status

**Prototype only; do not use with real credentials yet.** The Rust core implements first-time and returning browser authorization, signed account validation, a protected token store, guarded refresh, one-use signed lane grants, durable quota/revocation, and a fixed Responses request route. Two Unix sockets expose separate controller grant/revocation and agent inference surfaces. They check peer UIDs, directory ownership, group permissions, and the agent bearer capability. A fake completed inference turn, route separation, and revocation pass through the sockets. An experimental `siwc-serve` binary starts this service. A separate `siwc-agent-bridge` binary exposes only the Responses route on agent-local loopback HTTP, replacing Codex's placeholder authorization header with a revocable lane capability before forwarding to the broker socket. Codex CLI 0.163.0 completed a synthetic turn through this bridge and a fake Unix-socket broker. All OAuth and model transports have used only synthetic local services.

The private campaign controller, its approval state, target source, research traces, and reports are not part of this repository.

## Intended trust boundary

```text
Codex in agent UID ── loopback HTTP ──> bridge holding scoped capability ──> agent Unix socket
trusted controller UID ── signed lane authority ──> admin Unix socket
                                      broker UID (distinct from both)
                                      ├─ private 0700 SIWC credential store
                                      ├─ durable grant ledger and refresh owner
                                      └─ HTTPS to POST /v1/responses
```

The broker verifies a short-lived lane grant, exact model and route, lease and request quota before dispatch. It does not return OAuth tokens or upstream headers to the agent. Upstream errors are quarantined; successful responses are rejected if they contain a full credential, a 12-byte opaque middle or suffix fragment, or a full base64/hex encoding. Arbitrary transformations and short masked fragments remain possible and need adversarial testing. Host egress policy must prevent an agent from bypassing the socket. A local HTTP proxy or a hidden prompt is not this boundary.

`siwc-login` and `siwc-serve` are feature-gated experimental binaries. `siwc-serve` requires a selected client ID and subject, the controller Ed25519 public key, distinct non-root broker/controller/agent UIDs, and two **different** broker-owned 0750 exchange directories grouped to their respective peers. Each socket is 0660 and also checks the connecting UID. The credential directory remains separate and 0700. The broker account must be able to set each socket's intended group. The library unit tests simulate these identities within one UID; they do not prove the deployment boundary.

`siwc-agent-bridge` is also feature-gated. It requires an agent-owned 0600 file containing only the short-lived lane capability, the agent socket path, campaign and lane IDs, and a loopback listen address. It never mounts the admin socket or credential directory, and it forwards no client-controlled host, URL, or authorization header. Other processes in the same agent network namespace can use the loopback listener and consume that lane's quota; target builds need their own isolated namespace. The broker remains the authority for model policy, budget, and revocation.

The bridge closes incomplete HTTP headers after five seconds and rejects an incomplete body after ten seconds, so a stalled local client cannot hold one of its 32 connection slots indefinitely. The broker applies the same five-second header deadline on both Unix sockets, plus a ten-second agent-body and five-second admin-body deadline. The bridge's broker Unix-socket connection and HTTP handshake each have a five-second deadline. A delayed upstream response can still occupy a slot until the bounded broker call finishes; the production streaming and workload-latency gate below remains open.

`sh scripts/probe_linux_uid_boundary.sh` runs an additional disposable Linux fixture with three real UIDs and a networkless test phase. It verifies cross-role socket denial, broker credential-directory denial, and peer UID enforcement even when a test root process can traverse both exchange directories. It uses synthetic tokens and cleans its build cache by default. Passing the fixture does not establish cloud namespace isolation or account eligibility.

With Codex CLI installed, `python3 scripts/probe_codex_bridge.py` exercises a synthetic Codex turn through the new bridge and a fake Unix-socket broker under a clean temporary Codex home. It uses no ChatGPT credential. The fake broker verifies the exact scoped capability, campaign, lane, and Responses request shape.

The experimental VM handoff now has `siwc-login export-vm` and `import-vm`. Export writes one disposable `0600` credential copy into a broker-owned `0700` staging directory; it never prints tokens. The operator transfers that file over SSH into a broker-owned `0700` staging directory on the VM. The VM must create and retain its own host ID first (`siwc-login list` does this). Import fetches the fixed issuer's JWKS, verifies the saved ID token's signature, client, and subject, binds the record to the VM host ID, refuses to overwrite an existing client, and removes the VM staging copy after durable save. The operator must remove the laptop export after confirmed transfer. Both commands must run only under the respective trusted broker UID, with staging paths outside every agent and build mount. This is a synthetic-tested transfer primitive, not a live-account deployment approval. OpenAI currently does not offer host-specific usage attribution or revocation for transferred sessions; use the broker's own lane revocation and account-level ChatGPT controls.

## Next gates before a live login

1. Deploy and test the feature-gated login and VM handoff commands under dedicated broker OS identities, with a human-operated browser, SSH transfer, and protected credential and staging directories outside all agent mounts. Validate trusted issuer JWKS rotation. Returning authorization omits `id_token_hint`, so the user sees the browser account selector; the signed replacement identity is checked against the selected local record. The bound loopback listener, fixed token/JWKS transport, signed ID-token verifier, and VM handoff have only fake-authority coverage.
2. Verify refresh and restart behavior against an eligible real account under a dedicated broker OS identity. The owner-only atomic store, single refresh owner, and uncertain-outcome marker are tested with synthetic records.
3. Deploy the two Unix socket surfaces and the Codex bridge under separate live OS identities, including denied cross-role access and inaccessible credential paths. Deliver close/revocation events reliably and verify host/container egress policy. The synthetic three-UID Linux fixture passes, but the actual cloud layout remains untested.
4. Replace whole-response buffering with a safe incremental streaming design or demonstrate that its latency and bounded memory meet the Codex workload. Test transformed credential reflections and errors without exposing upstream bodies. Keep agent, broker, and target-build process and mount namespaces separate.
5. Run a harmless authenticated turn, restart/resume, and adversarial shell inspection in the isolated environment. The synthetic CLI probe establishes adapter compatibility, not plan entitlement. A model catalog is not proof of entitlement; a completed authenticated inference turn is.

The [OpenAI sign-in guide](https://developers.openai.com/siwc/token-sharing-open-source/sign-in) defines authorization and ID-token checks. [Self-hosted VMs](https://developers.openai.com/siwc/token-sharing-open-source/self-hosted-vms) need their own stable host ID and protected credentials. The [preview limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations) define the Responses constraints this project will enforce. OpenAI plan access and limits remain subject to account and workspace eligibility.

## Development

```sh
cargo fmt --all --check
cargo test --locked
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
```

Security issues: see [SECURITY.md](SECURITY.md). Licensed under MIT.
