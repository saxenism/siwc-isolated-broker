# SIWC Isolated Broker

A small Rust project for using [Sign in with ChatGPT plan sharing](https://developers.openai.com/siwc/token-sharing-open-source) from an isolated, self-hosted agent system. Its intended boundary is simple: the process that holds OAuth credentials is separate from every process that runs untrusted shell commands or code.

## Status

**Prototype only; do not use with real credentials yet.** The Rust core implements first-time and returning browser authorization, signed account validation, a protected token store, guarded refresh, one-use signed lane grants, durable quota/revocation, and a fixed Responses request route. Two Unix sockets expose separate controller grant/revocation and agent inference surfaces. They check peer UIDs, directory ownership, group permissions, and the agent bearer capability. A fake completed inference turn, route separation, and revocation pass through the sockets. An experimental `siwc-serve` binary starts this service, but it has not been run under three actual OS identities or with a live account. All OAuth and model transports have used only synthetic local services.

The private campaign controller, its approval state, target source, research traces, and reports are not part of this repository.

## Intended trust boundary

```text
untrusted agent UID ── scoped capability ──> agent Unix socket
trusted controller UID ── signed lane authority ──> admin Unix socket
                                      broker UID (distinct from both)
                                      ├─ private 0700 SIWC credential store
                                      ├─ durable grant ledger and refresh owner
                                      └─ HTTPS to POST /v1/responses
```

The broker verifies a short-lived lane grant, exact model and route, lease and request quota before dispatch. It does not return OAuth tokens or upstream headers to the agent. Upstream errors and exact credential reflections are quarantined; transformed reflections still need adversarial testing. Host egress policy must prevent an agent from bypassing the socket. A local HTTP proxy or a hidden prompt is not this boundary.

`siwc-login` and `siwc-serve` are feature-gated experimental binaries. `siwc-serve` requires a selected client ID and subject, the controller Ed25519 public key, distinct non-root broker/controller/agent UIDs, and two **different** broker-owned 0750 exchange directories grouped to their respective peers. Each socket is 0660 and also checks the connecting UID. The credential directory remains separate and 0700. The broker account must be able to set each socket's intended group. The library unit tests simulate these identities within one UID; they do not prove the deployment boundary.

## Next gates before a live login

1. Deploy and test the feature-gated login command under a dedicated broker OS identity, with a human-operated browser and protected credential directory outside all agent mounts. Validate trusted issuer JWKS rotation. Returning authorization omits `id_token_hint`, so the user sees the browser account selector; the signed replacement identity is checked against the selected local record. The bound loopback listener, fixed token/JWKS transport, and signed ID-token verifier have only fake-authority coverage.
2. Verify refresh and restart behavior against an eligible real account under a dedicated broker OS identity. The owner-only atomic store, single refresh owner, and uncertain-outcome marker are tested with synthetic records.
3. Prove the two Unix socket surfaces under separate live OS identities, including denied cross-role access and inaccessible credential paths. Deliver close/revocation events reliably and verify host/container egress policy. The socket and ledger currently pass synthetic unit tests only.
4. Replace whole-response buffering with a safe incremental streaming design or demonstrate that its latency and bounded memory meet the Codex workload. Test transformed credential reflections and errors without exposing upstream bodies. Keep agent, broker, and target-build process and mount namespaces separate.
5. Run a harmless authenticated turn, restart/resume, and adversarial shell inspection in the isolated environment. A model catalog is not proof of entitlement; a completed inference turn is.

The [OpenAI sign-in guide](https://developers.openai.com/siwc/token-sharing-open-source/sign-in) defines authorization and ID-token checks. [Self-hosted VMs](https://developers.openai.com/siwc/token-sharing-open-source/self-hosted-vms) need their own stable host ID and protected credentials. The [preview limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations) define the Responses constraints this project will enforce. OpenAI plan access and limits remain subject to account and workspace eligibility.

## Development

```sh
cargo fmt --all --check
cargo test --locked
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
```

Security issues: see [SECURITY.md](SECURITY.md). Licensed under MIT.
