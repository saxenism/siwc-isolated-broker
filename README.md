# SIWC Isolated Broker

A small Rust project for using [Sign in with ChatGPT plan sharing](https://developers.openai.com/siwc/token-sharing-open-source) from an isolated, self-hosted agent system. Its intended boundary is simple: the process that holds OAuth credentials is separate from every process that runs untrusted shell commands or code.

## Status

**Prototype only; do not use with real credentials yet.** This milestone builds and tests first-time and returning authorization, a bound loopback callback listener, fixed-endpoint code exchange and refresh, issuer JWKS retrieval, signed ID-token validation, plan permission and account binding, and a narrow Responses request policy. A Unix-only, owner-only store atomically saves validated token records, rejects account switches on replacement, and holds an exclusive broker process lock. Refresh rotation uses an in-process gate and a durable uncertain-outcome marker. The fixed Responses transport verifies the request and buffers a bounded, completed SSE response while suppressing upstream error bodies and exact credential reflection. All transports have been exercised only against fake local services. A feature-gated `siwc-login` command prints a one-time browser URL, but has not been run with a real account. There is no serving socket or lane grant enforcement.

The private campaign controller, its approval state, target source, research traces, and reports are not part of this repository.

## Intended trust boundary

```text
untrusted agent container ── scoped lane capability ──> broker Unix socket
                                                   trusted broker process
                                                   ├─ protected SIWC credentials
                                                   ├─ rotating refresh owner
                                                   └─ HTTPS to POST /v1/responses
```

The broker must verify a short-lived lane grant, exact model and route, lease and request quota before dispatch. It must never return OAuth tokens, upstream headers, or credential-bearing error bodies to the agent. Host egress policy must prevent an agent from bypassing the socket. A local HTTP proxy or a hidden prompt is not this boundary.

## Next gates before a live login

1. Deploy and test the feature-gated login command under a dedicated broker OS identity, with a human-operated browser and protected credential directory outside all agent mounts. Add a saved-account picker and validate trusted issuer JWKS rotation. Returning authorization omits `id_token_hint`, so the user sees the browser account selector; the signed replacement identity is checked against the selected local record. The bound loopback listener, fixed token/JWKS transport, and signed ID-token verifier have only fake-authority coverage.
2. Verify refresh and restart behavior against an eligible real account under a dedicated broker OS identity. The owner-only atomic store, single refresh owner, and uncertain-outcome marker are tested with synthetic records.
3. Serve a Unix socket with peer authentication and controller-signed, revocable lane grants. Atomically reserve quota before every Responses call. Permit only `POST /v1/responses` for one approved model and its documented request shape.
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
