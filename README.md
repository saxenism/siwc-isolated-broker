# SIWC Isolated Broker

A small Rust project for using [Sign in with ChatGPT plan sharing](https://developers.openai.com/siwc/token-sharing-open-source) from an isolated, self-hosted agent system. Its intended boundary is simple: the process that holds OAuth credentials is separate from every process that runs untrusted shell commands or code.

## Status

**Protocol core only; do not use with real credentials yet.** This milestone builds and tests a browser authorization URL, validates a bound callback, performs a fixed-endpoint token exchange, fetches issuer JWKS, verifies the signed ID token, checks plan permission and account binding, and rejects Responses requests outside the selected plan route. A Unix-only, owner-only store atomically saves validated token records and holds an exclusive broker process lock. Refresh rotation uses an in-process gate and a durable uncertain-outcome marker. Sign-in and refresh transports have been exercised only against a fake authority. There is no browser callback listener, serving socket, lane grant enforcement, or inference forwarding. No runnable live-login flow is enabled in this repository.

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

1. Implement local browser sign-in with a bound loopback listener, trusted issuer discovery and JWKS rotation, and the account picker. The fixed token/JWKS transport and signed ID-token verifier exist but have only fake-authority coverage.
2. Verify refresh and restart behavior against an eligible real account under a dedicated broker OS identity. The owner-only atomic store, single refresh owner, and uncertain-outcome marker are tested with synthetic records.
3. Serve a Unix socket with peer authentication and controller-signed, revocable lane grants. Permit only `POST /v1/responses` for one approved model and its documented request shape.
4. Validate upstream streaming completion and quarantine credential reflections without leaking response bodies, while measuring memory and latency. Keep agent, broker, and target-build process and mount namespaces separate.
5. Run a harmless authenticated turn, restart/resume, and adversarial shell inspection in the isolated environment. A model catalog is not proof of entitlement; a completed inference turn is.

The [OpenAI sign-in guide](https://developers.openai.com/siwc/token-sharing-open-source/sign-in) defines authorization and ID-token checks. [Self-hosted VMs](https://developers.openai.com/siwc/token-sharing-open-source/self-hosted-vms) need their own stable host ID and protected credentials. The [preview limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations) define the Responses constraints this project will enforce. OpenAI plan access and limits remain subject to account and workspace eligibility.

## Development

```sh
cargo fmt --all --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Security issues: see [SECURITY.md](SECURITY.md). Licensed under MIT.
