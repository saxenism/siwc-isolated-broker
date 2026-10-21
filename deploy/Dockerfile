# Build the fixed experimental service binaries without any account data.
FROM docker.io/library/rust:1.96.1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release \
    --features experimental-login,experimental-serve,experimental-bridge \
    --bins

FROM docker.io/library/debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/target/release/siwc-login /usr/local/bin/siwc-login
COPY --from=build /src/target/release/siwc-serve /usr/local/bin/siwc-serve
COPY --from=build /src/target/release/siwc-agent-bridge /usr/local/bin/siwc-agent-bridge
USER 29001:29001
CMD ["/usr/local/bin/siwc-serve"]
