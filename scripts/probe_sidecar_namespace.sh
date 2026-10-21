#!/bin/sh
# Disposable Linux proof that a networkless agent can reach a broker only
# through a bridge sidecar sharing its loopback namespace. Synthetic token only.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
rust_image='rust:1.96.1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663'
node_image='node:22-bookworm-slim@sha256:3ed98443660ff48413b5af19ecefce3b9d50845a901a43420d47cc63a9fddbe9'
nonce=$(python3 -c 'import uuid; print(uuid.uuid4().hex[:12])')
agent="siwc-agent-$nonce"
sidecar="siwc-bridge-$nonce"
broker="siwc-broker-$nonce"
exchange="siwc-exchange-$nonce"
capability="siwc-capability-$nonce"
if [ -n "${SIWC_SIDECAR_BUILD_DIR:-}" ]; then
  build_dir=$SIWC_SIDECAR_BUILD_DIR
  mkdir -p "$build_dir"
  remove_build=0
else
  build_dir=$(mktemp -d)
  remove_build=1
fi

cleanup() {
  docker rm -f "$sidecar" "$agent" "$broker" >/dev/null 2>&1 || :
  docker volume rm "$exchange" "$capability" >/dev/null 2>&1 || :
  if [ "$remove_build" -eq 1 ]; then
    docker run --rm --network none \
      --mount "type=bind,source=$build_dir,target=/out" \
      "$rust_image" find /out -mindepth 1 -delete >/dev/null 2>&1 || :
    rmdir "$build_dir" 2>/dev/null || :
  fi
}
trap cleanup EXIT INT TERM

if ! docker run --rm \
  --mount "type=bind,source=$repo_dir,target=/src,readonly" \
  --mount "type=bind,source=$build_dir,target=/out" \
  --env CARGO_TARGET_DIR=/out/target \
  --env CARGO_HOME=/out/cargo \
  --env CARGO_BUILD_JOBS=2 \
  --env CARGO_INCREMENTAL=0 \
  --env CARGO_PROFILE_DEV_DEBUG=0 \
  --workdir /src "$rust_image" \
  cargo build --locked --features experimental-bridge --bin siwc-agent-bridge \
  >"$build_dir/build.log" 2>&1; then
  tail -n 80 "$build_dir/build.log"
  exit 1
fi
bridge_binary="$build_dir/target/debug/siwc-agent-bridge"
test -x "$bridge_binary"

docker volume create "$exchange" >/dev/null
docker volume create "$capability" >/dev/null
docker run --rm --network none --user 0:0 \
  --mount "type=volume,source=$exchange,target=/exchange" \
  --mount "type=volume,source=$capability,target=/cap" \
  "$node_image" node -e '
    const fs = require("node:fs");
    fs.chownSync("/exchange", 29001, 29003);
    fs.chmodSync("/exchange", 0o750);
    fs.writeFileSync("/cap/capability", Buffer.alloc(32, 9).toString("base64url"));
    fs.chownSync("/cap", 29003, 29003);
    fs.chownSync("/cap/capability", 29003, 29003);
    fs.chmodSync("/cap", 0o700);
    fs.chmodSync("/cap/capability", 0o600);
  '

docker run -d --name "$broker" --network none --user 29001:29003 \
  --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=volume,source=$exchange,target=/exchange" \
  --mount "type=bind,source=$repo_dir/scripts/fake_broker_sidecar.js,target=/fake-broker.js,readonly" \
  "$node_image" node /fake-broker.js >/dev/null
ready=0
for _ in $(seq 1 50); do
  if docker exec "$broker" node -e "process.exit(require('node:fs').statSync('/exchange/agent.sock').isSocket() ? 0 : 1)" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 0.1
done
if [ "$ready" -ne 1 ]; then
  docker logs "$broker" || :
  echo 'fake broker did not create its Unix socket' >&2
  exit 1
fi

docker run -d --name "$agent" --network none --user 29003:29003 \
  --cap-drop ALL --security-opt no-new-privileges \
  "$node_image" sleep infinity >/dev/null
docker run -d --name "$sidecar" --network "container:$agent" --user 29003:29003 \
  --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=volume,source=$exchange,target=/exchange,readonly" \
  --mount "type=volume,source=$capability,target=/cap,readonly" \
  --mount "type=bind,source=$bridge_binary,target=/usr/local/bin/siwc-agent-bridge,readonly" \
  "$rust_image" /usr/local/bin/siwc-agent-bridge \
    --listen 127.0.0.1:18080 \
    --broker-socket /exchange/agent.sock \
    --capability-file /cap/capability \
    --campaign-id campaign-1 --lane-id lane-1 >/dev/null

ready=0
for _ in $(seq 1 50); do
  if docker logs "$sidecar" 2>&1 | grep -q 'serving loopback'; then
    ready=1
    break
  fi
  sleep 0.1
done
if [ "$ready" -ne 1 ]; then
  docker logs "$sidecar" || :
  echo 'bridge sidecar did not bind loopback' >&2
  exit 1
fi
agent_id=$(docker inspect "$agent" --format '{{.Id}}')
test "$(docker inspect "$sidecar" --format '{{.HostConfig.NetworkMode}}')" = "container:$agent_id"
test "$(docker inspect "$agent" --format '{{len .Mounts}}')" = 0

docker exec -i "$agent" node <<'JS'
const assert = require('node:assert/strict');
const fs = require('node:fs');
(async () => {
  assert.equal(fs.existsSync('/exchange/agent.sock'), false);
  assert.equal(fs.existsSync('/cap/capability'), false);
  const denied = await fetch('http://127.0.0.1:18080/v1/grants', {
    method: 'POST', headers: {'content-type': 'application/json'}, body: '{}',
  });
  assert.equal(denied.status, 403);
  const result = await fetch('http://127.0.0.1:18080/v1/responses', {
    method: 'POST', headers: {'content-type': 'application/json'},
    body: JSON.stringify({model: 'gpt-6-sol'}),
  });
  assert.equal(result.status, 200);
  assert.match(await result.text(), /response.completed/);
  await assert.rejects(fetch('http://1.1.1.1/', {signal: AbortSignal.timeout(1500)}));
  console.log('networkless agent reached only its scoped bridge');
})().catch(error => { console.error(error); process.exitCode = 1; });
JS
