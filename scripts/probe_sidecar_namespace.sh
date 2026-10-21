#!/bin/sh
# Disposable Linux proof that a networkless agent can reach a broker only
# through a bridge sidecar sharing its loopback namespace. Synthetic token only.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
node_image='node:22-bookworm-slim@sha256:3ed98443660ff48413b5af19ecefce3b9d50845a901a43420d47cc63a9fddbe9'
bridge_image=${SIWC_SIDECAR_IMAGE:-siwc-isolated-broker:local}
docker image inspect "$bridge_image" >/dev/null 2>&1 || {
  echo "build the packaged bridge image first: docker build -f deploy/Dockerfile -t $bridge_image ." >&2
  exit 1
}
nonce=$(python3 -c 'import uuid; print(uuid.uuid4().hex[:12])')
agent="siwc-agent-$nonce"
sidecar="siwc-bridge-$nonce"
broker="siwc-broker-$nonce"
exchange="siwc-exchange-$nonce"
capability="siwc-capability-$nonce"
cleanup() {
  docker rm -f "$sidecar" "$agent" "$broker" >/dev/null 2>&1 || :
  docker volume rm "$exchange" "$capability" >/dev/null 2>&1 || :
}
trap cleanup EXIT INT TERM

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
docker run -d --name "$sidecar" --pull never --network "container:$agent" --user 29003:29003 \
  --cap-drop ALL --security-opt no-new-privileges \
  --read-only \
  --mount "type=volume,source=$exchange,target=/exchange,readonly" \
  --mount "type=volume,source=$capability,target=/cap,readonly" \
  "$bridge_image" /usr/local/bin/siwc-agent-bridge \
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
test "$(docker inspect "$sidecar" --format '{{len .Mounts}}')" = 2
test "$(docker inspect "$sidecar" --format '{{.HostConfig.ReadonlyRootfs}}')" = true
test "$(docker inspect "$sidecar" --format '{{.Config.User}}')" = 29003:29003

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
    body: JSON.stringify({model: 'gpt-6-sol', store: false, stream: true, input: []}),
  });
  assert.equal(result.status, 200);
  assert.match(await result.text(), /response.completed/);
  await assert.rejects(fetch('http://1.1.1.1/', {signal: AbortSignal.timeout(1500)}));
  console.log('networkless agent reached only its scoped bridge');
})().catch(error => { console.error(error); process.exitCode = 1; });
JS
