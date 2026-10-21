#!/bin/sh
# Synthetic end-to-end Codex turn through the packaged bridge and a fake broker.
# No account credential, external egress, provider token, or paid resource.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
node_image='node:22-bookworm-slim@sha256:3ed98443660ff48413b5af19ecefce3b9d50845a901a43420d47cc63a9fddbe9'
agent_image=${SIWC_CODEX_IMAGE:-hunter-factory-codex:local}
bridge_image=${SIWC_SIDECAR_IMAGE:-siwc-isolated-broker:local}
docker image inspect "$agent_image" "$bridge_image" >/dev/null 2>&1 || {
  echo 'build the local pinned Codex and packaged broker images first' >&2
  exit 1
}
nonce=$(python3 -c 'import uuid; print(uuid.uuid4().hex[:12])')
agent="siwc-codex-$nonce"
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

docker run -d --name "$agent" --network none --user 29010:29010 \
  --cap-drop ALL --security-opt no-new-privileges --read-only \
  --pids-limit 128 --memory 1g --cpus 2 \
  --tmpfs /root/.codex:uid=29010,gid=29010,mode=0700 \
  --tmpfs /tmp:uid=29010,gid=29010,mode=1777 \
  "$agent_image" sleep infinity >/dev/null
docker run -d --name "$sidecar" --pull never --network "container:$agent" \
  --user 29003:29003 --cap-drop ALL --security-opt no-new-privileges \
  --read-only --pids-limit 64 --memory 256m --cpus 1 \
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
test "$(docker inspect "$agent" --format '{{.HostConfig.ReadonlyRootfs}}')" = true
test "$(docker inspect "$sidecar" --format '{{.HostConfig.ReadonlyRootfs}}')" = true
test "$(docker inspect "$agent" --format '{{.Config.User}}')" = 29010:29010
test "$(docker inspect "$sidecar" --format '{{.Config.User}}')" = 29003:29003
if docker exec "$agent" test -e /exchange/agent.sock || docker exec "$agent" test -e /cap/capability; then
  echo 'agent can see broker exchange or lane capability' >&2
  exit 1
fi
docker exec "$agent" node -e '
  fetch("http://1.1.1.1/", {signal: AbortSignal.timeout(1500)})
    .then(() => process.exit(1), () => process.exit(0));
' || {
  echo 'agent unexpectedly reached an external network address' >&2
  exit 1
}

output=$(docker exec -e FACTORY_PLACEHOLDER_TOKEN=not-a-service-credential \
  -e HTTP_PROXY=http://127.0.0.1:1 -e HTTPS_PROXY=http://127.0.0.1:1 \
  -e ALL_PROXY=http://127.0.0.1:1 -e NO_PROXY=127.0.0.1,localhost \
  "$agent" codex exec --skip-git-repo-check --ignore-user-config --ephemeral \
  --sandbox read-only -C /workspace -m gpt-6-sol \
  -c 'model_provider="fixture"' \
  -c 'model_providers.fixture.name="Fixture"' \
  -c 'model_providers.fixture.base_url="http://127.0.0.1:18080/v1"' \
  -c 'model_providers.fixture.env_key="FACTORY_PLACEHOLDER_TOKEN"' \
  -c 'model_providers.fixture.wire_api="responses"' \
  -c 'model_providers.fixture.requires_openai_auth=false' \
  -c 'model_providers.fixture.supports_websockets=false' \
  'Reply with ok' 2>&1) || {
    printf '%s\n' "$output" | tail -40 >&2
    docker logs "$broker" 2>&1 | tail -20 >&2 || :
    docker logs "$sidecar" 2>&1 | tail -20 >&2 || :
    echo 'Codex did not complete the synthetic model turn' >&2
    exit 1
  }
printf '%s\n' "$output" | grep -q 'synthetic packaged bridge works' || {
  printf '%s\n' "$output" | tail -40 >&2
  echo 'Codex output did not contain the fake broker response' >&2
  exit 1
}
if printf '%s\n' "$output" | grep -q 'CQkJCQkJCQkJ'; then
  echo 'synthetic lane capability appeared in Codex output' >&2
  exit 1
fi
if docker exec "$agent" test -e /root/.codex/auth.json; then
  echo 'agent unexpectedly has an auth file' >&2
  exit 1
fi
echo 'networkless Codex completed a synthetic turn through the packaged bridge and fake broker'
