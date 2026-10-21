# Browser sign-in to a trusted Linux broker through SSH

This is a deployment runbook, **not a completed login**. It applies only after a trusted broker VM, private SSH access, a published image digest, and the campaign cost approval exist. The broker image has not yet completed a live ChatGPT entitlement test.

The login process runs on the broker VM as UID/GID `29001`. Its callback listens on that VM's `127.0.0.1:48211`. An SSH local forward carries only the browser callback from Rahul's laptop to the VM; the code exchange and protected credential store stay on the VM. Do not copy a Codex `auth.json`, an access token, or a refresh token to an AoE worker, agent home, or chat.

1. On the trusted VM, prepare a broker-only directory. Run this under an administrator account before starting the broker. Do not mount the directory into any worker or build container:

   ```sh
   sudo install -d -o 29001 -g 29001 -m 0700 /var/lib/hunter-factory/broker-credentials
   ```

2. Stop the trusted broker service for enrollment. Its credential store uses an exclusive lock. Do this only when no lane needs the broker; restart the service after sign-in. In one laptop terminal, keep this SSH local forward open (replace the private VM host with the deployed address):

   ```sh
   ssh -o ExitOnForwardFailure=yes -N \
     -L 127.0.0.1:48211:127.0.0.1:48211 broker-vm
   ```

3. In a second SSH terminal on the VM, run the **digest-pinned** broker image under its separate UID. Replace `BROKER_IMAGE_BY_DIGEST` with the deployed image reference; never use a floating tag for account enrollment:

   ```sh
   docker run --rm --network host --read-only \
     --user 29001:29001 --cap-drop ALL --security-opt no-new-privileges \
     --pids-limit 64 --memory 256m \
     --tmpfs /tmp:rw,nosuid,nodev,size=16m \
     --mount type=bind,source=/var/lib/hunter-factory/broker-credentials,target=/broker/store \
     BROKER_IMAGE_BY_DIGEST /usr/local/bin/siwc-login \
       --store-dir /broker/store new --callback-port 48211
   ```

4. Open the `Continue with ChatGPT` URL displayed by that trusted SSH session in the laptop browser. The browser callback must return through the still-open SSH forward. The VM process should print the account subject, issued client ID, and whether the selected plan granted access. It must never print the tokens. Close the forward after success. Restart the broker service and make one harmless, explicitly approved live model turn before allowing a real lane.

If local port `48211` is already in use, choose another nonzero port in **both** commands. The callback is bound to loopback, the authorization attempt includes state and PKCE, and a second login cannot bind the same port. This SSH route has been unit-tested for the fixed callback binding, but a real SSH/browser flow on a deployed VM remains a release gate. Docker Desktop host networking on macOS is not evidence for Linux behavior.

Reauthorization uses `returning --client-id ... --subject ... --callback-port 48211` instead of `new`. The saved subject must match the newly selected signed identity. Do not run a concurrent broker instance against the same credential store.
