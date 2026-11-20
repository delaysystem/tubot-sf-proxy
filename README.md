# Salesforce messaging proxy

`POST /api/v1/salesforce/proxyRegister` on New Panel provisions a unique SCRT base URL. It requires an active Salesforce Panel OAuth grant with `write` scope and an existing channel connection owned by that grant's team.

The JSON body contains `orgId`, `channelId`, `deploymentName`, `secureKeys` (one to three random strings of at least 32 characters), and `action`:

```json
{
  "name": "Tubot_Proxy_Send_Notification",
  "definitionName": "Tubot_Proxy_Echo",
  "inputMapping": {
    "definition": "definitionName",
    "recipients": "recipients",
    "parameters": "parameters"
  },
  "outputMapping": {"requestId": "requestId"}
}
```

Use the returned `baseUrl` in place of the SCRT origin. Every request must include `X-Tubot-Proxy-Key` with one of the supplied keys. Salesforce bearer tokens are still required by Salesforce. Keep proxy keys on the server; do not embed them in a public browser deployment.

The auth broker independently discovers the Flow action and checks its mapping, active channel, and published API deployment. Salesforce credentials remain inside `tubot-sf-auth`. Private service bindings expose a narrow messaging broker to this worker and registration management to Panel.

Each registration has its own Durable Object. Inbound text is encrypted with AES-GCM using tenant-registration-event associated data before forwarding. The worker returns SCRT's response status, body, and streams unchanged. Alarms submit echoes, query actual Salesforce send-request delivery, and retry broker failures. The durable event id makes a lost Flow response safe to retry. Uncertain SCRT outcomes are checked against the actual conversation before sending an echo. Text payloads are erased on completion or after the 24-hour retry deadline; status receipts expire after seven days. Terminal Salesforce delivery errors appear as `failed`; unresolved outcomes appear as `needs_attention`.

Only text messages up to 4096 characters are supported for echo. Unsupported inbound content receives `422`. Each registration allows 600 requests per minute and 1000 pending echo events. Keys are stored only as registration-salted SHA-256 digests.

`GET /api/v1/salesforce/proxies` lists registrations for the authenticated team. `GET /api/v1/salesforce/proxies/{id}` returns status counts and recent delivery receipts without message text or keys. `DELETE` on that route revokes the proxy and clears pending text. Re-register with new keys, update the server-side client, and revoke the old route to rotate keys.

## Setup and live verification

On `tubot-sf-app`'s `v2` branch:

```bash
bun scripts/setup-proxy-echo-live.ts "$SF_ORG" "$WEB_DEPLOYMENT"
bun scripts/verify-proxy-echo-live.ts "$SF_ORG" "$MESSAGING_END_USER_ID"
```

The setup command deploys the notification definition, Flow adapter, permissions, and renderers; activates the messaging component in real Salesforce Setup; configures and publishes the existing Web deployment; and independently retrieves its metadata. Playwright resolves from the sibling Panel project, or `PLAYWRIGHT_MODULE`. The broker sends typed `RichMessaging` parameters because Flow string assignments trim whitespace.

The org must already have its messaging channel/API deployment and a verified Panel connection. For a new messaging scratch org, run `tubot-sf-app/nu-message.sh` first, install the OAuth package dependency, and connect its channel through Panel's normal setup workflow.

From `test-client`, use a private JSON file containing a real issued Panel `access_token`:

```bash
bun scripts/test-proxy-echo-live.ts "$SF_ORG" "$PANEL_URL" "$PANEL_TOKEN_FILE" "$CHANNEL_NAME" "$API_DEPLOYMENT"
```

The test registers a real proxy, independently queries remote D1, sends through `MiawClient`, checks queue ownership and Salesforce's persisted exact text/delivery receipts, checks the real conversation transcript and proxied SSE stream, and tests missing keys, conflicting message IDs, and duplicate replay. An optional sixth argument accepts an existing private registration JSON with `id`, `baseUrl`, and `key`. The test leaves the registration available for inspection. Set `VERIFY_PROXY_RESTART=1` to redeploy the real proxy while an echo is pending, `VERIFY_PROXY_REVOKE=1` to revoke and independently verify the test registration, or `PROXY_ISOLATION_REGISTRATION_FILE` to check that another real registration cannot use its keys.

Deployment order is auth broker, proxy, then Panel. Apply `tubot-new-panel/migrations/0003_messaging_proxies.sql` through the Panel migration workflow. Configure `PROXY_ENCRYPTION_KEY` as a base64-encoded random 32-byte Worker secret before registering routes. Set `PROXY_PUBLIC_ORIGIN` to the deployed HTTPS origin. Production and staging have separate service bindings and Durable Object namespaces; configure a separate encryption secret in each.

```bash
bun run typecheck
bun run deploy
# staging only when its matching broker and Panel are deployed:
bun run deploy:staging
```
