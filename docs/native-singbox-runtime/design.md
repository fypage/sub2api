# Native sing-box Runtime Design

Status: design in progress  
Base: Sub2API v0.1.155 (`41cec0db`)  
Branch: `feat/native-singbox-runtime`

## Goal

Add first-class Xray share-link and sing-box JSON proxy runtimes to Sub2API without a separately deployed bridge service. Preserve the existing `proxies` and `accounts.proxy_id` forwarding path so upstream merges remain tractable.

## Product observations

The reference UI exposes two creation modes:

- Standard creation: create one logical proxy runtime.
- Batch creation: ingest multiple nodes and create multiple runtimes.

Supported input protocols shown by the reference:

- Xray share link
- Sing-box JSON
- Existing HTTP, HTTPS, SOCKS5 and SOCKS5H remain unchanged.

### Xray share link

- Accept a single node share link in standard mode.
- Initial schemes: `vless://`, `vmess://`, `trojan://`, `ss://`.
- The share link is parsed by Sub2API, but the managed runtime uses sing-box.
- Never expose the raw link or embedded credentials in list APIs, logs or exports unless an explicit secret export operation is authorized.

### Sing-box JSON

Two input methods are required:

1. Subscription URL
2. Pasted configuration

Accepted pasted shapes:

- one outbound object;
- one endpoint object;
- an array of outbounds/endpoints;
- a complete sing-box configuration.

When a complete configuration or subscription contains multiple usable nodes, standard creation must parse first and show a second node-selection step. Batch creation may select multiple nodes and create multiple logical proxies.

Selectors, URL tests, DNS, direct, block and other non-egress objects are not importable nodes. References between outbounds/endpoints must be resolved or rejected with a precise validation error; silently dropping dependencies is not allowed.

## Logical proxy and runtime model

Keep the official `proxies` row as the object bound through `accounts.proxy_id`. Add a one-to-one optional native runtime record for advanced protocols.

Proposed `proxy_runtimes` fields:

- `id`
- `proxy_id` (unique FK to `proxies`, cascade delete)
- `engine` (`sing-box` initially)
- `source_type` (`xray_link`, `singbox_json`, `singbox_subscription`)
- `source_secret_encrypted`
- `normalized_outbound_encrypted`
- `node_fingerprint`
- `listen_host`
- `listen_port`
- `status` (`pending`, `starting`, `healthy`, `degraded`, `blocked`, `stopped`, `error`)
- `pid`
- `config_path`
- `last_error_code`
- `last_error_redacted`
- `restart_count`
- `auto_start`
- `last_started_at`
- `last_stopped_at`
- timestamps and soft-delete metadata

Subscription metadata should be separated so one subscription can produce many runtimes:

- source URL stored encrypted;
- refresh interval and conditional request metadata;
- last sync status/error;
- node fingerprint inventory;
- explicit policy for removed nodes (`keep`, `disable`, or `fallback`).

## Visibility and ownership

Reference behavior includes a checkbox to make a proxy available to all users. The native model therefore needs:

- owner user ID;
- visibility (`private`, `public`);
- admin override;
- authorization checks on list, get, update, delete, test and account binding;
- no leakage of private node address or source configuration to other users.

Public availability does not grant edit/delete rights. Ownership and usability are separate concepts.

## Failure fallback

Creation includes fallback selection. Reuse official proxy fallback semantics where possible:

- no fallback;
- direct fallback;
- fallback to another proxy.

For OpenAI OAuth/K12, direct fallback should be opt-in and prominently marked unsafe when the direct server exit fails ChatGPT Backend checks. Runtime process failure and upstream-IP blocking are distinct failure classes.

## Managed runtime

The Sub2API backend owns lifecycle management:

- validate generated configuration with `sing-box check` before persistence activation;
- write configuration atomically;
- allocate ports from a configured range with collision checks;
- spawn sing-box as a supervised child process;
- restore `auto_start` runtimes on application startup;
- graceful stop on update/delete/shutdown;
- bounded restart backoff and restart budget;
- process and config ownership restricted to the Sub2API user;
- redact credentials from command lines and logs;
- store runtime state under the application data directory.

A runtime becomes bindable only after its listener is ready and the required quality policy passes.

## Quality and IP policy

Generic connectivity is insufficient. Each advanced proxy must report:

1. actual public exit IP;
2. geolocation;
3. base connection latency;
4. OpenAI API reachability (`api.openai.com`);
5. ChatGPT OAuth/K12 backend reachability (`chatgpt.com/backend-api`);
6. Cloudflare challenge or IP-block classification;
7. optional authenticated canary result without exposing account credentials.

A proxy that reaches `api.openai.com` but receives the ChatGPT `Unable to load site`/VPN 403 page is `blocked`, not healthy. Database `active` state and an HTTP 200 from the admin test endpoint are never sufficient proof of account usability.

## Creation workflow

### Standard / Xray share link

1. Enter name and one share link.
2. Parse and validate.
3. Show normalized, secret-redacted node preview.
4. Select fallback and visibility.
5. Create runtime in `pending` state.
6. Validate config, start runtime, detect exit IP and run quality checks.
7. Mark bindable only on policy success.

### Standard / Sing-box subscription

1. Enter name and subscription URL.
2. Fetch with bounded size, timeout, redirects and SSRF protection.
3. Parse candidate nodes.
4. Show node-selection step.
5. Create selected runtime and retain subscription metadata for refresh.

### Standard / pasted Sing-box configuration

1. Paste outbound/endpoint or complete config.
2. Parse and resolve dependencies.
3. If one usable node exists, show preview; if multiple exist, show node selection.
4. Create selected runtime.

### Batch creation

- Parse once and display per-node validation results.
- Allow selecting valid nodes only.
- Deduplicate by canonical fingerprint.
- Create transactionally where possible and return itemized success/failure results.
- Never partially bind accounts during import.

## Scheduler compatibility

The v0.1.155 baseline includes the scheduler storm fixes from commits `9033e14b`, `8f328d4a` and `831862b9`. Native runtime work must preserve those guarantees.

- Runtime start, stop, health changes and subscription refreshes must not request a full scheduler snapshot rebuild.
- Account rebinding caused by runtime failure or proxy fallback must publish bounded, per-account scheduler outbox events, matching the official proxy-expiry path.
- Batch node import and batch account binding must aggregate changed account IDs and enqueue them in chunks; one event per row and one full rebuild per batch are both forbidden.
- Concurrent recovery, subscription refresh and administrator actions must coalesce duplicate work.
- Runtime-only changes that do not alter account schedulability or outbound binding must emit no scheduler event.
- If an incremental event cannot be persisted, report the failure and retry from durable state; do not silently fall back to a rebuild storm.
- Tests must assert that proxy/runtime expiry and fallback update affected accounts without invoking the full rebuild path.
- Event delay metrics must use the original durable event timestamp and must not be reset by retries or coalescing.

## Upgrade boundary

- `main` follows upstream only.
- Native runtime work remains on `feat/native-singbox-runtime`.
- Schema migrations must be additive in the first release.
- Existing static proxies and accounts must work unchanged when the feature is disabled.
- Production remains on official v0.1.155 until migration, rollback, runtime recovery, frontend, Docker and real K12 egress tests all pass.
