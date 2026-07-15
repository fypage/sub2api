# Native sing-box Runtime Operations

Status: pre-production feature on `feat/native-singbox-runtime`.

## Enablement

The feature is disabled by default. The release image pins sing-box `v1.13.14` musl binaries and verifies the upstream SHA-256 digest for amd64 and arm64 during the Docker build.

```yaml
native_proxy_runtime:
  enabled: true
  binary_path: /usr/local/bin/sing-box
  data_dir: /app/data
  ready_timeout_seconds: 20
  probe_interval_millis: 100
  stop_timeout_seconds: 5
  max_restarts: 5
  restart_base_seconds: 1
  restart_max_seconds: 30
```

Do not enable the feature before migration `177_native_proxy_runtime_foundation.sql` has completed. Existing static proxies are unaffected while disabled.

## Runtime safety model

- Generated listeners bind only to loopback and require random SOCKS authentication.
- Imported node/source secrets are encrypted with the durable database runtime key.
- Config files are mode `0600`; runtime directories are mode `0700`.
- sing-box output is discarded because it can contain credentials.
- Only one application replica can own a runtime through a PostgreSQL session advisory lock.
- Logical proxy rows remain disabled until the listener is ready.
- Runtime failure atomically disables the logical proxy.
- Shutdown sends SIGTERM to the process group, then SIGKILL after the configured timeout.

## Pre-deployment checks

1. Back up PostgreSQL and `/app/data`.
2. Build the feature image for the target architecture.
3. Verify `/usr/local/bin/sing-box version` reports `1.13.14`.
4. Run migration tests and the full backend/frontend CI suite.
5. Start with `native_proxy_runtime.enabled: false`; verify all existing static proxies and account scheduling.
6. Enable the feature in a staging instance with an isolated database copy.
7. Import one disposable node and verify:
   - runtime status becomes `healthy`;
   - proxy status becomes `active` only after listener readiness;
   - listener is not reachable outside the container/host namespace;
   - exit IP differs from direct server IP;
   - OpenAI API and ChatGPT backend classifications are recorded separately.
8. Restart the application and verify auto-start recovery obtains a lease and replaces the stale PID.
9. Kill the child process and verify bounded restart and `restart_count`.
10. Stop the application and verify no sing-box child or listener remains.

## Rollback

1. Set `native_proxy_runtime.enabled: false` and restart the application. This prevents recovery and stops locally managed children during graceful shutdown.
2. Keep migration 177 in place. It is additive and must not be removed from a live database.
3. Roll back the application image to the official pinned Sub2API version.
4. Native proxy rows remain disabled and cannot affect existing static proxies.
5. If cleanup is required after confirming no account references a native proxy, delete those logical proxies through the application workflow; do not manually drop runtime tables.

## Failure triage

Runtime APIs expose only stable error codes and redacted messages. Relevant codes include:

- `config_check_failed`
- `listener_in_use`
- `listener_not_ready`
- `process_exit`
- `runtime_start_failed`

Never copy raw share links, encrypted envelopes, generated SOCKS passwords, config files, or sing-box stderr into tickets or logs.
