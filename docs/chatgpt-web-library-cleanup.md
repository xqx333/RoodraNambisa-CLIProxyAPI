# ChatGPT Web Library Cleanup

The Auth Files page provides a manual **Web library cleanup** action. Select
ChatGPT Web credentials, or explicitly select all Web credentials regardless of
page filters, choose concurrency (1-32), and confirm deletion. Automatic cleanup
is a separate, destructive opt-in and is disabled by default.

## Deletion Scope

- All owned, first-party library files found during the inventory are selected,
  including files uploaded manually. Back up anything that must be retained.
- Shared files, third-party mounts, folders and existing trash are excluded.
- This action does not delete conversations or authentication files. It does not
  purge existing trash or implement an undo operation.
- A frozen inventory is collected before deletion. Files created outside CPA
  after inventory are not included. Capacity and rolling upload-rate limits are
  separate; clearing storage does not guarantee a rate limit is lifted.

## Execution

Only one cleanup job may run per CPA process. Concurrency is across credentials;
queued credentials remain available until a worker starts their maintenance.
The worker blocks new execution leases for the credential and any known account
aliases, then waits for in-flight execution leases without canceling them.
Deletion uses the credential's own persona and configured proxy. Finishing or
canceling maintenance never changes its persisted enabled/disabled state.

The complete inventory is paginated, then deleted in batches of 20. A successful
HTTP response is insufficient: each returned file result must identify the
requested library file and contain `success: true`. Missing or ambiguous results
fail the credential without replaying the deletion. Partial results are retained.
Explicit per-file failures are classified using their `status_code` and safe
error categories. Transient or unspecified rejections retry only the failed
subset, at most twice with cancelable 1/2-second waits. Permission, not-found and
invalid-request errors are not retried. Storage usage is read before and after
the operation; the upstream capacity counter can lag behind successful deletion.

Closing the dialog does not stop the job. Cancel stops pending and ongoing work
but does not undo completed deletions. Request-owned connections are closed on
cancellation. The latest progress survives page reloads, but is memory-only and
is replaced by the next job or lost on server restart. Jobs are limited to 50,000
runtime credentials; queued targets retain IDs, not copies of tokens or cookies.

Credentials must have usable access tokens. Authentication failures are shown
as such; cleanup does not automatically log in, cool credentials, or change
model usage statistics. Credentials shared across different CPA processes require
external coordination; the maintenance gate is local to this process.

## Automatic Recovery

```yaml
images:
  chatgpt-web:
    auto-cleanup-library-on-full: false
```

When explicitly enabled, an image reference upload rejection carrying the
website's `library_storage_limit_exceeded` or `over_user_quota` code can schedule
a background check. The latter is ambiguous: a generic 429, `throttled`, or an
image generation quota never triggers deletion by itself. After draining the
credential, the worker reads authoritative library usage again. It deletes only
if the library is over its storage limit or remaining bytes cannot fit the
rejected upload. Failed/invalid usage reads fail closed without deletion.

The same safe inventory, maintenance gate, cancellation and progress interface
is reused. No image is automatically resubmitted. Only one manual or automatic
job runs at once; there is no unbounded automatic queue. Automatic checks are
limited to once per account per 10 minutes, with a bounded in-memory cooldown.
Progress labels automatic versus manual jobs. The setting is pinned to the
logical image request, including retries and aggregation. Normal chats and
other providers do not opt into deletion.

## Live Validation (2026-09-16)

Three additional authorized accounts contained 268, 260 and 263 owned library
entries. Tests first exercised the management job, its duplicate-start rejection
and drain gate. The test-only 120-second safety deadline interrupted the initial
passes; residual passes completed, and final listings were empty on all three.
All production credentials were restored to their prior enabled state.

An account with nonempty Recently deleted showed 0 used bytes and 512 MiB free,
and a real 83-byte PNG reference upload completed through the new processing
endpoint without purging trash. Another account's usage counter was still
settling after its listing became empty. This is evidence of recovery without a
trash purge for these accounts, not a promise of synchronous quota accounting.

Per-file failures were transient in follow-up tests, but their original backend
cause was not proven. Do not label them as authentication failures or confirmed
throttling. The code now preserves safe per-file status categories. No account
was deliberately filled to capacity, so the exact full-storage HTTP response
was not reproduced; code recognition is based on the current official frontend
and automatic deletion additionally requires a live storage check.

## Management API

These endpoints use the existing management authentication and access prefix:

- `GET /v0/management/chatgpt-web/library-cleanup`: latest `{ "task": ... }`,
  or `{ "task": null }` before the first job. `?page=1` selects a page of 25
  credential results; aggregate counts always cover the entire job.
- `POST /v0/management/chatgpt-web/library-cleanup`: start a job (202). Send
  `names: ["credential.json"]` or `all: true`, `concurrency: 4`, and
  `confirm_delete_all_files: true`. A concurrent start returns 409.
- `DELETE /v0/management/chatgpt-web/library-cleanup/{id}`: cancel that exact job.

Progress includes credential name, stage, counts, capacity snapshots and safe
error categories. It excludes file inventories, file content, account tokens,
cookies and signed URLs. All upstream errors remain isolated from business
request retry, cooling and usage accounting.

## Upload Compatibility

Reference uploads now include MIME metadata and explicitly avoid requesting
library persistence. They confirm processing through `files/process_upload_stream`
and require `file.processing.completed`, accepting the observed newline-delimited
JSON and SSE framing. Only an explicit 404 or 405 on that endpoint permits legacy
`files/{id}/uploaded` confirmation; uploads and generation submissions are never
replayed by this fallback.

The official frontend still uses `POST /backend-api/files` for initialization.
This compatibility update does not establish the cause of earlier initialization
404/451 errors. Ordinary 404s now report `not_found` rather than inventing a missing
model; explicit model errors remain intact. Runtime management summaries no longer
classify arbitrary upstream failures as authentication failures.
