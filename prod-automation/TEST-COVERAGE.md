# Test coverage — Rift v3 enclave + multi-tenant routing

Snapshot of what has automated coverage vs what still needs
human eyes before you sink migration time into prod.

## What IS covered by automated tests

### Backend — Jest (`src/tests/*.test.ts`)

**`projectEnclaveConfigService.test.ts` — 18 tests, all green**
Prisma is mocked at `db/dbConnection` (no real DB). AES `encrypt` /
`decrypt` from `utils/encryption` is real, so we exercise the actual
at-rest-encryption path for bearers.

Assertions:
- `resolveEnclaveConfig` returns null for empty / null / undefined
  projectId without touching prisma.
- `resolveEnclaveConfig` returns null when no row exists (env-fallback
  signal for callers).
- Bearer round-trip: `writeEnclaveConfig` encrypts, `resolveEnclaveConfig`
  decrypts back to the original plaintext.
- 60-second cache: 3 reads within TTL = 1 prisma call.
- Negative cache: null result also cached (no stampede on unknown projects).
- Corrupt ciphertext → returns null (defensive).
- `writeEnclaveConfig` normalises pcr0 to lowercase.
- `writeEnclaveConfig` invalidates cache; next read re-fetches.
- Upsert path: create → update in the same session works.
- `deleteEnclaveConfig` removes the row AND clears the cache.
- Delete on a non-existent row does not throw.
- `resolveChainConfig` returns null when `active=false`.
- `resolveChainConfig` decrypts `bundlerBearer` when present.
- `resolveChainConfig` leaves `bundlerBearer` null when unset.
- `writeChainConfig` encrypts `bundlerBearer` when present.
- Missing `ENCRYPTION_KEY` env → throws (fail loud, don't silently write plaintext).

**`enclaveConfigRoutes.test.ts` — 23 tests, all green**
Supertest against a bare `express()` app that mounts only the routers
under test. Service layer is mocked so we test routing + auth +
validation, not encryption (that's the service test above).

Assertions:
- Admin PUT: 401 without `X-Admin-Key`, 401 with wrong key, 200 with
  correct key.
- Admin PUT input validation: rejects non-https URL, short bearer,
  bad KMS ARN, bad AWS region, wrong-length PCR0, non-hex PCR0,
  empty enclaveRef.
- Admin GET: bearer redacted to `***redacted***`; plaintext bearer
  never appears in the response body (asserted via full-body search).
- Admin GET: 404 when no config exists.
- Admin DELETE: forwards to service.
- Admin PUT chain-configs: rejects non-integer chainId, non-http URLs.
- Admin PUT chain-configs: accepts a valid config and forwards.
- Internal GET: 401 without `X-Internal-Token`.
- Internal GET: 401 with wrong token.
- **Internal GET does NOT accept the admin key** — critical, they must
  be distinct secrets.
- Internal GET returns plaintext bearer when auth is correct (this is
  the whole point of the internal path).
- Internal GET 404 when config missing.
- Missing `ENCLAVE_ADMIN_API_KEY` env → 503 (safer than accidental open).
- Missing `INTERNAL_SERVICE_TOKEN` env → 503.

**Combined:** 41 backend tests, ~2 s to run.

### Smart-wallet — Vitest (`src/enclaveConfigClient.test.ts`)

20 tests, all green. `fetch` is mocked with `vi.spyOn(globalThis, "fetch")`
so the suite is hermetic — no network, no backend, no enclave.

Assertions:
- Falsy inputs (null / undefined / empty projectId) return null without
  fetching.
- Missing `RIFT_BACKEND_URL` or `INTERNAL_SERVICE_TOKEN` env → null
  without fetching (multi-tenant off; caller falls back to env).
- Env-missing null is NOT cached (env may be set later at runtime).
- 200 path returns the parsed config.
- 200 path caches: 3 reads = 1 fetch.
- Attaches `X-Internal-Token` on the outgoing request.
- URL-encodes the projectId (slash / space handled).
- 404 path returns null and caches (negative TTL).
- 500 path returns null.
- Network error path returns null when no cache exists.
- Stale-if-error: a cached good value is served when a subsequent
  fetch would 5xx within the positive TTL window.
- `resolveChainConfig` picks the right chain out of the parent config,
  returns null when the chain isn't in the list, keeps decrypted
  `bundlerBearer` when set, respects `paymasterUrl`.
- `invalidateCache(projectId)` forces a re-fetch for one project.
- `invalidateCache()` with no arg clears everything.

### Shell scripts — Shellcheck

All four scripts pass at `--severity=info` (strictest short of style
nits). Confirmed via `npx --yes shellcheck --severity=info *.sh` from
`prod-automation/`.

Scripts covered:
- `aws-provision.sh`
- `ec2-bootstrap.sh`
- `teardown-provision.sh`
- `verify-pcr0.sh`

### Static typecheck

- `backend`: `npx tsc --noEmit` clean.
- `smart-wallet`: `npx tsc --noEmit` clean for our changes. Pre-existing
  errors in `permissionless/*` (third-party lib strictness) and a
  handful in `keyEncryption.ts` / `routes.ts` that were there before —
  none introduced by this work.
- `dashboard`: `npx tsc --noEmit -p tsconfig.app.json` clean, `vite build`
  clean.

## What is NOT covered (and why)

### Dashboard `EnclaveTab.tsx` — no unit tests

The dashboard repo has zero test infrastructure — no `jest`, no
`vitest`, no `@testing-library/react`, no `test` script in
`package.json`. Introducing testing here would be a separate PR of
its own (add vitest + RTL + jsdom, decide on conventions, write the
tests). Deferred so we can ship the flow.

**Manual verification required** for the tab, when you review:
- Empty state renders when no config exists.
- Form validation errors surface for: non-https URL, short bearer,
  bad KMS ARN, bad AWS region, wrong-length PCR0, empty enclaveRef.
- Save round-trips through the backend and re-renders with the bearer
  redacted.
- "Remove config" opens the confirm affordance, second click actually
  deletes.
- Chain-configs section: add a chain, edit it (bundler bearer blank
  keeps current), remove it.
- Rotating a bearer: paste a new one into the bearer field on an
  existing config, save, verify the smart-wallet picks it up within
  the 60-second cache TTL.

### The bash scripts themselves — never run against real AWS

We cannot exercise `aws-provision.sh` / `ec2-bootstrap.sh` /
`teardown-provision.sh` end-to-end without spending money on real
AWS resources. They're syntax-clean, shellcheck-clean, and
logically correct on paper, but the first prod run is the first
real run.

**Mandatory before Phase 1 of the graduation plan:**
1. Run `DRY_RUN=1 ENV_TAG=sandbox AWS_REGION=us-east-1 ./aws-provision.sh`
   and read the log carefully. Verify it doesn't propose anything
   surprising.
2. Run the real thing against a scratch AWS account (NOT prod).
3. Run `./ec2-bootstrap.sh` on that instance with `ENCLAVE_REF=main`
   (for the first test) and confirm the self-verify block at
   the end reports 0 failures.
4. Run `./teardown-provision.sh --yes` against the same scratch
   account and confirm every resource comes down cleanly.

Only after the scratch-account rehearsal do you touch a real prod
AWS account.

### The signing-flow end-to-end — never run against a live enclave

No test in this repo drives:
- Backend `enclaveClient.provisionUserEoa(userId, projectId)` →
  smart-wallet `/generate-wallet` → integrator's parent-proxy →
  enclave → KMS `Decrypt-with-Recipient` → signed envelope back.
- The dashboard "click save" → backend PUT → service write → cache
  invalidate → smart-wallet next resolve → new routing applied.

These need an actual enclave running to test. First rehearsal is the
sandbox pass in Phase 0 of the graduation plan; that's the gate for
proceeding to Phase 1 (prod idle).

### Canonical PCR0 publication

`verify-pcr0.sh` fetches `https://riftfi.com/enclave/pcr0/<tag>.txt`
and byte-compares. **That URL 404s today.** Nothing to test until
someone drops the static file for `v1.0.0` on the marketing site.

### Load / soak

No load test exists. Sizing assumption (`c6g.large`, 1 vCPU + 1024
MiB to the enclave) is inherited from sandbox. Verify with a real
prod-shaped load test before the 72-hour soak in Phase 11 of the
graduation plan.

## How to run the suites

```bash
# Backend (jest)
cd backend
npx jest src/tests/projectEnclaveConfigService.test.ts \
         src/tests/enclaveConfigRoutes.test.ts

# Smart-wallet (vitest)
cd smart-wallet
npx vitest run src/enclaveConfigClient.test.ts

# Shell scripts
cd rift-signer-enclave/prod-automation
npx --yes shellcheck --severity=info *.sh

# Dry-run the AWS provision (safe, no mutations)
DRY_RUN=1 ENV_TAG=sandbox AWS_REGION=us-east-1 ./aws-provision.sh
```

## Green line count

| Suite | Tests | Time |
|---|---|---|
| backend / projectEnclaveConfigService | 18 | 4.0 s |
| backend / enclaveConfigRoutes | 23 | 2.8 s |
| smart-wallet / enclaveConfigClient | 20 | 0.5 s |
| **Total automated** | **61** | **~7 s** |
| Shell scripts (shellcheck) | 4 files, 0 findings | <1 s |
| Static typecheck (backend + smart-wallet + dashboard) | clean for our changes | ~15 s |
