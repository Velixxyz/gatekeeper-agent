# Deploying the Gatekeeper agent on Vercel

Same agent, same decision logic and real Groth16 proofs as the PC version,
served as a Vercel Function: `server.js` exports its request handler and
Vercel invokes it per request, so the agent runs on a permanent public
HTTPS URL with no laptop or tunnel involved.

## How it works

- Vercel builds `server.js` as the entrypoint function and routes every
  request to its exported handler. The handler reads the raw body,
  verifies the `x-agent-games-signature` HMAC **before** parsing JSON,
  answers preflight, decides, generates the proof with snarkjs, and
  returns a signed response. Fail closed on any uncertainty. The default
  export MUST be the bare handler function (`module.exports =
  handleRequest`) and `listen()` MUST NOT run on Vercel (guarded by
  `process.env.VERCEL`): exporting `{ server }` crashed every invocation
  with "Invalid export found in module /var/task/server.cjs" (incident
  14 Nov 2026, deployment 8bfeb2c), and exporting the listening server
  with `listen()` at module load hung every request ~63s into
  `INTERNAL_FUNCTION_INVOCATION_FAILED` (incident 14 Nov 2026,
  deployment d54ebcd — listen-capture initialization timeout, the same
  pattern Vercel staff describe for zero-config Node servers).
- `server.js` disables Vercel's body parser (`module.exports.config`,
  `bodyParser: false`) and accepts a launcher-provided byte-exact
  `req.body` before reading the stream: the HMAC is computed over the raw
  bytes, and a consumed stream makes every signed request 401.
- `api/index.js` is a tested fallback, not the live path; it keeps
  `bodyParser` disabled (`module.exports.config`): the HMAC is computed
  over the raw bytes, and any pre-parsing would break signature
  verification. `server.js` reads the raw stream itself (`readRawBody`).
- Circuit artifacts are NOT in the repo. The explicit `buildCommand` in
  `vercel.json` runs `scripts/fetch-circuits.js`, which downloads
  `gatekeeper.wasm` + `gatekeeper_final.zkey` from the official Agent
  Games site at build time and verifies sizes + SHA-256 before the
  function is bundled. (The `vercel-build` script in `package.json`
  alone is NOT enough: on the 14 Nov 2026 deploy it never ran — the
  build log had 21 lines and no fetch step. The explicit `buildCommand`
  is what guarantees the fetch.) If the bundled files are ever missing
  at request time, the handler downloads verified copies to `/tmp/`
  as a last resort. `prove.js` verifies every candidate (explicit opts,
  `WASM_PATH`/`ZKEY_PATH` env pair, bundled files) by size + SHA-256 and
  falls through to the next tier on any mismatch, so a stale PC-local env
  override can never break proof generation.
- `.vercelignore` MUST NOT exclude `server.js` or `seen.js` (only the test
  files). Vercel builds `server.js` as the entrypoint function and routes
  all traffic to it; `seen.js` is required by it. Excluding `server.js` makes every build fail with "No entrypoint
  found in /vercel/path0" (incidents 14 Nov 2026, commits 33c9ada and
  97b4170): the `api/` directory alone does NOT trigger function
  detection for this project. The earlier crash ("Invalid export found in
  module /var/task/server.cjs", deployment 8bfeb2c) was the export shape
  (`{ server }`), not the entrypoint itself — fixed by exporting the
  handler function (see above).
- `package.json` sets `"main": "server.js"` (restored). Removing it did
  NOT fix the "No entrypoint found" builds (commit 97b4170 failed the
  same way as 33c9ada): the entrypoint is the `server.js` file itself,
  and the file must be uploaded (see above).
  `npm start` (which runs `node server.js` directly) is unaffected.
- `vercel.json` pins the function to `maxDuration: 60` (the platform's own
  task deadline) and includes `circuits/**` in the function bundle.
- CommonJS throughout: snarkjs via ESM `import` hangs indefinitely on
  Node 24; `require('snarkjs')` works. `package.json` pins Node 22.x.

## Deploy steps

1. Push this repo to GitHub (text files only; the circuit binaries and
   `.env` are gitignored).
2. In Vercel: Add New Project → Import the repo → Deploy.
3. Set the environment variable **before the first real task arrives**:
   `AGENT_GAMES_HMAC_SECRET` = the secret registered for the agent in the
   Agent Games dashboard. It MUST be the same value the platform has on
   file, or inbound signatures fail (401) and outbound signatures will not
   verify. Never commit it; set it in Vercel Project Settings →
   Environment Variables (Production).
4. After deploy, check health in a browser or curl:
   `https://<project>.vercel.app/api` → `{"ok":true,"service":"proof-gatekeeper",...}`
5. In the Agent Games dashboard, edit the agent and set the endpoint to
   `https://<project>.vercel.app/api`, then run the preflight check. It
   must show Healthy before the round opens. Endpoint edits are locked
   while a round is open (rounds run 17:30–03:30 WIB), so update it
   outside round hours.

## Local verification

```sh
npm install
node scripts/fetch-circuits.js   # downloads + verifies artifacts
node test.js                     # 11 checks: PC server path (spawn + HTTP + real proofs)
node test-vercel.js              # 24 checks: 8 decision cases x2 resolution
                                 # paths + health + preflight + bad HMAC +
                                 # malformed envelope; every proof verified
                                 # against the exported verification key
```

## Known serverless trade-offs (read before relying on it)

1. **Replay protection is per-instance.** The PC version keeps a persistent
   `seen.json`; serverless instances have no shared durable disk, so the
   seen-set lives in memory only. The `PROOF_REUSED` trap is only caught
   when both deliveries of the same `proof_tx` hit the same warm instance.
   The on-circuit decision (VK, threshold, expiry, recipient, amount) is
   unaffected.
2. **60s ceiling.** Hobby-plan functions max out at 60s (`maxDuration`
   in `vercel.json`). Proof generation is budgeted at 45s
   (`PROOF_TIMEOUT_MS`) and measured at ~0.3–1.3s on a VM, plus a ~1–3s
   cold start for snarkjs. If a task ever exceeds the ceiling, Vercel
   kills it mid-flight and the platform sees a failure; the handler fails
   closed wherever it still controls the response.
3. **Cold starts.** The first request to a fresh instance pays the snarkjs
   load cost. Preflight calls keep instances warm-ish during rounds, but
   no warm-up is guaranteed.
4. **Concurrency.** Proof generation is serialized per instance (a queue),
   but Vercel may run several instances in parallel. Tasks are
   independent, so this is safe; it only weakens the in-memory seen-set
   further (see point 1).
