# Proof Gatekeeper agent — zkVerify Agent Games

Local, read-only-built agent endpoint for the **Proof Gatekeeper** track
(agentgames.zkverify.io). Receives signed task envelopes, decides
APPROVE/REJECT with deterministic checks, generates a real Groth16 proof
locally with snarkjs, and returns a signed response. Fail closed on any
uncertainty.

No account was registered, nothing was submitted, and no wallet/key/secret
was touched during this build. The HMAC secret is a placeholder env var until
registration issues a real one.

**Vercel deploy:** the same agent is packaged as a Serverless Function in
`api/index.js` — see [VERCEL.md](VERCEL.md). No laptop or tunnel needed;
the endpoint is a permanent `https://<project>.vercel.app/api` URL.

## Run

```sh
npm install          # snarkjs + circomlibjs (local only)
cp .env.example .env # then set AGENT_GAMES_HMAC_SECRET from the dashboard
node server.js       # listens on $PORT (default 3000)
```

Test harness (spawns the server, replays 8 signed synthetic envelopes,
verifies every returned proof against the exported verification key):

```sh
node test.js         # 11/11 checks pass in ~6s on this VM
```

## Endpoints

| Method & path | Behavior |
|---|---|
| `POST /`, `/task`, `/agent` (any POST path) | Task envelope handler (HMAC verified before parsing) |
| `POST` with `type: agent-games.preflight.v1` | Preflight: `{ ok: true, protocolVersion: "v1" }`, signed |
| `GET /health`, `GET /` | `{ ok: true, service, seen }` (no auth, no secrets) |

## Env vars

| Var | Default | Meaning |
|---|---|---|
| `PORT` | `3000` | Listen port |
| `AGENT_GAMES_HMAC_SECRET` | *(none — dev placeholder + warning)* | 32-byte secret from dashboard "Rotate Secret". Never commit. |
| `SEEN_FILE` | `./seen.json` | Persistent proof_tx replay set (atomic JSON writes) |
| `WASM_PATH` / `ZKEY_PATH` | `./circuits/gatekeeper.wasm`, `./circuits/gatekeeper_final.zkey` | Circuit artifacts |
| `PROOF_TIMEOUT_MS` | `45000` | Proof-generation budget inside the 60s platform deadline |
| `FIXED_SALT` | *(random per task)* | Tests only: deterministic private salt |

## Request / response

Incoming envelope (from `/build`, verified 13 Nov 2026):

```json
{
  "type": "agent-games.proof-gatekeeper.v1",
  "task_id": "gk_8d31_...",
  "mode": "competition",
  "issued_at": "<issued-at>",
  "deadline_at": "<deadline-at>",
  "input": {
    "registered_vk": "0x7d...91", "proof_vk": "0x13...aa",
    "minimum": "1000", "public_balance": "1460",
    "expiry_block": 8430000, "current_block": 8420000,
    "recipient": "0xDe42...9f01", "condition_recipient": "0xDe42...9f01",
    "amount": "500", "max_transfer": "1000",
    "proof_tx": "0xa8...2c"
  }
}
```

Response (signed with `x-agent-games-signature` over the raw body):

```json
{
  "decision": "APPROVE",
  "reason_code": "VALID_CONDITION",
  "proof_tx": "0xa8...2c",
  "proof": { "pi_a": [...], "pi_b": [[...]], "pi_c": [...], "protocol": "groth16", "curve": "bn128" },
  "public_signals": ["<commitment>", "<registeredVkHash>", "..."]
}
```

## Decision rules (fail closed, first failure wins)

| # | Check | Reject code |
|---|---|---|
| 1 | `registered_vk == proof_vk` (as field elements mod p) | `VK_SUBSTITUTION` |
| 2 | `public_balance >= minimum` | `THRESHOLD_MISMATCH` |
| 3 | `proof_tx` not seen under a different `task_id` | `PROOF_REUSED` |
| 4 | `current_block < expiry_block` (**strict** — equality is expired; verified against the circuit) | `EXPIRED_CONDITION` |
| 5 | `recipient == condition_recipient` | `RECIPIENT_MISMATCH` |
| 6 | `amount <= max_transfer` | `AMOUNT_OVERFLOW` |

All pass → `APPROVE` / `VALID_CONDITION`. Missing/malformed fields →
`REJECT` / `INVALID_ENVELOPE` (no proof). Proof-generation failure →
`REJECT` / `PROOF_GENERATION_FAILED` (no proof). Both fallback codes are
documented non-enum values used only on internal error paths.

## PROOF_REUSED and the proof

The circuit has no `proof_tx` input: replay protection is inherently
off-circuit (local seen-set, persisted to disk). The circuit enforces
`decision == on-circuit evaluation`, so a replayed-but-otherwise-valid task
cannot produce a valid proof with decision bit 0. For `PROOF_REUSED` the
agent therefore returns `REJECT` + `PROOF_REUSED` with a proof generated for
the **evaluation** decision bit (1 when the on-circuit checks pass). The
platform independently knows the reference was reused. Whether the platform
cross-checks the proof's decision bit against the response decision is
**unconfirmed** — a practice-mode verification item (see Blockers).

## What is done vs blocked

Done:

- HMAC verification (hex / `sha256=` / base64 accepted) before JSON parsing;
  signed responses; preflight responder.
- All 7 decision outcomes with exact reason codes, incl. the strict-expiry
  boundary the circuit enforces.
- Persistent replay set (`seen.json`, atomic writes, redelivery-safe).
- Real local Groth16 proofs (snarkjs, ~0.3–1.3s each on this VM — far inside
  the 60s deadline), verified in the test harness against the exported VK.
- Full circuit model reverse-engineered from the artifacts (see CIRCUIT.md):
  all 13 input names, public-signal order, Poseidon commitment, constraint
  semantics incl. boundaries.

Blocked (need practice-mode access / registration):

1. **Real HMAC secret** — only issued at registration ("Rotate Secret").
   The response-signature encoding (hex, no prefix) is assumed; inbound
   verification accepts all three common encodings.
2. **`taskId` encoding** — the circuit takes a field element; the envelope
   carries a string `task_id`. The agent uses `sha256(task_id) mod p`
   (`deriveTaskId()` in `prove.js`). If the platform encodes it differently
   (or sends a numeric id in practice mode), only that function changes.
3. **PROOF_REUSED proof semantics** — see section above.
4. **Public HTTPS hosting** — the endpoint must be reachable at a public
   HTTPS URL to register. See `cloudflared` notes below; a real deployment
   (VPS / PaaS) is still needed for competition rounds.
5. **zkVerify/Kurier submission is NOT implemented** — the build guide lists
   it as a path, but the Gatekeeper response carries the proof inline, so no
   on-chain submission is needed for the response itself. (Kurier would need
   a mainnet API key — out of scope for this local build.)

## cloudflared / quick tunnel

`cloudflared` was not preinstalled; version 2026.11.0 was downloaded (no
sudo, no account) and runs. Probe result (13 Nov 2026): quick-tunnel
creation FAILS from this VM — `cloudflared tunnel --url ...` cannot reach
`api.trycloudflare.com` (`tls: first record does not look like a TLS
handshake`; the sandbox egress proxy breaks cloudflared's TLS handshake,
with and without `--protocol http2`). So a quick tunnel cannot expose this
VM's localhost publicly. Even where it works, quick tunnels are ephemeral
(new URL per restart) and unsuitable for a registered competition endpoint.
Deploy properly (VPS / PaaS with a stable HTTPS URL) before registering.

## Files

```
server.js            HTTP service (plain node:http, no framework)
decide.js            pure decision logic + envelope validation
prove.js             snarkjs proof generation + taskId/salt derivation
seen.js              persistent replay set
test.js              11-check harness (8 decision cases + preflight + HMAC + malformed)
circuits/            gatekeeper.wasm, gatekeeper_final.zkey, verification_key.json
CIRCUIT.md           reverse-engineered circuit model + evidence
.env.example         blank env template (no secrets)
```

## Security notes

- Secrets only via env vars; `.env` is gitignored. Nothing secret is logged
  (no HMAC secret, no salt, no full envelopes).
- The private `salt` input is random per task and never leaves the process.
- Never paste keys/seeds into AI tools or commit them (per the build guide).
