'use strict';
/**
 * api/index.js — Proof Gatekeeper agent endpoint as a Vercel Serverless Function.
 *
 * Same protocol and decision logic as server.js (the long-running PC version),
 * adapted for serverless:
 *  - No http server: Vercel invokes this handler with Node (req, res).
 *  - bodyParser MUST stay disabled (see module.exports.config below): the
 *    HMAC signature is computed over the RAW body, so we read the stream
 *    ourselves and verify BEFORE parsing JSON.
 *  - CommonJS throughout: snarkjs via ESM `import` hangs indefinitely on
 *    Node 24; `require('snarkjs')` works (~1.3s cold start).
 *  - Replay-protection seen-set is IN-MEMORY ONLY (serverless filesystem is
 *    ephemeral; /tmp does not outlive a warm instance). Consequence: the
 *    PROOF_REUSED trap is only caught when both deliveries hit the same warm
 *    instance. The on-circuit decision is unaffected. See VERCEL.md.
 *  - Circuit artifacts resolve in order: WASM_PATH/ZKEY_PATH env (only if
 *    the files verify — a stale or PC-local override is ignored), bundled
 *    ./circuits/ (fetched at build time by scripts/fetch-circuits.js),
 *    then a verified runtime download to /tmp/circuits/ as last resort.
 *  - Fail closed everywhere: any timeout, error, or uncertainty -> REJECT.
 *
 * Env vars (set in the Vercel dashboard, never committed):
 *   AGENT_GAMES_HMAC_SECRET — MUST be the same secret registered for the
 *     agent in the Agent Games dashboard, or signatures will not verify.
 *   PROOF_TIMEOUT_MS (default 45000), WASM_PATH, ZKEY_PATH,
 *   FIXED_SALT (tests only).
 *
 * No secrets are ever logged.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { decide, REASON } = require('../decide');
const { generateProof } = require('../prove');
const { ensureCircuits, fileIsValid, ARTIFACTS } = require('../lib/circuits');

const HMAC_SECRET = (process.env.AGENT_GAMES_HMAC_SECRET || '').trim() || '';
const PROOF_TIMEOUT_MS = parseInt(process.env.PROOF_TIMEOUT_MS || '45000', 10);
const MAX_BODY_BYTES = 1024 * 1024;

if (!HMAC_SECRET) {
  console.error(JSON.stringify({ level: 'warn', msg: 'AGENT_GAMES_HMAC_SECRET is unset — using dev placeholder; DO NOT register this deployment' }));
}
const SECRET = HMAC_SECRET || 'dev-placeholder-secret-do-not-register';

/** In-memory replay set. Same semantics as SeenSet, no persistence. */
class MemorySeenSet {
  constructor() { this.map = new Map(); }
  isReused(proofTxKey, taskId) {
    const rec = this.map.get(proofTxKey);
    return !!rec && rec.task_id !== taskId;
  }
  record(proofTxKey, taskId, decision) {
    if (!this.map.has(proofTxKey)) {
      this.map.set(proofTxKey, { task_id: taskId, decided_at: new Date().toISOString(), decision });
    }
  }
  get size() { return this.map.size; }
}

const seen = new MemorySeenSet();

// Serialize proof generation per instance: the prover is CPU-heavy; queue
// tasks instead of running them concurrently so each stays in deadline.
let proveQueue = Promise.resolve();
function enqueueProve(fn) {
  const run = proveQueue.then(fn, fn);
  proveQueue = run.then(() => undefined, () => undefined);
  return run;
}

function hmacHex(rawBody) {
  return crypto.createHmac('sha256', SECRET).update(rawBody).digest('hex');
}

function safeEqual(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/**
 * Verify the inbound signature. Accepts: raw lowercase hex, "sha256=<hex>",
 * or base64 of the raw HMAC bytes. The platform does not publish the exact
 * encoding; accepting all three removes a needless failure mode.
 */
function verifySignature(headerValue, rawBody) {
  if (!headerValue || typeof headerValue !== 'string') return false;
  const v = headerValue.trim();
  const hex = hmacHex(rawBody);
  const candidates = [hex, 'sha256=' + hex];
  for (const c of candidates) if (safeEqual(v.toLowerCase(), c.toLowerCase())) return true;
  try {
    const b64 = Buffer.from(hex, 'hex').toString('base64');
    if (safeEqual(v, b64)) return true;
  } catch { /* ignore */ }
  return false;
}

function log(obj) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...obj }));
}

function sendSigned(res, statusCode, obj) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(statusCode, {
    'content-type': 'application/json',
    'x-agent-games-signature': hmacHex(body),
  });
  res.end(body);
}

function readRawBody(req) {
  // Vercel may hand us a parsed body if bodyParser was ever enabled; with
  // bodyParser disabled req is a plain stream. Handle both, but prefer the
  // raw stream so the HMAC input is byte-exact.
  if (req.body !== undefined && req.body !== null && typeof req.body !== 'object') {
    return Promise.resolve(Buffer.from(String(req.body), 'utf8'));
  }
  if (Buffer.isBuffer(req.body)) return Promise.resolve(req.body);
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error('body too large'));
        if (typeof req.destroy === 'function') req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function withTimeout(promise, ms, label) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(label + ' timed out after ' + ms + 'ms')), ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

// --- Circuit artifact resolution (cached per instance) ---
let circuitsPromise = null;

function bundledCandidates() {
  // Layouts, in order: next to the bundled function, project root, Lambda cwd.
  const bases = [
    path.join(__dirname, '..', 'circuits'),
    path.join(process.cwd(), 'circuits'),
    path.join('/var/task', 'circuits'),
  ];
  const out = [];
  for (const base of bases) {
    out.push({
      wasmPath: path.join(base, 'gatekeeper.wasm'),
      zkeyPath: path.join(base, 'gatekeeper_final.zkey'),
    });
  }
  return out;
}

function resolveCircuits() {
  if (circuitsPromise) return circuitsPromise;
  circuitsPromise = (async () => {
    // 1. Explicit env overrides — verified before use. A stale or PC-local
    // WASM_PATH/ZKEY_PATH (e.g. copied from the PC .env into Vercel) must
    // never break the deployment: invalid overrides fall through to the
    // bundled artifacts below instead of being trusted blindly.
    if (process.env.WASM_PATH && process.env.ZKEY_PATH) {
      const envCand = { wasmPath: process.env.WASM_PATH, zkeyPath: process.env.ZKEY_PATH };
      if (fileIsValid(envCand.wasmPath, ARTIFACTS[0]) && fileIsValid(envCand.zkeyPath, ARTIFACTS[1])) {
        return envCand;
      }
      log({ level: 'warn', msg: 'WASM_PATH/ZKEY_PATH set but artifacts invalid or missing, falling back to bundled circuits' });
    }
    // 2. Bundled artifacts (build-time fetch), verified before use.
    for (const cand of bundledCandidates()) {
      if (fileIsValid(cand.wasmPath, ARTIFACTS[0]) && fileIsValid(cand.zkeyPath, ARTIFACTS[1])) {
        return cand;
      }
    }
    // 3. Last resort: verified runtime download into the ephemeral /tmp.
    const dir = path.join(os.tmpdir(), 'gatekeeper-circuits');
    log({ msg: 'circuits not bundled, downloading verified copies', dir });
    return ensureCircuits(dir, { timeoutMs: 20000 });
  })().catch((err) => {
    circuitsPromise = null; // allow a later request to retry
    throw err;
  });
  return circuitsPromise;
}

async function handleTask(envelope) {
  const taskId = typeof envelope.task_id === 'string' ? envelope.task_id : null;
  const started = Date.now();
  const result = decide(envelope, (k, t) => seen.isReused(k, t));

  // Record the proof reference for replay protection (all decided tasks, win or lose).
  if (result.fields) seen.record(result.fields.proofTxKey, taskId, result.decision);

  const proofTxOut = result.fields
    ? '0x' + result.fields.proofTxKey
    : (envelope.input && typeof envelope.input.proof_tx === 'string' ? envelope.input.proof_tx : null);

  // No valid fields -> cannot build a proof input. Fail closed, no proof.
  if (!result.fields || result.evaluation === null) {
    log({ task_id: taskId, decision: result.decision, reason_code: result.reason_code, proof_tx: proofTxOut, ms: Date.now() - started, proof: 'none', note: result.error });
    return { decision: result.decision, reason_code: result.reason_code, proof_tx: proofTxOut, proof: null, public_signals: [] };
  }

  // Proof decision bit: normally matches the response decision. EXCEPTION:
  // PROOF_REUSED with otherwise-valid fields — the circuit only accepts
  // decision == on-circuit evaluation, so the proof attests the evaluation
  // (bit 1) while the response decision is REJECT. See README.md.
  const proofBit = result.reason_code === REASON.REUSED ? result.evaluation : (result.decision === 'APPROVE' ? 1 : 0);

  try {
    const circuits = await withTimeout(resolveCircuits(), 25000, 'circuit resolution');
    const { proof, publicSignals } = await enqueueProve(() =>
      withTimeout(
        generateProof(result.fields, proofBit, taskId, { wasmPath: circuits.wasmPath, zkeyPath: circuits.zkeyPath }),
        PROOF_TIMEOUT_MS,
        'proof generation',
      ));
    log({ task_id: taskId, decision: result.decision, reason_code: result.reason_code, proof_tx: proofTxOut, ms: Date.now() - started, proof: 'generated' });
    return { decision: result.decision, reason_code: result.reason_code, proof_tx: proofTxOut, proof, public_signals: publicSignals };
  } catch (err) {
    // Proof generation failed: fail closed. A REJECT without a valid proof is
    // still the platform-prescribed behavior ("reject on uncertainty").
    log({ level: 'error', task_id: taskId, decision: 'REJECT', reason_code: 'PROOF_GENERATION_FAILED', proof_tx: proofTxOut, ms: Date.now() - started, proof: 'failed', error: String(err.message).slice(0, 200) });
    return { decision: 'REJECT', reason_code: 'PROOF_GENERATION_FAILED', proof_tx: proofTxOut, proof: null, public_signals: [] };
  }
}

const HEALTH_PATHS = new Set(['/', '/health', '/api', '/api/', '/api/health', '/api/index', '/api/index.js']);

async function handler(req, res) {
  try {
    const pathname = (req.url || '/').split('?')[0];
    if (req.method === 'GET' && HEALTH_PATHS.has(pathname)) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, service: 'proof-gatekeeper', seen: seen.size, runtime: 'vercel' }));
      return;
    }
    if (req.method !== 'POST') {
      res.writeHead(405, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'method not allowed' }));
      return;
    }

    // 1. Read raw body, 2. verify HMAC BEFORE parsing (per spec).
    const rawBody = await readRawBody(req);
    if (!verifySignature(req.headers['x-agent-games-signature'], rawBody)) {
      log({ level: 'warn', msg: 'signature verification failed', path: pathname });
      sendSigned(res, 401, { error: 'invalid signature' });
      return;
    }

    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString('utf8'));
    } catch {
      sendSigned(res, 400, { error: 'invalid JSON' });
      return;
    }

    // Preflight handshake (runs before any task).
    if (envelope && envelope.type === 'agent-games.preflight.v1') {
      log({ msg: 'preflight', agent_id: envelope.agent_id || null, nonce: envelope.nonce || null });
      sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
      return;
    }

    if (!envelope || typeof envelope !== 'object' || !envelope.input) {
      sendSigned(res, 200, { decision: 'REJECT', reason_code: REASON.INVALID, proof_tx: null, proof: null, public_signals: [] });
      return;
    }

    const response = await handleTask(envelope);
    sendSigned(res, 200, response);
  } catch (err) {
    // Last-resort fail closed: never leave the platform hanging.
    log({ level: 'error', msg: 'unhandled request error', error: String(err.message).slice(0, 200) });
    try { sendSigned(res, 200, { decision: 'REJECT', reason_code: REASON.INVALID, proof_tx: null, proof: null, public_signals: [] }); } catch { /* socket gone */ }
  }
}

module.exports = handler;
// Raw-body access is REQUIRED for HMAC verification. Do not remove.
module.exports.config = { api: { bodyParser: false } };
