'use strict';
// Minimal .env loader (no dependency): fills unset vars from a local .env file
// so `npm start` works the same on Windows/macOS/Linux. Real env vars win.
try {
  const fs = require('node:fs');
  const path = require('node:path');
  const envFile = path.join(__dirname, '.env');
  if (fs.existsSync(envFile)) {
    for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  }
} catch { /* .env is optional */ }
/**
 * server.js — Proof Gatekeeper agent endpoint (plain Node.js http, no framework).
 *
 * Protocol (from https://agentgames.zkverify.io/build, 13 Nov 2026):
 *  - Platform POSTs a signed JSON task envelope to the registered public HTTPS endpoint.
 *  - Incoming requests carry x-agent-games-signature: HMAC-SHA256 over the RAW body.
 *    Verified BEFORE parsing JSON. Mismatch -> 401, no processing.
 *  - Responses are signed with x-agent-games-signature over the raw response body.
 *  - Preflight: { type: "agent-games.preflight.v1", ... } -> { ok: true, protocolVersion: "v1" }.
 *  - Task: { type: "agent-games.proof-gatekeeper.v1", task_id, input: {...} }
 *    -> { decision, reason_code, proof_tx, proof, public_signals } within 60s.
 *  - Fail closed: any timeout, error, or uncertainty -> REJECT, never approve by default.
 *
 * Env vars:
 *   PORT (default 3000), AGENT_GAMES_HMAC_SECRET (required in production;
 *   placeholder allowed locally with a loud warning), SEEN_FILE (default ./seen.json),
 *   WASM_PATH, ZKEY_PATH, PROOF_TIMEOUT_MS (default 45000), FIXED_SALT (tests only).
 *
 * No secrets are ever logged. The HMAC secret is read from the environment only.
 */
const http = require('node:http');
const crypto = require('node:crypto');
const { decide, REASON } = require('./decide');
const { SeenSet } = require('./seen');
const { generateProof } = require('./prove');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const SEEN_FILE = process.env.SEEN_FILE || './seen.json';
const PROOF_TIMEOUT_MS = parseInt(process.env.PROOF_TIMEOUT_MS || '45000', 10);
const MAX_BODY_BYTES = 1024 * 1024;

if (!HMAC_SECRET) {
  console.error(JSON.stringify({ level: 'warn', msg: 'AGENT_GAMES_HMAC_SECRET is unset — using dev placeholder; DO NOT register this instance' }));
}
const SECRET = HMAC_SECRET || 'dev-placeholder-secret-do-not-register';

const seen = new SeenSet(SEEN_FILE);

// Serialize proof generation: the prover is CPU-heavy; queue tasks instead of
// running them concurrently so each stays inside the 60s deadline.
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
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error('body too large'));
        req.destroy();
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
    const { proof, publicSignals } = await enqueueProve(() =>
      withTimeout(generateProof(result.fields, proofBit, taskId), PROOF_TIMEOUT_MS, 'proof generation'));
    log({ task_id: taskId, decision: result.decision, reason_code: result.reason_code, proof_tx: proofTxOut, ms: Date.now() - started, proof: 'generated' });
    return { decision: result.decision, reason_code: result.reason_code, proof_tx: proofTxOut, proof, public_signals: publicSignals };
  } catch (err) {
    // Proof generation failed: fail closed. A REJECT without a valid proof is
    // still the platform-prescribed behavior ("reject on uncertainty").
    log({ level: 'error', task_id: taskId, decision: 'REJECT', reason_code: 'PROOF_GENERATION_FAILED', proof_tx: proofTxOut, ms: Date.now() - started, proof: 'failed', error: String(err.message).slice(0, 200) });
    return { decision: 'REJECT', reason_code: 'PROOF_GENERATION_FAILED', proof_tx: proofTxOut, proof: null, public_signals: [] };
  }
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && (req.url === '/health' || req.url === '/')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, service: 'proof-gatekeeper', seen: seen.size }));
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
      log({ level: 'warn', msg: 'signature verification failed', path: req.url });
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
});

server.listen(PORT, () => {
  log({ msg: 'listening', port: PORT, seen_entries: seen.size, hmac: HMAC_SECRET ? 'env-secret' : 'PLACEHOLDER' });
});

module.exports = { server };
