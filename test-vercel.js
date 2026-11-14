'use strict';
/**
 * test-vercel.js — local harness for the Vercel serverless handler (api/index.js).
 * Invokes the handler directly with mock Node req/res streams (the same shape
 * Vercel passes to Node functions), replays the same 8 signed synthetic
 * envelopes as test.js, and verifies every returned proof against the
 * exported verification key. No HTTP server, no network.
 *
 * Two phases:
 *  A. Circuit paths via WASM_PATH/ZKEY_PATH env (explicit-override path).
 *  B. No env paths: handler must resolve the bundled ./circuits/ artifacts
 *     relative to the function file (the path production uses on Vercel).
 *
 * Usage: node test-vercel.js   (exit 0 = all pass)
 * Requires: circuits/gatekeeper.wasm, circuits/gatekeeper_final.zkey,
 *           circuits/verification_key.json.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Readable } = require('node:stream');
const snarkjs = require('snarkjs');

const SECRET = 'test-hmac-secret-12345';
const VK = JSON.parse(fs.readFileSync(path.join(__dirname, 'circuits', 'verification_key.json'), 'utf8'));

const VK_A = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const VK_B = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const ADDR_A = '0x1111111111111111111111111111111111111111';
const ADDR_B = '0x2222222222222222222222222222222222222222';

function envelope(taskId, input) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode: 'competition',
    issued_at: '2026-11-13T00:00:00Z',
    deadline_at: '2026-11-13T00:01:00Z',
    input,
  };
}

function validInput(overrides = {}) {
  return {
    registered_vk: VK_A, proof_vk: VK_A,
    minimum: '1000', public_balance: '1460',
    expiry_block: 8430000, current_block: 8420000,
    recipient: ADDR_A, condition_recipient: ADDR_A,
    amount: '500', max_transfer: '1000',
    proof_tx: '0xbbbb000000000000000000000000000000000000000000000000000000000001',
    ...overrides,
  };
}

const CASES = [
  { name: 'valid', env: envelope('gk_vtest_01', validInput()), decision: 'APPROVE', reason: 'VALID_CONDITION', proofDecisionBit: '1' },
  { name: 'vk_substitution', env: envelope('gk_vtest_02', validInput({ proof_vk: VK_B, proof_tx: '0xbbbb000000000000000000000000000000000000000000000000000000000002' })), decision: 'REJECT', reason: 'VK_SUBSTITUTION', proofDecisionBit: '0' },
  { name: 'threshold_mismatch', env: envelope('gk_vtest_03', validInput({ public_balance: '999', proof_tx: '0xbbbb000000000000000000000000000000000000000000000000000000000003' })), decision: 'REJECT', reason: 'THRESHOLD_MISMATCH', proofDecisionBit: '0' },
  { name: 'proof_reused', env: envelope('gk_vtest_04', validInput()), decision: 'REJECT', reason: 'PROOF_REUSED', proofDecisionBit: '1' /* proof attests evaluation; response is REJECT */ },
  { name: 'expired', env: envelope('gk_vtest_05', validInput({ current_block: 8430001, proof_tx: '0xbbbb000000000000000000000000000000000000000000000000000000000005' })), decision: 'REJECT', reason: 'EXPIRED_CONDITION', proofDecisionBit: '0' },
  { name: 'recipient_mismatch', env: envelope('gk_vtest_06', validInput({ condition_recipient: ADDR_B, proof_tx: '0xbbbb000000000000000000000000000000000000000000000000000000000006' })), decision: 'REJECT', reason: 'RECIPIENT_MISMATCH', proofDecisionBit: '0' },
  { name: 'amount_overflow', env: envelope('gk_vtest_07', validInput({ amount: '1001', proof_tx: '0xbbbb000000000000000000000000000000000000000000000000000000000007' })), decision: 'REJECT', reason: 'AMOUNT_OVERFLOW', proofDecisionBit: '0' },
  { name: 'expiry_boundary_current_eq_expiry', env: envelope('gk_vtest_08', validInput({ current_block: 8430000, proof_tx: '0xbbbb000000000000000000000000000000000000000000000000000000000008' })), decision: 'REJECT', reason: 'EXPIRED_CONDITION', proofDecisionBit: '0' },
];

function mockReq({ method, url, bodyBuffer, secret }) {
  const sig = secret !== undefined
    ? crypto.createHmac('sha256', secret).update(bodyBuffer).digest('hex')
    : undefined;
  const stream = new Readable({
    read() {
      this.push(bodyBuffer.length ? bodyBuffer : null);
      if (bodyBuffer.length) { bodyBuffer = Buffer.alloc(0); }
    },
  });
  stream.method = method;
  stream.url = url;
  stream.headers = sig ? { 'x-agent-games-signature': sig, 'content-type': 'application/json' } : {};
  return stream;
}

function mockRes() {
  const res = {
    statusCode: 0,
    headers: {},
    chunks: [],
    writeHead(status, headers) { this.statusCode = status; Object.assign(this.headers, headers); },
    setHeader(k, v) { this.headers[k] = v; },
    end(body) {
      if (body) this.chunks.push(Buffer.isBuffer(body) ? body : Buffer.from(body));
      this.finished = true;
      if (this.onFinish) this.onFinish();
    },
  };
  return res;
}

async function invoke(handler, req) {
  const res = mockRes();
  const done = new Promise((resolve) => { res.onFinish = resolve; });
  await handler(req, res);
  await done;
  const raw = Buffer.concat(res.chunks);
  let json = null;
  try { json = JSON.parse(raw.toString('utf8')); } catch { /* keep null */ }
  return { status: res.statusCode, headers: res.headers, raw, json };
}

function verifyResponseSignature(res) {
  const expected = crypto.createHmac('sha256', SECRET).update(res.raw).digest('hex');
  const got = res.headers['x-agent-games-signature'];
  return typeof got === 'string' && got.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(got), Buffer.from(expected));
}

function loadHandlerFresh() {
  for (const key of Object.keys(require.cache)) {
    if (key.includes('/api/index.js') || key.endsWith('/decide.js') || key.endsWith('/prove.js') || key.includes('/lib/circuits.js')) {
      delete require.cache[key];
    }
  }
  return require('./api/index.js');
}

async function runSuite(handler, label, results, check) {
  // Health check (no auth).
  {
    const res = await invoke(handler, mockReq({ method: 'GET', url: '/api', bodyBuffer: Buffer.alloc(0) }));
    check(label + ':health', res.status === 200 && res.json && res.json.ok === true && res.json.service === 'proof-gatekeeper',
      'status=' + res.status + ' ' + JSON.stringify(res.json));
  }
  for (const c of CASES) {
    const t0 = Date.now();
    const raw = Buffer.from(JSON.stringify(c.env), 'utf8');
    const res = await invoke(handler, mockReq({ method: 'POST', url: '/api', bodyBuffer: raw, secret: SECRET }));
    const ms = Date.now() - t0;
    const okStatus = res.status === 200;
    const okDecision = res.json && res.json.decision === c.decision;
    const okReason = res.json && res.json.reason_code === c.reason;
    const okSig = verifyResponseSignature(res);
    let okProof = true;
    let proofDetail = '';
    if (!res.json || !res.json.proof || !Array.isArray(res.json.public_signals)) {
      okProof = false; proofDetail = 'proof/public_signals missing';
    } else {
      try {
        okProof = await snarkjs.groth16.verify(VK, res.json.public_signals, res.json.proof);
        proofDetail = 'groth16.verify=' + okProof;
        if (okProof && res.json.public_signals[11] !== c.proofDecisionBit) {
          okProof = false; proofDetail += ', decision bit=' + res.json.public_signals[11] + ' expected ' + c.proofDecisionBit;
        }
      } catch (e) { okProof = false; proofDetail = 'verify threw: ' + String(e.message).slice(0, 120); }
    }
    const ok = okStatus && okDecision && okReason && okSig && okProof;
    check(label + ':' + c.name, ok, `status=${res.status} decision=${res.json && res.json.decision} reason=${res.json && res.json.reason_code} sig=${okSig} ${proofDetail} ${ms}ms`);
  }
  // Preflight handshake.
  {
    const raw = Buffer.from(JSON.stringify({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: '2026-11-13T00:00:00Z', nonce: 'abc123' }), 'utf8');
    const res = await invoke(handler, mockReq({ method: 'POST', url: '/api', bodyBuffer: raw, secret: SECRET }));
    check(label + ':preflight', res.status === 200 && res.json && res.json.ok === true && res.json.protocolVersion === 'v1' && verifyResponseSignature(res),
      JSON.stringify(res.json));
  }
  // Bad HMAC -> 401.
  {
    const raw = Buffer.from(JSON.stringify(CASES[0].env), 'utf8');
    const res = await invoke(handler, mockReq({ method: 'POST', url: '/api', bodyBuffer: raw, secret: 'wrong-secret' }));
    check(label + ':bad_hmac_401', res.status === 401, 'status=' + res.status);
  }
  // Malformed envelope -> fail-closed REJECT.
  {
    const bad = envelope('gk_vtest_09', validInput({ proof_tx: '0xbbbb000000000000000000000000000000000000000000000000000000000009' }));
    delete bad.input.amount;
    const raw = Buffer.from(JSON.stringify(bad), 'utf8');
    const res = await invoke(handler, mockReq({ method: 'POST', url: '/api', bodyBuffer: raw, secret: SECRET }));
    check(label + ':malformed_fail_closed', res.status === 200 && res.json && res.json.decision === 'REJECT' && res.json.reason_code === 'INVALID_ENVELOPE',
      `decision=${res.json && res.json.decision} reason=${res.json && res.json.reason_code}`);
  }
}

async function main() {
  const results = [];
  const check = (name, ok, detail) => {
    results.push({ name, ok, detail: detail || '' });
    console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (detail ? '  — ' + detail : ''));
  };

  // Phase A: explicit env circuit paths.
  process.env.AGENT_GAMES_HMAC_SECRET = SECRET;
  process.env.FIXED_SALT = '99';
  process.env.WASM_PATH = path.join(__dirname, 'circuits', 'gatekeeper.wasm');
  process.env.ZKEY_PATH = path.join(__dirname, 'circuits', 'gatekeeper_final.zkey');
  await runSuite(loadHandlerFresh(), 'A:env-paths', results, check);

  // Phase B: no env paths — bundled resolution relative to the function file.
  delete process.env.WASM_PATH;
  delete process.env.ZKEY_PATH;
  await runSuite(loadHandlerFresh(), 'B:bundled', results, check);

  const failed = results.filter((r) => !r.ok);
  console.log('\n' + (results.length - failed.length) + '/' + results.length + ' checks passed.');
  if (failed.length > 0) process.exit(1);
  process.exit(0);
}

main().catch((e) => { console.error('HARNESS ERROR:', e); process.exit(2); });
