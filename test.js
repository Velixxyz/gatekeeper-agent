'use strict';
/**
 * test.js — local test harness. Spawns the server on a test port with a test
 * HMAC secret, replays 8 synthetic signed envelopes, and asserts decisions,
 * reason codes, response signatures, and (where a proof is included) real
 * Groth16 verification against the exported verification key.
 *
 * The 8 cases: 1 valid + 7 traps (6 named reason codes + the expiry-boundary
 * trap, current_block == expiry_block, which the circuit treats as expired).
 * Bonus checks (reported separately): preflight handshake, bad-HMAC 401,
 * malformed-envelope fail-closed.
 *
 * Usage: node test.js   (exit 0 = all pass)
 * Requires: circuits/gatekeeper.wasm, circuits/gatekeeper_final.zkey,
 *           circuits/verification_key.json (exported via snarkjs).
 */
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const snarkjs = require('snarkjs');

const PORT = 3457;
const SECRET = 'test-hmac-secret-12345';
const SEEN_FILE = path.join(__dirname, 'test-seen.json');
const BASE = `http://127.0.0.1:${PORT}`;
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
    proof_tx: '0xaaaa000000000000000000000000000000000000000000000000000000000001',
    ...overrides,
  };
}

const CASES = [
  { name: 'valid', env: envelope('gk_test_01', validInput()), decision: 'APPROVE', reason: 'VALID_CONDITION', verifyProof: true, proofDecisionBit: '1' },
  { name: 'vk_substitution', env: envelope('gk_test_02', validInput({ proof_vk: VK_B, proof_tx: '0xaaaa000000000000000000000000000000000000000000000000000000000002' })), decision: 'REJECT', reason: 'VK_SUBSTITUTION', verifyProof: true, proofDecisionBit: '0' },
  { name: 'threshold_mismatch', env: envelope('gk_test_03', validInput({ public_balance: '999', proof_tx: '0xaaaa000000000000000000000000000000000000000000000000000000000003' })), decision: 'REJECT', reason: 'THRESHOLD_MISMATCH', verifyProof: true, proofDecisionBit: '0' },
  { name: 'proof_reused', env: envelope('gk_test_04', validInput()), decision: 'REJECT', reason: 'PROOF_REUSED', verifyProof: true, proofDecisionBit: '1' /* proof attests evaluation; response is REJECT */ },
  { name: 'expired', env: envelope('gk_test_05', validInput({ current_block: 8430001, proof_tx: '0xaaaa000000000000000000000000000000000000000000000000000000000005' })), decision: 'REJECT', reason: 'EXPIRED_CONDITION', verifyProof: true, proofDecisionBit: '0' },
  { name: 'recipient_mismatch', env: envelope('gk_test_06', validInput({ condition_recipient: ADDR_B, proof_tx: '0xaaaa000000000000000000000000000000000000000000000000000000000006' })), decision: 'REJECT', reason: 'RECIPIENT_MISMATCH', verifyProof: true, proofDecisionBit: '0' },
  { name: 'amount_overflow', env: envelope('gk_test_07', validInput({ amount: '1001', proof_tx: '0xaaaa000000000000000000000000000000000000000000000000000000000007' })), decision: 'REJECT', reason: 'AMOUNT_OVERFLOW', verifyProof: true, proofDecisionBit: '0' },
  { name: 'expiry_boundary_current_eq_expiry', env: envelope('gk_test_08', validInput({ current_block: 8430000, proof_tx: '0xaaaa000000000000000000000000000000000000000000000000000000000008' })), decision: 'REJECT', reason: 'EXPIRED_CONDITION', verifyProof: true, proofDecisionBit: '0' },
];

function post(pathname, bodyObj, secretOverride) {
  const raw = Buffer.from(JSON.stringify(bodyObj), 'utf8');
  const sig = crypto.createHmac('sha256', secretOverride !== undefined ? secretOverride : SECRET).update(raw).digest('hex');
  return new Promise((resolve, reject) => {
    const req = http.request(BASE + pathname, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': sig },
      timeout: 90000,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const rawRes = Buffer.concat(chunks);
        let json = null;
        try { json = JSON.parse(rawRes.toString('utf8')); } catch { /* keep null */ }
        resolve({ status: res.statusCode, headers: res.headers, raw: rawRes, json });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('request timeout')));
    req.end(raw);
  });
}

function verifyResponseSignature(res) {
  const expected = crypto.createHmac('sha256', SECRET).update(res.raw).digest('hex');
  const got = res.headers['x-agent-games-signature'];
  return typeof got === 'string' && crypto.timingSafeEqual(Buffer.from(got), Buffer.from(expected));
}

async function waitForHealth(serverProc, tries = 40) {
  for (let i = 0; i < tries; i++) {
    try {
      await new Promise((resolve, reject) => {
        http.get(BASE + '/health', { timeout: 2000 }, (res) => { res.resume(); resolve(); }).on('error', reject);
      });
      return;
    } catch { await new Promise((r) => setTimeout(r, 500)); }
    if (serverProc.exitCode !== null) throw new Error('server exited early with code ' + serverProc.exitCode);
  }
  throw new Error('server did not become healthy');
}

async function main() {
  if (fs.existsSync(SEEN_FILE)) fs.unlinkSync(SEEN_FILE);
  const serverProc = spawn('node', ['server.js'], {
    cwd: __dirname,
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET, SEEN_FILE, FIXED_SALT: '99' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  serverProc.stdout.on('data', (d) => { serverLog += d.toString(); });
  serverProc.stderr.on('data', (d) => { serverLog += d.toString(); });

  const results = [];
  const check = (name, ok, detail) => {
    results.push({ name, ok, detail: detail || '' });
    console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (detail ? '  — ' + detail : ''));
  };

  try {
    await waitForHealth(serverProc);

    for (const c of CASES) {
      const t0 = Date.now();
      const res = await post('/task', c.env);
      const ms = Date.now() - t0;
      const okStatus = res.status === 200;
      const okDecision = res.json && res.json.decision === c.decision;
      const okReason = res.json && res.json.reason_code === c.reason;
      const okSig = verifyResponseSignature(res);
      let okProof = true;
      let proofDetail = '';
      if (c.verifyProof) {
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
      }
      const ok = okStatus && okDecision && okReason && okSig && okProof;
      check(c.name, ok, `status=${res.status} decision=${res.json && res.json.decision} reason=${res.json && res.json.reason_code} sig=${okSig} ${proofDetail} ${ms}ms`);
    }

    // Bonus: preflight handshake
    {
      const res = await post('/task', { type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: '2026-11-13T00:00:00Z', nonce: 'abc123' });
      check('preflight', res.status === 200 && res.json && res.json.ok === true && res.json.protocolVersion === 'v1' && verifyResponseSignature(res),
        JSON.stringify(res.json));
    }
    // Bonus: bad HMAC -> 401
    {
      const res = await post('/task', CASES[0].env, 'wrong-secret');
      check('bad_hmac_401', res.status === 401, 'status=' + res.status);
    }
    // Bonus: malformed envelope -> fail-closed REJECT
    {
      const bad = envelope('gk_test_09', validInput({ amount: undefined, proof_tx: '0xaaaa000000000000000000000000000000000000000000000000000000000009' }));
      delete bad.input.amount;
      const res = await post('/task', bad);
      check('malformed_fail_closed', res.status === 200 && res.json && res.json.decision === 'REJECT' && res.json.reason_code === 'INVALID_ENVELOPE',
        `decision=${res.json && res.json.decision} reason=${res.json && res.json.reason_code}`);
    }
  } finally {
    serverProc.kill('SIGTERM');
    await new Promise((r) => setTimeout(r, 500));
    if (fs.existsSync(SEEN_FILE)) fs.unlinkSync(SEEN_FILE);
  }

  const failed = results.filter((r) => !r.ok);
  console.log('\n' + (results.length - failed.length) + '/' + results.length + ' checks passed.');
  if (failed.length > 0) {
    console.log('--- server log (last 3000 chars) ---\n' + serverLog.slice(-3000));
    process.exit(1);
  }
  process.exit(0); // explicit exit: spawned-child stdio handles can otherwise keep the loop alive
}

main().catch((e) => { console.error('HARNESS ERROR:', e); process.exit(2); });
