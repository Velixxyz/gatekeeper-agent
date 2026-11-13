'use strict';
/**
 * decide.js — pure, deterministic decision logic for the Proof Gatekeeper agent.
 *
 * Checks (in evaluation order — first failure wins the reason_code):
 *   1. VK_SUBSTITUTION   registered_vk != proof_vk   (compared as BN128 field elements, mod p)
 *   2. THRESHOLD_MISMATCH public_balance < minimum
 *   3. PROOF_REUSED       proof_tx seen before under a DIFFERENT task_id
 *   4. EXPIRED_CONDITION  current_block >= expiry_block  (STRICT: equality is expired —
 *                         verified against the circuit, GatekeeperEvaluation line 102)
 *   5. RECIPIENT_MISMATCH recipient != condition_recipient
 *   6. AMOUNT_OVERFLOW    amount > max_transfer
 * All pass -> APPROVE / VALID_CONDITION.
 *
 * Any missing / malformed / unparseable field -> REJECT / INVALID_ENVELOPE (fail closed).
 * This module never touches the network, the filesystem, or secrets.
 */

const FIELD_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

const REASON = Object.freeze({
  VALID: 'VALID_CONDITION',
  VK: 'VK_SUBSTITUTION',
  THRESHOLD: 'THRESHOLD_MISMATCH',
  REUSED: 'PROOF_REUSED',
  EXPIRED: 'EXPIRED_CONDITION',
  RECIPIENT: 'RECIPIENT_MISMATCH',
  AMOUNT: 'AMOUNT_OVERFLOW',
  INVALID: 'INVALID_ENVELOPE',
});

function parseUint(value) {
  // Accepts JSON numbers or decimal strings. Returns BigInt or null.
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) return null;
    return BigInt(value);
  }
  if (typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value.trim())) {
    try { return BigInt(value.trim()); } catch { return null; }
  }
  return null;
}

function parseHex(value, maxHexChars) {
  // Accepts "0x..." hex strings. Returns { raw: lowercased-no-prefix, value: BigInt } or null.
  if (typeof value !== 'string') return null;
  const m = /^0x([0-9a-fA-F]{1,64})$/.exec(value.trim());
  if (!m || m[1].length > maxHexChars) return null;
  try { return { raw: m[1].toLowerCase(), value: BigInt('0x' + m[1]) }; } catch { return null; }
}

/**
 * Validate + normalize the task envelope input.
 * Returns { ok: true, fields } or { ok: false, error }.
 */
function normalizeInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, error: 'input missing or not an object' };
  }
  const registeredVk = parseHex(input.registered_vk, 64);
  const proofVk = parseHex(input.proof_vk, 64);
  const recipient = parseHex(input.recipient, 40);
  const conditionRecipient = parseHex(input.condition_recipient, 40);
  const proofTx = parseHex(input.proof_tx, 64);
  const minimum = parseUint(input.minimum);
  const publicBalance = parseUint(input.public_balance);
  const expiryBlock = parseUint(input.expiry_block);
  const currentBlock = parseUint(input.current_block);
  const amount = parseUint(input.amount);
  const maxTransfer = parseUint(input.max_transfer);

  const missing = [];
  if (!registeredVk) missing.push('registered_vk');
  if (!proofVk) missing.push('proof_vk');
  if (!recipient) missing.push('recipient');
  if (!conditionRecipient) missing.push('condition_recipient');
  if (!proofTx) missing.push('proof_tx');
  if (minimum === null) missing.push('minimum');
  if (publicBalance === null) missing.push('public_balance');
  if (expiryBlock === null) missing.push('expiry_block');
  if (currentBlock === null) missing.push('current_block');
  if (amount === null) missing.push('amount');
  if (maxTransfer === null) missing.push('max_transfer');
  if (missing.length > 0) return { ok: false, error: 'invalid/missing fields: ' + missing.join(', ') };

  return {
    ok: true,
    fields: {
      // Field-element values (vk hashes reduced mod p, exactly as the circuit sees them).
      registeredVkHash: registeredVk.value % FIELD_PRIME,
      proofVkHash: proofVk.value % FIELD_PRIME,
      recipient: recipient.value,
      conditionRecipient: conditionRecipient.value,
      minimum, publicBalance, expiryBlock, currentBlock, amount, maxTransfer,
      proofTxKey: proofTx.raw, // canonical lowercase hex, no 0x prefix — seen-set key
    },
  };
}

/**
 * Evaluate the on-circuit checks (everything except replay).
 * Returns the first failing reason code, or null if all pass.
 */
function evaluateOnChainChecks(f) {
  if (f.registeredVkHash !== f.proofVkHash) return REASON.VK;
  if (f.publicBalance < f.minimum) return REASON.THRESHOLD;
  if (f.currentBlock >= f.expiryBlock) return REASON.EXPIRED; // strict <: equality is expired
  if (f.recipient !== f.conditionRecipient) return REASON.RECIPIENT;
  if (f.amount > f.maxTransfer) return REASON.AMOUNT;
  return null;
}

/**
 * Full decision.
 * @param {object} envelope - parsed task envelope ({ task_id, input })
 * @param {(proofTxKey: string, taskId: string) => boolean} isReused - seen-set lookup
 * @returns {{ decision: 'APPROVE'|'REJECT', reason_code: string, fields: object|null,
 *             evaluation: 0|1|null, error: string|null }}
 *   evaluation = what the CIRCUIT would say (1 = all on-circuit checks pass).
 *   For PROOF_REUSED with otherwise-valid fields, decision=REJECT but evaluation=1:
 *   the proof attests the evaluation; the response decision reflects the off-circuit
 *   replay check. See README.md "PROOF_REUSED and the proof" for the full reasoning.
 */
function decide(envelope, isReused) {
  const taskId = envelope && typeof envelope.task_id === 'string' ? envelope.task_id : null;
  if (!taskId) {
    return { decision: 'REJECT', reason_code: REASON.INVALID, fields: null, evaluation: null, error: 'task_id missing' };
  }
  const norm = normalizeInput(envelope.input);
  if (!norm.ok) {
    return { decision: 'REJECT', reason_code: REASON.INVALID, fields: null, evaluation: null, error: norm.error };
  }
  const f = norm.fields;
  const onChainFail = evaluateOnChainChecks(f);
  const evaluation = onChainFail === null ? 1 : 0;

  // Documented check order: VK, THRESHOLD, REUSED, EXPIRED, RECIPIENT, AMOUNT.
  if (onChainFail === REASON.VK) {
    return { decision: 'REJECT', reason_code: REASON.VK, fields: f, evaluation, error: null };
  }
  if (onChainFail === REASON.THRESHOLD) {
    return { decision: 'REJECT', reason_code: REASON.THRESHOLD, fields: f, evaluation, error: null };
  }
  if (isReused && isReused(f.proofTxKey, taskId)) {
    return { decision: 'REJECT', reason_code: REASON.REUSED, fields: f, evaluation, error: null };
  }
  if (onChainFail !== null) {
    return { decision: 'REJECT', reason_code: onChainFail, fields: f, evaluation, error: null };
  }
  return { decision: 'APPROVE', reason_code: REASON.VALID, fields: f, evaluation, error: null };
}

module.exports = { decide, normalizeInput, evaluateOnChainChecks, REASON, FIELD_PRIME };
