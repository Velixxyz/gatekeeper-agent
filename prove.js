'use strict';
/**
 * prove.js — local Groth16 proof generation with snarkjs.
 *
 * Circuit model (reverse-engineered from the published artifacts, 13 Nov 2026;
 * see CIRCUIT.md for the evidence):
 *   Inputs (13 field elements): registeredVkHash, proofVkHash, minimum,
 *     publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
 *     amount, maxTransfer, decision, taskId (all public) + salt (PRIVATE).
 *   Public signals (13, in order): Poseidon([salt, taskId]) commitment,
 *     registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
 *     currentBlock, recipient, conditionRecipient, amount, maxTransfer,
 *     decision, taskId.
 *   Constraint: decision == (vk match AND balance >= minimum AND
 *     currentBlock < expiryBlock AND recipient match AND amount <= maxTransfer).
 *
 * No proof is ever faked: this module calls snarkjs groth16.fullProve with the
 * real wasm/zkey and returns the real proof + public signals, or throws.
 */
const crypto = require('node:crypto');
const path = require('node:path');
const snarkjs = require('snarkjs');
const { FIELD_PRIME } = require('./decide');
const { fileIsValid, ensureCircuits, ARTIFACTS } = require('./lib/circuits');

/**
 * Derive the circuit's taskId field element from the envelope's task_id string.
 * ASSUMPTION (practice-mode confirmation item): the platform's own taskId
 * encoding is not published. sha256(task_id) mod p is deterministic and
 * collision-resistant; if practice mode reveals a different encoding, only
 * this function needs to change.
 */
function deriveTaskId(taskIdString) {
  const hash = crypto.createHash('sha256').update(String(taskIdString), 'utf8').digest();
  return BigInt('0x' + hash.toString('hex')) % FIELD_PRIME;
}

/** Private salt: 31 random bytes (< 2^248, always < p). FIXED_SALT env overrides for deterministic tests. */
function makeSalt() {
  if (process.env.FIXED_SALT !== undefined && process.env.FIXED_SALT !== '') {
    const s = BigInt(process.env.FIXED_SALT);
    if (s < 0n || s >= FIELD_PRIME) throw new Error('FIXED_SALT out of field range');
    return s;
  }
  return BigInt('0x' + crypto.randomBytes(31).toString('hex'));
}

function buildCircuitInput(fields, decisionBit, taskIdString) {
  return {
    registeredVkHash: fields.registeredVkHash.toString(),
    proofVkHash: fields.proofVkHash.toString(),
    minimum: fields.minimum.toString(),
    publicBalance: fields.publicBalance.toString(),
    expiryBlock: fields.expiryBlock.toString(),
    currentBlock: fields.currentBlock.toString(),
    recipient: fields.recipient.toString(),
    conditionRecipient: fields.conditionRecipient.toString(),
    amount: fields.amount.toString(),
    maxTransfer: fields.maxTransfer.toString(),
    decision: String(decisionBit),
    taskId: deriveTaskId(taskIdString).toString(),
    salt: makeSalt().toString(), // PRIVATE — never logged, never returned
  };
}

/**
 * Generate a real Groth16 proof. Throws on any failure (caller fails closed).
 * @returns {{ proof: object, publicSignals: string[] }}
 */
/**
 * Resolve verified circuit artifacts. NEVER trust an env override blindly:
 * a stale PC-local WASM_PATH/ZKEY_PATH on Vercel would break every proof.
 * Order: explicit opts (if both files valid) -> env pair (if both valid) ->
 * bundled ./circuits/ next to this module (if valid) -> verified runtime
 * download to /tmp/circuits (memoized per instance). Every candidate is
 * checked by size + SHA-256. Throws only if no tier yields valid files.
 */
function artifactByName(name) {
  return ARTIFACTS.find((a) => a.name === name);
}

function pairIsValid(wasmPath, zkeyPath) {
  return !!wasmPath && !!zkeyPath
    && fileIsValid(wasmPath, artifactByName('gatekeeper.wasm'))
    && fileIsValid(zkeyPath, artifactByName('gatekeeper_final.zkey'));
}

let circuitsDownload = null;

async function resolveCircuits(opts = {}) {
  if (pairIsValid(opts.wasmPath, opts.zkeyPath)) {
    return { wasmPath: opts.wasmPath, zkeyPath: opts.zkeyPath };
  }
  if (pairIsValid(process.env.WASM_PATH, process.env.ZKEY_PATH)) {
    return { wasmPath: process.env.WASM_PATH, zkeyPath: process.env.ZKEY_PATH };
  }
  const bundledWasm = path.join(__dirname, 'circuits', 'gatekeeper.wasm');
  const bundledZkey = path.join(__dirname, 'circuits', 'gatekeeper_final.zkey');
  if (pairIsValid(bundledWasm, bundledZkey)) {
    return { wasmPath: bundledWasm, zkeyPath: bundledZkey };
  }
  if (!circuitsDownload) {
    circuitsDownload = ensureCircuits(path.join('/tmp', 'circuits'))
      .catch((err) => { circuitsDownload = null; throw err; });
  }
  return circuitsDownload;
}

async function generateProof(fields, decisionBit, taskIdString, opts = {}) {
  const { wasmPath, zkeyPath } = await resolveCircuits(opts);
  const input = buildCircuitInput(fields, decisionBit, taskIdString);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  return { proof, publicSignals: publicSignals.map(String) };
}

module.exports = { generateProof, deriveTaskId, makeSalt, buildCircuitInput };
