'use strict';
/**
 * lib/circuits.js — circuit artifact acquisition with verification.
 *
 * The gatekeeper circuit binaries (wasm + zkey) are NOT committed to the
 * repo. They are fetched from the official Agent Games site and verified
 * against the published sizes + SHA-256 (see CIRCUIT.md) before use.
 *
 * Two call sites:
 *  - scripts/fetch-circuits.js (Vercel build step): downloads into ./circuits/
 *    so the artifacts are bundled with the serverless function.
 *  - api/index.js (runtime fallback): if the bundled artifacts are missing at
 *    request time, downloads verified copies into /tmp/circuits/ on first use.
 *
 * No secrets here. Download failures throw — callers fail closed.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const https = require('node:https');
const path = require('node:path');

const BASE_URL = 'https://agentgames.zkverify.io/circuits/';

const ARTIFACTS = Object.freeze([
  {
    name: 'gatekeeper.wasm',
    bytes: 1755820,
    sha256: 'be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f',
  },
  {
    name: 'gatekeeper_final.zkey',
    bytes: 309750,
    sha256: 'adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d',
  },
]);

function sha256Hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function fileIsValid(filePath, artifact) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size !== artifact.bytes) return false;
    return sha256Hex(fs.readFileSync(filePath)) === artifact.sha256;
  } catch {
    return false;
  }
}

function download(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error('download ' + url + ' -> HTTP ' + res.statusCode));
        return;
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('download timed out after ' + timeoutMs + 'ms: ' + url)));
    req.on('error', reject);
  });
}

/**
 * Ensure both artifacts exist in `dir`, verified. Downloads any missing or
 * mismatched file from the official site. Returns { wasmPath, zkeyPath }.
 * Throws on download or verification failure.
 */
async function ensureCircuits(dir, opts = {}) {
  const timeoutMs = opts.timeoutMs || 30000;
  fs.mkdirSync(dir, { recursive: true });
  const out = {};
  for (const artifact of ARTIFACTS) {
    const filePath = path.join(dir, artifact.name);
    if (!fileIsValid(filePath, artifact)) {
      const data = await download(BASE_URL + artifact.name, timeoutMs);
      if (data.length !== artifact.bytes) {
        throw new Error(artifact.name + ': size mismatch (got ' + data.length + ', want ' + artifact.bytes + ')');
      }
      if (sha256Hex(data) !== artifact.sha256) {
        throw new Error(artifact.name + ': SHA-256 mismatch, refusing to use');
      }
      // Atomic write: tmp + rename, so a concurrent reader never sees a partial file.
      const tmp = filePath + '.tmp-' + process.pid;
      fs.writeFileSync(tmp, data);
      fs.renameSync(tmp, filePath);
    }
    out[artifact.name === 'gatekeeper.wasm' ? 'wasmPath' : 'zkeyPath'] = filePath;
  }
  return out;
}

module.exports = { ensureCircuits, fileIsValid, ARTIFACTS, BASE_URL };
