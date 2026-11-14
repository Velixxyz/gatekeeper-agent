'use strict';
/**
 * scripts/fetch-circuits.js — Vercel build step (see `vercel-build` in
 * package.json). Downloads the gatekeeper circuit artifacts from the
 * official Agent Games site into ./circuits/ and verifies sizes + SHA-256
 * before the serverless function is bundled, so the artifacts ship with the
 * deployment. Exits non-zero on any failure so a bad build never deploys.
 *
 * Safe to run locally too: skips downloads for files that already verify.
 */
const path = require('node:path');
const { ensureCircuits } = require('../lib/circuits');

async function main() {
  const dir = path.join(__dirname, '..', 'circuits');
  const { wasmPath, zkeyPath } = await ensureCircuits(dir);
  console.log('circuits ready:');
  console.log('  ' + wasmPath);
  console.log('  ' + zkeyPath);
}

main().catch((err) => {
  console.error('fetch-circuits FAILED: ' + err.message);
  process.exit(1);
});
