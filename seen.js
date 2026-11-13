'use strict';
/**
 * seen.js — persistent replay-protection set for proof_tx references.
 * Stored as JSON: { "<proof_tx lowercase hex, no 0x>": { task_id, decided_at, decision } }
 * Writes are atomic (tmp file + rename). No secrets are ever stored here.
 */
const fs = require('node:fs');
const path = require('node:path');

class SeenSet {
  constructor(filePath) {
    this.filePath = filePath;
    this.map = new Map();
    this.load();
  }

  load() {
    try {
      const raw = fs.readFileSync(this.filePath, 'utf8');
      const obj = JSON.parse(raw);
      if (obj && typeof obj === 'object') {
        for (const [k, v] of Object.entries(obj)) this.map.set(k, v);
      }
    } catch (err) {
      if (err.code !== 'ENOENT') {
        console.error(JSON.stringify({ level: 'warn', msg: 'seen-set load failed, starting empty', error: String(err.message) }));
      }
    }
  }

  save() {
    const dir = path.dirname(this.filePath);
    fs.mkdirSync(dir, { recursive: true });
    const tmp = this.filePath + '.tmp-' + process.pid;
    fs.writeFileSync(tmp, JSON.stringify(Object.fromEntries(this.map), null, 1) + '\n', 'utf8');
    fs.renameSync(tmp, this.filePath);
  }

  /** True if proofTxKey was recorded under a DIFFERENT task_id (redelivery of the same task is not reuse). */
  isReused(proofTxKey, taskId) {
    const rec = this.map.get(proofTxKey);
    return !!rec && rec.task_id !== taskId;
  }

  record(proofTxKey, taskId, decision) {
    if (!this.map.has(proofTxKey)) {
      this.map.set(proofTxKey, { task_id: taskId, decided_at: new Date().toISOString(), decision });
      this.save();
    }
  }

  get size() { return this.map.size; }
}

module.exports = { SeenSet };
