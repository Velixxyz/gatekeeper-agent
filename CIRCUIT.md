# Gatekeeper circuit — reverse-engineered model

Source: the published artifacts only (no `.circom`, `.sym`, or `.r1cs` is
served; all predictable URLs under `/circuits/` return 404, and no public
source repo was found). Everything below was determined empirically on
13 Nov 2026 from `gatekeeper.wasm` + `gatekeeper_final.zkey`.

## Artifacts

| File | Bytes | SHA-256 |
|---|---|---|
| `gatekeeper.wasm` | 1,755,820 | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `gatekeeper_final.zkey` | 309,750 | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |

- Protocol: Groth16 / BN128, Circom 2.x. Main template: `GatekeeperEvaluation`.
- Verification key exported with snarkjs: 13 public signals (`IC` length 14).
- `vkHash` from `/api/circuit-info`:
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
  (matches the published value; the exported VK was used for local verify).
- Witness size: 647 signals. Proving time on this VM: ~0.3–1.3s.

## Input signals (13, all size 1)

Recovered by probing the wasm's `getInputSignalSize` export with FNV-1a
hashes of candidate names (bogus names return 0; real signals return 1;
`setInputSignal` throws "Signal not found" for bogus names). Sum of sizes
= 13 = `getInputSize()`, so the set is complete:

```
registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
currentBlock, recipient, conditionRecipient, amount, maxTransfer,
decision, taskId, salt
```

Note the mixed naming: single-word names are bare (`minimum`, `recipient`,
`amount`, `decision`, `taskId`, `salt`); multi-word names are camelCase.
The envelope's snake_case field names (`public_balance`, `proof_vk`, …)
are NOT circuit input names.

## Public signals (13, in witness order)

```
[0]  Poseidon([salt, taskId])        — circuit output (commitment)
[1]  registeredVkHash
[2]  proofVkHash
[3]  minimum
[4]  publicBalance
[5]  expiryBlock
[6]  currentBlock
[7]  recipient
[8]  conditionRecipient
[9]  amount
[10] maxTransfer
[11] decision                        — 1 = APPROVE, 0 = REJECT
[12] taskId
```

`salt` is the only PRIVATE input (witness position 14, after the 13 public
signals). The commitment was confirmed as Poseidon with salt FIRST:
`Poseidon([salt, taskId])` reproduces witness signal 1 exactly for
(taskId, salt) ∈ {(1,0), (2,0), (1,1)} via circomlibjs.

## Constraint semantics (template line 102)

```
decision == (registeredVkHash == proofVkHash)
        AND (publicBalance >= minimum)
        AND (currentBlock < expiryBlock)     // STRICT — equality FAILS
        AND (recipient == conditionRecipient)
        AND (amount <= maxTransfer)
```

Verified by witness-generation trials (sanity check on):

| Trial | Result |
|---|---|
| all checks pass, decision=1 | witness OK |
| all checks pass, decision=0 | assert fail (line 102) |
| amount > max, decision=1 / decision=0 | fail / OK |
| vk mismatch, decision=1 / decision=0 | fail / OK |
| expired, decision=0 | OK |
| balance == minimum, decision=1 | OK (>= confirmed) |
| balance == minimum − 1, decision=1 / 0 | fail / OK |
| current == expiry, decision=1 | **FAIL** (strict `<` confirmed) |
| current == expiry + 1, decision=1 / 0 | fail / OK |
| amount == max, decision=1 | OK (<= confirmed) |
| amount == max + 1, decision=1 / 0 | fail / OK |
| recipient mismatch, decision=1 / 0 | fail / OK |
| taskId/salt varied (all else fixed) | OK; only signal [0] changes |

End-to-end: `snarkjs.groth16.fullProve` + `groth16.verify` against the
exported VK returns `true`, with public signals in the order above.

## Encoding notes

- vk hashes (32 bytes) exceed the BN128 field: the circuit sees them mod p.
  The agent compares vk equality as field elements (mod p) so the decision
  can never disagree with the circuit.
- Addresses (20 bytes) fit the field directly.
- `taskId` is a field element; the envelope's `task_id` is a string. The
  agent derives it as `sha256(task_id) mod p` — an assumption, flagged as a
  practice-mode confirmation item. The proof verifies regardless; only a
  platform cross-check of signal [12] could depend on the encoding.
- There is NO `proof_tx` input: replay protection is off-circuit by design
  (the agent's persistent seen-set). See README.md "PROOF_REUSED and the
  proof" for the consequence.
