# Circuit artifacts

`gatekeeper.wasm` and `gatekeeper_final.zkey` are NOT committed here (binary
files). Download them from the official Agent Games site before running:

```sh
curl -O https://agentgames.zkverify.io/circuits/gatekeeper.wasm
curl -O https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
```

Verify the downloads (sizes + SHA-256 must match):

| File | Bytes | SHA-256 |
|---|---|---|
| `gatekeeper.wasm` | 1,755,820 | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `gatekeeper_final.zkey` | 309,750 | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |

```sh
sha256sum gatekeeper.wasm gatekeeper_final.zkey
```

`verification_key.json` in this folder was exported from the zkey with
snarkjs and IS committed. See `../CIRCUIT.md` for the reverse-engineered
circuit model.
