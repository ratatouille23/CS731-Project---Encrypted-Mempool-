# ShieldedMempool v2 — Change log and assignment compliance

This archive extends the previous `ShieldedMempool_Complete_Project.zip` rather than discarding its cryptographic implementation.

## Added in v2

1. **Actual encrypted mempool:** SQLite pending queue with duplicate suppression, validated submissions, FIFO/priority selection, finalized/included statuses and excluded-transaction rollover.
2. **External gateway and client:** TCP JSON operations for key discovery, encrypted submission, mining, status and pending identifiers.
3. **Restartable local demonstration:** password-encrypted trusted-dealer keystore, tied to the SQLite queue's committee public key and recorded block height.
4. **Attack through real nodes:** malleated ciphertext is submitted, selected, finalized and decrypted by the actual 16-process network; original victim remains excluded. A naive epoch-key-release variant also leaks the pending transaction.
5. **Defended counterexample:** authenticated-envelope and randomness-proof validation refuses this tampering before a committee vote; key-release debug RPC disabled in secure mode.
6. **BTE mathematics:** additional **insecure** symbolic BTX algebra and BEAT-MEV-style index-collision scheduling model. These illustrate published approaches without falsely claiming secure pairing-based batching.
7. **Queue-based benchmark:** measurements for B=1,2,4 with timing and communication breakdown.
8. **Improved fault runner:** seven failures injected over one continuously running 16-process committee.
9. **Synthetic MEV market example:** deterministic constant-product sandwich, with no real-money claims.
10. **Documentation:** mathematical derivations, source mapping, protocol, security caveats and reproducible commands.

## Requirement audit

| Assignment item | v2 result |
|---|---|
| Encrypt mempool transactions to committee public key | Implemented |
| Keep pending queue and select transactions for blocks | Implemented (SQLite) |
| Reveal only after fixed ordering | Implemented under a threshold signature-finality simulator |
| Key generation, partial decryption and share combination implemented ourselves | Implemented |
| >=16 nodes | Verified 16 separate processes, t=11 |
| End-to-end latency per block | Measured for 1,2,4 tx with phase breakdown |
| One published attack against a deliberately naive variant and mitigation | Integrated attack-class reproduction and secure-variant rejection |
| Genuine efficient pairing-based O(n) batch threshold encryption | **NOT implemented**; separate algebra-only model is explicitly insecure |
| Real BFT consensus, DKG, peer transport authentication | **NOT implemented**; out of prototype scope |

The last two rows must remain explicit in a course presentation: the project is an end-to-end encrypted-mempool research prototype, not a reimplementation or security proof of the USENIX/BEAT-MEV/BTX optimized BTE cryptosystem.
