# Security model, implementation limits and prohibited claims

This project is a **research demonstrator**. Do not connect it to a real blockchain, hold live funds, expose its TCP ports to the Internet or describe it as production-ready.

## Security objectives verified experimentally

- The active committee has **16 independent OS processes**, with a reconstruction threshold of **11**. A 16-node block demo and attack demo were exercised.
- The public gateway accepts encrypted, locally authenticated envelopes and refuses the exact malicious ciphertext modification used in our attack test.
- In the modeled finality rule, honest committee nodes only release per-ciphertext DH shares after seeing a valid **11-signature** finality certificate for an ordered batch; a non-voting node can also verify the signed certificate and contribute its share.
- In tests, 5 unavailable nodes allow an 11-of-16 quorum; 6 unavailable nodes cause failure. Withholding and invalid partial proofs can be rejected when the remaining honest responses reach quorum.
- Outside-the-batch pending ciphertexts receive no partial decryption shares from the secure committee (unless 11 committee members collude outside the protocol).

## Cryptographic implementation

`crypto.py` implements from scratch the **threshold logic**: Shamir polynomial secret distribution, Feldman verification commitments, subgroup and ciphertext validation, Schnorr-style Fiat–Shamir proof of randomness bound to the envelope, partial ElGamal DH decryption, Chaum–Pedersen equal-discrete-log proofs, Lagrange coefficients, and share aggregation. It uses a 2048-bit MODP prime and an order-q subgroup. AES-256-GCM, HKDF, SHA-256/SHA-512, and Ed25519 primitives use the `cryptography` library.

These choices are educational. The Fiat–Shamir proof / hybrid scheme is **not accompanied by an IND-CCA2 proof**, a side-channel audit, or a security review. In particular, do not equate the observed rejection of one bit-flip attack with resistance to all chosen-ciphertext attacks.

## Architecture limitations

1. **No genuine optimized BTE in live protocol.** The measured pipeline uses *per-transaction* partial decryptions and **O(nB)** share traffic; it is not the pairing-based BTE schemes of USENIX 2024, BEAT-MEV or BTX. The `btx_algebra.py` model recreates BTX's batching equations but exposes group exponents directly: anybody can recover toy plaintext without committee shares. It is explicitly insecure and **not used** by any real transaction.
2. **Not real BFT consensus.** A coordinator proposes batches and collects at least 11 Ed25519 committee signatures. This models finality after order fixation, without view change, ledger synchrony, leader rotation, network adversaries, or the guarantees of a deployed consensus system.
3. **Dealer-assisted key setup.** During setup, the dealer has the entire key and all shares. `keystore.py` stores all those shares together in one password-encrypted development file; this is NOT DKG, distributed recovery or hardware security.
4. **Localhost TCP only, no TLS.** The API is unauthenticated, and priorities are client-supplied. The gateway is not a production mempool's spam prevention, payment, replay prevention, access controls, or execution environment.
5. **Fault-injection administrative RPC.** A research-only `test_config` request, authenticated with a random coordinator-held token over localhost, can change simulated node faults. It is not part of a secure production protocol.
6. **Committee collusion.** Any >=11 nodes colluding can decrypt early. The protocol cannot cryptographically prevent off-protocol key disclosure.
6. **Metadata leaks.** Envelope metadata and submission timing are observable. Privacy experiments are synthetic and do not establish empirical real-world unlinkability.
7. **Partial execution recovery (hardened v3).** Once a block has finality, its transactions are marked `finalized_unopened`. The exact finalized body and signing certificate are persisted in SQLite, and the next `mine` call or `Coordinator.recover_unopened()` requests verified shares for that same finalized block, including after an application restart with the same keystore. This is recovery under a trusted coordinator and simulated finality, not crash-safe distributed BFT consensus. Node voting locks remain memory-only.
8. **Timing and benchmarks.** Python multiprocess localhost measurements are workload- and machine-specific. Older benchmark files from v1 are retained separately and not pooled with fresh v2 values.
9. **Toy attacks only.** The vulnerable endpoint is explicitly configured with `allow_naive=True` and demonstrates an *attack class* from Choudhuri et al.; it does not demonstrate a new vulnerability in current Shutter, BEAT-MEV, F3B or Aptos.
10. **Not economically MEV-free.** Encryption can reduce content-dependent frontrunning, not arbitrary censorship, known-transaction MEV, post-finality arbitrage, metadata-guided selection, side channels or early threshold collusion.

## Allowed claims

- “We independently implemented and tested a 16-node threshold-ElGamal encrypted-mempool research prototype.”
- “The prototype demonstrates a published-class malleability attack and epoch-wide release leak in deliberately insecure variants, through the committee network, while the defended variant rejects the tested attack.”
- “The implementation measures its own end-to-end critical path and documents O(nB) overhead.”
- “The BTX algebra file demonstrates the *equations* for aggregate shares, not pairing-based cryptographic security.”

## Claims NOT supported

- “A cryptographically secure, optimized O(n) batched-threshold encryption implementation is complete.”
- “The project implements BEAT-MEV or BTX's full security proofs.”
- “We have proven CCA2/UC security or censorship resistance.”
- “16-node quorum signatures are equivalent to a deployed BFT consensus.”
- “The measured latency implies real Ethereum mainnet or Aptos network performance.”

## Security audit follow-up (hardened v3)

The original v2 accepted alternate numeric Schnorr-proof encodings and unknown proof fields, allowing transaction-id clones. v3 enforces exact JSON field schemas and canonical integer representations, hashes parsed proof values, rejects duplicate ephemeral `u` values for defended ciphertexts, and tests these attacks at both the parser and 16-node network level. The deliberately naive demonstration remains vulnerable by design. The patch is not a formal chosen-ciphertext security proof.

The coordinator now stops at the first t **cryptographically verified** votes and release bundles and retries exactly the same blocked proposal, not a randomly re-encrypted alternative. A finalized-unopened block is recovered from its persisted certificate. See `HARDENING_REPORT.md` for reproducible evidence, measurement caveats, and limitations.
