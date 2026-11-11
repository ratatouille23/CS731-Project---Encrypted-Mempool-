# Paper-to-code traceability (precise about what was borrowed)

This document separates **published ideas** from our **implemented realization** and identifies algorithms that are **not** implemented.

| Source | Research content | Our code | Fidelity |
|---|---|---|---|
| Rondelet & Kilbourn, 2023, arXiv 2307.10878 | Mempool privacy economics, validator incentives and metadata information asymmetries | `privacy.py`, `mev_sandbox.py`, background in README | Synthetic model; not a replication of their market study |
| Choudhuri, Garg, Piet & Policharla, USENIX Security 2024 | Batched threshold encryption (BTE) security notion; efficient O(n) aggregated communication; ciphertext malleability / pending transaction privacy failure classes | `insecure.py`, `network_attacks.py`, `attacks.py`, `crypto.py` | **Attack class reproduced**, NOT the exact upstream Shutter implementation, NOT paper's KZG-based BTE construction |
| Bormet, Faust, Othman & Qu, USENIX Security 2025 BEAT-MEV | Epochless BTE, puncturable PRF, index coordination and collision tradeoffs | `btx_algebra.index_collision_demo` | **Only a simplified scheduling/collision model**, not BEAT-MEV threshold encryption |
| Zhang et al., AFT 2023 F3B | Per-transaction symmetric encryption under threshold decryption, confidentiality until consensus finality, secret committee | `crypto.py` + `protocol.py` + `node.py` + `engine.py` | F3B-style architectural baseline; NOT a replication of their TDH2/PVSS implementation or production Ethereum integration |
| Agarwal et al., BTX (user-uploaded 2026 paper) | BTE aggregation equations, epochless collision-free encryption, fast pairing-based openings | `btx_algebra.py` | Correct **symbolic algebra** only; pairing-groups and secure ciphertext implementation are absent |

## Reference URLs

- Economics: https://arxiv.org/abs/2307.10878
- USENIX 2024: https://www.usenix.org/conference/usenixsecurity24/presentation/choudhuri
- BEAT-MEV 2025: https://www.usenix.org/conference/usenixsecurity25/presentation/bormet
- F3B 2023: https://doi.org/10.4230/LIPIcs.AFT.2023.3

## Explicit novelty statement

The project’s original contribution is **systems integration, instrumentation, fault simulation, and a reproducible in-network attack / mitigation comparison** on top of published cryptographic ideas. We do **not** claim a new encryption primitive, a new vulnerability, a novel formal security theorem, or production-grade blockchain integration.

The independently prepared 16-node prototype is useful for a course evaluation because it exercises the entire lifecycle and exposes performance/failure costs that a crypto-only library benchmark does not cover. Publication novelty would require a new mechanism or stronger external evidence.
