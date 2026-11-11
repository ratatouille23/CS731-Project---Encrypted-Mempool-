"""Controlled metadata/timing transaction-linkage study (not real-world trace data).

An observer knows plaintext preflight simulation traces at one RPC and sees
encrypted submissions. Objective: match each encrypted submission to a known
simulation. Model is intentionally explicit about observer visibility.
"""
from __future__ import annotations
import math
import random
import statistics


def _round_up(n: int, step: int) -> int:
    return ((n + step - 1) // step) * step


def simulate(policy: str, *, samples: int = 160, seed: int = 42) -> dict:
    if policy not in {"direct", "fixed_padding", "padding_jitter", "adaptive", "split_provider"}:
        raise ValueError("Unknown policy")
    rng = random.Random(seed)
    simulations, submissions = [], []
    base_delay = .07
    for ident in range(samples):
        # Fewer wallet/fee classes make metadata collisions realistic enough to
        # isolate side channels. This is a SYNTHETIC distribution, not production.
        sender = f"w{rng.randrange(12)}"
        fee = rng.randrange(3)
        plain_size = rng.randrange(96, 880)
        sim_time = rng.uniform(0, 8)
        sims = {"id": ident, "time": sim_time, "sender": sender, "fee": fee, "size": plain_size}
        simulations.append(sims)
        encrypted_size = plain_size + 36  # fixed ciphertext framing/AEAD overhead proxy
        submit_time = sim_time + base_delay + max(-.025, rng.gauss(0, .012))
        if policy == "fixed_padding":
            encrypted_size = _round_up(plain_size + 4, 512) + 32
        if policy == "padding_jitter":
            encrypted_size = _round_up(plain_size + 4, 512) + 32
            submit_time += rng.uniform(0, .75)
        if policy == "adaptive":
            # A heuristic privacy/performance policy to MEASURE, not a novel
            # cryptographic protection or demonstrated optimum.
            encrypted_size = _round_up(plain_size + 4, 512) + 32
            # More mixing for records sharing public metadata; nothing can
            # conceal truly unique revealed identity in this model.
            submit_time += rng.uniform(0, .55)
        if policy == "split_provider":
            # No preflight logs visible to this attacker under NONCOLLUSION.
            encrypted_size = plain_size + 36
        submissions.append({"id": ident, "time": submit_time, "sender": sender,
                            "fee": fee, "ciphertext_size": encrypted_size,
                            "extra_latency_ms": max(0.0, (submit_time-sim_time-base_delay) * 1000),
                            "padding_bytes": max(0, encrypted_size-(plain_size+36))})
    visible_sim = [] if policy == "split_provider" else simulations
    attack = link_attack(visible_sim, submissions, policy=policy)
    uniqueness = sum(1 for a in simulations if sum(1 for b in simulations if
                     b['sender'] == a['sender'] and b['fee'] == a['fee']) == 1) / max(samples, 1)
    return {
        "policy": policy, "samples": samples, "seed": seed,
        "observer_sees_plaintext_simulations": policy != "split_provider",
        "linked_fraction": attack["accuracy"],
        "linked_count": attack["matches"],
        "visible_simulation_count": len(visible_sim),
        "mean_added_delay_ms": round(statistics.mean(x["extra_latency_ms"] for x in submissions), 3),
        "mean_padding_bytes": round(statistics.mean(x["padding_bytes"] for x in submissions), 3),
        "unique_public_metadata_fraction": round(uniqueness, 4),
        "interpretation": ("Linkage accuracy is undefined: attacker cannot observe candidate plaintext simulations. "
                           "Security depends on providers not colluding." if policy == "split_provider" else
                           "Synthetic one-to-one timing+size+sender+fee linkage; low accuracy is not anonymity proof.")
    }


def link_attack(simulations: list[dict], submissions: list[dict], *, policy: str) -> dict:
    if not simulations:
        return {"matches": None, "accuracy": None}
    candidates = []
    for i, a in enumerate(simulations):
        for j, b in enumerate(submissions):
            if a['sender'] != b['sender'] or a['fee'] != b['fee']:
                continue
            delay = b['time'] - a['time']
            if delay < -0.1 or delay > 1.5:
                continue
            predicted = (a['size']+36 if policy == 'direct' else _round_up(a['size']+4,512)+32)
            size_penalty = abs(predicted - b['ciphertext_size']) / 24
            if policy in ('padding_jitter','adaptive'):
                time_penalty = abs(delay - (.35 if policy == 'padding_jitter' else .27)) / .26
            else:
                time_penalty = abs(delay - .07) / .035
            candidates.append((size_penalty + time_penalty, i, j))
    # Transparent greedy bipartite matching, NOT an optimal attacker. This
    # underestimates what more sophisticated linkage models might recover.
    candidates.sort()
    used_sim, used_sub = set(), set()
    correct = 0
    for _,i,j in candidates:
        if i not in used_sim and j not in used_sub:
            used_sim.add(i)
            used_sub.add(j)
            correct += simulations[i]['id'] == submissions[j]['id']
    return {"matches": correct, "accuracy": round(correct / len(submissions), 4)}


def experiment(samples: int = 160, seed: int = 42) -> list[dict]:
    return [simulate(p, samples=samples, seed=seed) for p in
            ("direct", "fixed_padding", "padding_jitter", "adaptive", "split_provider")]
