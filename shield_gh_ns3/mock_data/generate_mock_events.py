#!/usr/bin/env python3
"""
SHIELD-GH NS-3 Mock Data Generator
====================================
Generates realistic vehicle_events.jsonl files that match the NS-3 output schema.
Use this while NS-3 is being set up, or to test the connection to SHIELD-GH.

Requirements:
    pip install numpy

Usage:
    python generate_mock_events.py                    # generate all variants
    python generate_mock_events.py --variant S1_DP_FR # single variant
    python generate_mock_events.py --send --host 192.168.1.X  # generate + send immediately
"""

import json
import random
import argparse
import sys
from pathlib import Path

try:
    import numpy as np
except ImportError:
    print("[ERROR] numpy not installed. Run: pip install numpy")
    sys.exit(1)

# ── Attack variant configurations ────────────────────────────────────────────
ATTACK_CONFIGS = {
    "BENIGN":   {"drop": 0.00, "intermittent": False, "target_src": False},
    "S1_DP_FR": {"drop": 0.50, "intermittent": False, "target_src": False},
    "S2_DP_IT": {"drop": 0.50, "intermittent": True,  "target_src": False},
    "S3_DP_TS": {"drop": 0.50, "intermittent": False, "target_src": True},
    "S4_CP_FR": {"drop": 0.50, "intermittent": False, "target_src": False},
    "S5_CP_IT": {"drop": 0.50, "intermittent": True,  "target_src": False},
    "S6_CP_TS": {"drop": 0.50, "intermittent": False, "target_src": True},
}

RSU_ZONES = [(0, 350, "RSU_01"), (350, 650, "RSU_02"), (650, 1000, "RSU_03")]


def get_rsu(x_pos: float) -> str:
    for lo, hi, rsu in RSU_ZONES:
        if lo <= x_pos < hi:
            return rsu
    return "RSU_03"


def generate_run(variant: str, drop_rate: float, seed: int,
                 n_vehicles: int = 8, duration: float = 60.0, dt: float = 1.0) -> list:
    random.seed(seed)
    np.random.seed(seed)

    cfg = ATTACK_CONFIGS[variant]
    attacker_id = 3 if variant != "BENIGN" else -1

    positions = [50.0 + i * 100.0 for i in range(n_vehicles)]
    speeds    = np.random.uniform(50, 90, n_vehicles)   # km/h

    events = []
    t = 1.0
    while t <= duration:
        for vid in range(n_vehicles):
            positions[vid] += speeds[vid] / 3.6 * dt
            if positions[vid] > 1000:
                positions[vid] = 0.0

            rsu_id   = get_rsu(positions[vid])
            prev_rsu = get_rsu(max(0.0, positions[vid] - speeds[vid] / 3.6 * dt))
            handoff  = (rsu_id != prev_rsu)

            base_pdr = float(np.random.uniform(0.85, 0.99))
            if handoff:
                base_pdr *= float(np.random.uniform(0.75, 0.90))

            # Apply attack logic
            is_attacker = (vid == attacker_id)
            if is_attacker:
                attack_active = True
                if cfg["intermittent"]:
                    attack_active = (int(t / 10) % 2 == 1)
                if attack_active:
                    effective_drop = drop_rate
                    if cfg["target_src"]:
                        src = (vid - 1) % n_vehicles
                        effective_drop = drop_rate if src == 1 else 0.0
                    base_pdr = max(0.0, base_pdr - effective_drop
                                   + float(np.random.normal(0, 0.02)))

            n_rx  = random.randint(8, 15)
            n_fwd = max(0, min(n_rx, int(n_rx * base_pdr + np.random.normal(0, 0.5))))
            pdr   = n_fwd / n_rx if n_rx > 0 else 1.0

            events.append({
                "node_id":            vid,
                "timestamp":          round(t, 3),
                "packets_received":   n_rx,
                "packets_forwarded":  n_fwd,
                "pdr":                round(pdr, 4),
                "speed_kmh":          round(float(speeds[vid]), 1),
                "rsu_id":             rsu_id,
                "flow_id":            f"flow_{vid}",
                "is_handoff":         handoff,
                "src_vehicle":        (vid - 1) % n_vehicles,
                "dst_vehicle":        (vid + 1) % n_vehicles,
                "ground_truth_label": variant if is_attacker else "BENIGN",
                "is_attacker":        is_attacker,
            })
        t += dt

    return events


def send_to_shield_gh(host: str, events: list):
    try:
        import requests
    except ImportError:
        print("[ERROR] requests not installed. Run: pip install requests")
        sys.exit(1)

    url = f"http://{host}/api/ns3/events"
    print(f"Sending {len(events)} events to {url} ...")
    r = requests.post(url, json=events, timeout=30)
    r.raise_for_status()
    result = r.json()
    print(f"[OK] {result}")
    print()
    print("Now on the SHIELD-GH machine run:")
    print("  docker compose run --rm pipeline python "
          "shield_gh_blockchain/mock_mode/run_mock_pipeline.py /app/ns3_input/events.jsonl")
    print("  docker compose run --rm pipeline python "
          "shield_gh_fl/mock_mode/run_mock_fl.py")


def main():
    parser = argparse.ArgumentParser(description="SHIELD-GH NS-3 mock data generator")
    parser.add_argument("--variant",  default=None,
                        help="Single variant to generate (default: all 7)")
    parser.add_argument("--drop",     type=float, default=0.50,
                        help="Drop rate for attacker (default: 0.50)")
    parser.add_argument("--seed",     type=int, default=1, help="Random seed")
    parser.add_argument("--send",     action="store_true",
                        help="Send generated events to SHIELD-GH via HTTP")
    parser.add_argument("--host",     default="localhost",
                        help="IP address of SHIELD-GH machine (use with --send)")
    args = parser.parse_args()

    out_dir = Path(__file__).parent / "output"
    out_dir.mkdir(exist_ok=True)

    variants = [args.variant] if args.variant else list(ATTACK_CONFIGS.keys())

    all_events = []
    for variant in variants:
        events = generate_run(variant, args.drop, args.seed)
        fpath  = out_dir / f"{variant}_drop{int(args.drop*100)}_seed{args.seed}.jsonl"
        with open(fpath, "w") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")
        print(f"[OK] {variant}: {len(events)} events → {fpath.name}")
        all_events.extend(events)

    combined = out_dir / "combined_events.jsonl"
    with open(combined, "w") as f:
        for ev in all_events:
            f.write(json.dumps(ev) + "\n")
    print(f"\n[COMBINED] {len(all_events)} events total → {combined}")

    if args.send:
        send_to_shield_gh(args.host, all_events)


if __name__ == "__main__":
    main()
