#!/usr/bin/env python3
"""
NS-3 → SHIELD-GH Bridge
========================
Run this script on the NS-3 simulation machine to send vehicle events
to the SHIELD-GH dashboard running on another computer.

Requirements (friend's machine):
    pip install requests

Usage:
    python ns3_bridge.py --host 192.168.1.X --events vehicle_events.jsonl

Each line of vehicle_events.jsonl must be a JSON object with these fields:
    {
        "node_id":           1,        # int  - vehicle node ID
        "timestamp":         0.5,      # float - simulation time (seconds)
        "packets_received":  30,       # int  - packets the node received
        "packets_forwarded": 28,       # int  - packets it actually forwarded
        "pdr":               0.933,    # float - forwarding ratio (fwd/rx)
        "speed_kmh":         75.0,     # float - vehicle speed in km/h
        "rsu_id":            "RSU_01", # str  - nearest RSU ("RSU_01"/"RSU_02"/"RSU_03")
        "is_handoff":        false,    # bool - true if changing RSU this time step
        "src_vehicle":       1,        # int  - source of the packet flow
        "dst_vehicle":       3         # int  - destination of the packet flow
    }

Attackers (grey-hole nodes) should additionally have:
        "_is_attacker": true

After sending, run on the SHIELD-GH machine:
    docker compose run --rm pipeline \\
        python shield_gh_blockchain/mock_mode/run_mock_pipeline.py /app/ns3_input/events.jsonl
    docker compose run --rm pipeline \\
        python shield_gh_fl/mock_mode/run_mock_fl.py
Then refresh http://localhost in the browser.
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' not installed. Run:  pip install requests")
    sys.exit(1)


REQUIRED_FIELDS = {
    "node_id", "timestamp", "packets_received",
    "packets_forwarded", "pdr", "speed_kmh",
    "rsu_id", "is_handoff", "src_vehicle", "dst_vehicle",
}


def load_jsonl(path: str) -> list:
    events = []
    with open(path) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"[WARN] Line {i}: invalid JSON — {e}")
                continue
            missing = REQUIRED_FIELDS - set(ev.keys())
            if missing:
                print(f"[WARN] Line {i} (node {ev.get('node_id','?')}): "
                      f"missing fields {missing}")
            events.append(ev)
    return events


def send(host: str, events: list, timeout: int = 30):
    url = f"http://{host}/api/ns3/events"
    print(f"Connecting to {url} ...")
    r = requests.post(url, json=events, timeout=timeout)
    r.raise_for_status()
    return r.json()


def main():
    parser = argparse.ArgumentParser(description="NS-3 → SHIELD-GH bridge")
    parser.add_argument("--host",   required=True,
                        help="IP of the SHIELD-GH machine, e.g. 192.168.1.5")
    parser.add_argument("--events", required=True,
                        help="Path to vehicle_events.jsonl produced by NS-3")
    args = parser.parse_args()

    events_path = Path(args.events)
    if not events_path.exists():
        print(f"[ERROR] File not found: {events_path}")
        sys.exit(1)

    events = load_jsonl(str(events_path))
    if not events:
        print("[ERROR] No valid events found in file.")
        sys.exit(1)

    print(f"[OK] Loaded {len(events)} events from {events_path.name}")

    try:
        result = send(args.host, events)
    except requests.exceptions.ConnectionError:
        print(f"\n[ERROR] Could not connect to {args.host}")
        print("Check:")
        print("  1. SHIELD-GH machine is reachable: ping", args.host)
        print("  2. Docker is running on SHIELD-GH machine (docker compose ps)")
        print("  3. Windows Firewall allows port 80 on SHIELD-GH machine")
        sys.exit(1)

    print(f"[SENT] {result}")
    print()
    print("Events are saved. Now on the SHIELD-GH machine, run:")
    print()
    print("  docker compose run --rm pipeline python "
          "shield_gh_blockchain/mock_mode/run_mock_pipeline.py "
          "/app/ns3_input/events.jsonl")
    print()
    print("  docker compose run --rm pipeline python "
          "shield_gh_fl/mock_mode/run_mock_fl.py")
    print()
    print("Then open http://localhost in the browser — dashboard will update.")


if __name__ == "__main__":
    main()
