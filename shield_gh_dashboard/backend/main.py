"""
SHIELD-GH Dashboard API
FastAPI backend — serves blockchain and FL output files as REST endpoints.
Read-only. No database. All data comes from JSON files written by Part 2 & 3.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from typing import List, Any
import json, glob, math

app = FastAPI(title="SHIELD-GH Dashboard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

BASE = Path(__file__).parent.parent.parent          # project root
BC_DIR  = BASE / "shield_gh_blockchain" / "output" / "bc_records"
FL_DIR  = BASE / "shield_gh_fl" / "output" / "fl_scores"
FL_OUT  = BASE / "shield_gh_fl" / "output"
NS3_DIR = BASE / "ns3_input"
NS3_DIR.mkdir(parents=True, exist_ok=True)
NS3_EVENTS_FILE = NS3_DIR / "events.jsonl"


def _load_json(path: Path):
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {path.name}")
    with open(path) as f:
        return json.load(f)


def _all_json(directory: Path, pattern: str) -> list:
    files = sorted(directory.glob(pattern))
    return [json.loads(f.read_text()) for f in files]


# ── Blockchain endpoints ──────────────────────────────────────────────────────

@app.get("/api/blockchain/records")
def get_all_bc_records():
    records = _all_json(BC_DIR, "bc_record_*.json")
    return {"count": len(records), "records": records}


@app.get("/api/blockchain/records/{node_id}")
def get_bc_record(node_id: int):
    path = BC_DIR / f"bc_record_{node_id}.json"
    return _load_json(path)


# ── FL endpoints ──────────────────────────────────────────────────────────────

@app.get("/api/fl/scores")
def get_all_fl_scores():
    scores = _all_json(FL_DIR, "fl_score_*.json")
    return {"count": len(scores), "scores": scores}


@app.get("/api/fl/scores/{node_id}")
def get_fl_score(node_id: int):
    path = FL_DIR / f"fl_score_{node_id}.json"
    return _load_json(path)


@app.get("/api/fl/rounds")
def get_round_log():
    data = _load_json(FL_OUT / "round_log.json")
    return {"rounds": data, "total_rounds": len(data)}


@app.get("/api/fl/ledger")
def get_gradient_ledger():
    data = _load_json(FL_OUT / "mock_ledger.json")
    entries = [{"key": k, "hash": v[:24] + "...", "full_hash": v} for k, v in data.items()]
    return {"count": len(entries), "entries": entries}


# ── System summary ────────────────────────────────────────────────────────────

@app.get("/api/system/summary")
def get_summary():
    bc_records = _all_json(BC_DIR, "bc_record_*.json")
    fl_scores  = _all_json(FL_DIR, "fl_score_*.json")
    round_log  = json.loads((FL_OUT / "round_log.json").read_text()) if (FL_OUT / "round_log.json").exists() else []
    ledger     = json.loads((FL_OUT / "mock_ledger.json").read_text()) if (FL_OUT / "mock_ledger.json").exists() else {}

    isolated   = [r for r in bc_records if r.get("debsc_triggered")]
    avg_rep    = sum(r["reputation_score"] for r in bc_records) / max(len(bc_records), 1)
    avg_acc    = sum(s["local_accuracy"] for s in fl_scores) / max(len(fl_scores), 1)
    total_accepted = sum(r["accepted"] for r in round_log)
    total_rejected = sum(len(r["rejected"]) for r in round_log)

    return {
        "total_vehicles_monitored": len(bc_records),
        "total_isolated":           len(isolated),
        "avg_reputation_score":     round(avg_rep, 4),
        "fl_rounds_completed":      len(round_log),
        "fl_avg_accuracy":          round(avg_acc, 4),
        "gradient_commits":         len(ledger),
        "gradient_accepted":        total_accepted,
        "gradient_rejected":        total_rejected,
        "pqc_active":               True,
    }


# ── Network topology ──────────────────────────────────────────────────────────

@app.get("/api/network/topology")
def get_topology():
    bc_records = _all_json(BC_DIR, "bc_record_*.json")
    fl_scores  = _all_json(FL_DIR,  "fl_score_*.json")

    fl_by_id = {s["node_id"]: s for s in fl_scores}
    bc_by_id = {r["node_id"]: r for r in bc_records}

    rsus = [
        {"id": "RSU_01", "type": "rsu", "label": "RSU 01", "x": 200, "y": 150},
        {"id": "RSU_02", "type": "rsu", "label": "RSU 02", "x": 500, "y": 150},
        {"id": "RSU_03", "type": "rsu", "label": "RSU 03", "x": 800, "y": 150},
    ]

    # Assign vehicles to RSUs in round-robin
    all_node_ids = sorted(set(list(bc_by_id.keys()) + list(fl_by_id.keys())))
    vehicle_nodes = []
    rsu_map = ["RSU_01", "RSU_02", "RSU_03"]

    for i, nid in enumerate(all_node_ids):
        bc  = bc_by_id.get(nid, {})
        fl  = fl_by_id.get(nid, {})
        rsu = rsu_map[i % 3]
        angle = (i * 60) % 360
        r = 120
        cx = [200, 500, 800][i % 3]
        x  = cx + r * math.cos(math.radians(angle + 200))
        y  = 350 + r * math.sin(math.radians(angle + 200)) * 0.5

        vehicle_nodes.append({
            "id":               f"V_{nid}",
            "type":             "vehicle",
            "node_id":          nid,
            "label":            f"V{nid}",
            "rsu":              rsu,
            "isolation_status": bc.get("isolation_status", "UNKNOWN"),
            "debsc_triggered":  bc.get("debsc_triggered", False),
            "reputation_score": bc.get("reputation_score", 0),
            "zkp_valid":        bc.get("zkp_valid", True),
            "malicious_prob":   fl.get("malicious_prob", None),
            "local_accuracy":   fl.get("local_accuracy", None),
            "x": round(x),
            "y": round(y),
        })

    nodes = rsus + vehicle_nodes

    edges = []
    for v in vehicle_nodes:
        edges.append({"source": v["id"], "target": v["rsu"], "type": "vehicle-rsu"})
    for i in range(len(rsus) - 1):
        edges.append({"source": rsus[i]["id"], "target": rsus[i+1]["id"], "type": "rsu-rsu"})

    return {"nodes": nodes, "edges": edges}


# ── LLM Threat Scoring endpoints ─────────────────────────────────────────────

LLM_DIR    = BASE / "shield_gh_llm" / "output"
LLM_SCORES = LLM_DIR / "llm_scores"


# ── DistilBERT Q_i scores (Section 3.6.3) ────────────────────────────────────

@app.get("/api/llm/scores")
def get_all_llm_scores():
    scores = _all_json(LLM_SCORES, "llm_score_*.json")
    return {"count": len(scores), "scores": scores}


@app.get("/api/llm/scores/{node_id}")
def get_llm_score(node_id: int):
    return _load_json(LLM_SCORES / f"llm_score_{node_id}.json")


# ── Threat narrative reports (fusion of BC + FL + LLM) ────────────────────────

@app.get("/api/llm/summary")
def get_llm_summary():
    return _load_json(LLM_DIR / "llm_summary.json")


@app.get("/api/llm/reports")
def get_all_llm_reports():
    reports = _all_json(LLM_DIR, "llm_report_*.json")
    return {"count": len(reports), "reports": reports}


@app.get("/api/llm/reports/{node_id}")
def get_llm_report(node_id: int):
    return _load_json(LLM_DIR / f"llm_report_{node_id}.json")


# ── NS-3 integration ──────────────────────────────────────────────────────────

@app.post("/api/ns3/events")
def receive_ns3_events(events: List[Any]):
    """Receive vehicle events from NS-3 simulation running on another machine."""
    if not events:
        raise HTTPException(status_code=400, detail="Empty events list")
    lines = [json.dumps(e) for e in events]
    NS3_EVENTS_FILE.write_text('\n'.join(lines))
    return {
        "status": "saved",
        "events_received": len(events),
        "next_step": "docker compose run --rm pipeline python shield_gh_blockchain/mock_mode/run_mock_pipeline.py /app/ns3_input/events.jsonl"
    }


@app.get("/api/ns3/status")
def ns3_status():
    if not NS3_EVENTS_FILE.exists():
        return {"file_ready": False, "event_count": 0}
    lines = [l for l in NS3_EVENTS_FILE.read_text().strip().split('\n') if l.strip()]
    return {"file_ready": True, "event_count": len(lines), "path": str(NS3_EVENTS_FILE)}
