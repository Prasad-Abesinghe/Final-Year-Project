# NS-3 → SHIELD-GH Connection Guide

**Owner (NS-3 simulation):** D. Abenayaka (EG/2021/4376)  
**Owner (SHIELD-GH system):** B.M.L.P. Abesinghe (EG/2021/4377)

---

## Overview

The NS-3 simulation runs on one computer and produces vehicle network events.  
The SHIELD-GH system (Blockchain + FL + Dashboard) runs on another computer via Docker.  
This guide explains how to connect the two computers so NS-3 output feeds into SHIELD-GH.

```
Friend's Computer                     Your Computer (SHIELD-GH)
─────────────────                     ──────────────────────────
NS-3 Simulation                       Docker (pipeline + backend + frontend)
      │                                       │
      │  POST /api/ns3/events                 │
      │──────── HTTP ─────────────────────────▶  FastAPI saves events.jsonl
                                              │
                                              │  docker compose run pipeline
                                              │  (blockchain + FL re-run)
                                              │
                                              ▼
                                    http://localhost  (browser)
```

---

## Part A — Your Computer (SHIELD-GH)

### A1. Check Docker is running

Open PowerShell and run:

```powershell
docker compose ps
```

Expected output (backend and frontend should show "Up"):

```
NAME                        STATUS
finalyearproject-backend-1  Up
finalyearproject-frontend-1 Up
```

If not running, start it:

```powershell
cd "d:\Academic\FYP\Project\Final Year Project"
docker compose up -d
```

### A2. Find your IP address

Run in PowerShell:

```powershell
ipconfig | Select-String "IPv4"
```

Look for the IP under your WiFi adapter (e.g., `192.168.1.X` or `172.20.10.X`).  
**Both computers must be on the same WiFi network.**

### A3. Open port 80 in Windows Firewall

Run **PowerShell as Administrator** (right-click → Run as administrator):

```powershell
netsh advfirewall firewall add rule name="SHIELD-GH Port 80" dir=in action=allow protocol=TCP localport=80
```

### A4. Test that the API is reachable

Open a browser and go to:

```
http://localhost/api/ns3/status
```

Expected response:

```json
{"file_ready": false, "event_count": 0}
```

---

## Part B — Friend's Computer (NS-3)

### B1. Install Python dependencies

```bash
pip install requests numpy
```

### B2. Get the bridge files

Copy these two files from the SHIELD-GH project to the NS-3 computer:

| File | Where to get it |
|------|-----------------|
| `ns3_bridge.py` | Project root |
| `shield_gh_ns3/mock_data/generate_mock_events.py` | NS-3 mock generator |

### B3. Choose your method

#### Option 1 — NS-3 is not set up yet (use mock data)

Run the mock generator. It creates realistic NS-3-style events and sends them:

```bash
python generate_mock_events.py --send --host YOUR_IP
```

Replace `YOUR_IP` with the IP from Step A2 (e.g., `172.20.10.3`).

To generate only one attack variant (e.g., S1 grey-hole attack):

```bash
python generate_mock_events.py --variant S1_DP_FR --send --host YOUR_IP
```

#### Option 2 — NS-3 is running, send the output file

After NS-3 produces `vehicle_events.jsonl`, send it:

```bash
python ns3_bridge.py --host YOUR_IP --events path/to/vehicle_events.jsonl
```

---

## Part C — Re-run the Pipeline (Your Computer)

After the friend sends the events, run these two commands on your machine:

```powershell
cd "d:\Academic\FYP\Project\Final Year Project"

docker compose run --rm pipeline python shield_gh_blockchain/mock_mode/run_mock_pipeline.py /app/ns3_input/events.jsonl

docker compose run --rm pipeline python shield_gh_fl/mock_mode/run_mock_fl.py
```

Then open `http://localhost` in your browser — the dashboard updates automatically.

---

## NS-3 Event Format (Required Schema)

Every line of the `.jsonl` file must be a JSON object with these exact fields:

```json
{
  "node_id":            3,
  "timestamp":          2.9638,
  "packets_received":   30,
  "packets_forwarded":  14,
  "pdr":                0.4667,
  "speed_kmh":          72.4,
  "rsu_id":             "RSU_02",
  "flow_id":            "flow_29",
  "is_handoff":         false,
  "src_vehicle":        1,
  "dst_vehicle":        4,
  "ground_truth_label": "S1_DP_FR",
  "is_attacker":        true
}
```

### Field reference

| Field | Type | Description |
|-------|------|-------------|
| `node_id` | int | Vehicle node ID (benign: 0–7, attacker: e.g. 3) |
| `timestamp` | float | NS-3 simulation time in seconds |
| `packets_received` | int | Packets the node received this slot |
| `packets_forwarded` | int | Packets it actually forwarded |
| `pdr` | float | `packets_forwarded / packets_received` (0.0–1.0) |
| `speed_kmh` | float | Vehicle speed in km/h |
| `rsu_id` | string | Nearest RSU: `"RSU_01"`, `"RSU_02"`, or `"RSU_03"` |
| `flow_id` | string | Flow identifier, e.g. `"flow_3"` |
| `is_handoff` | bool | `true` if vehicle is changing RSU this time slot |
| `src_vehicle` | int | Source node of the packet flow |
| `dst_vehicle` | int | Destination node of the packet flow |
| `ground_truth_label` | string | See attack variants table below |
| `is_attacker` | bool | `true` for the malicious node |

### Attack variant labels

| Label | Description |
|-------|-------------|
| `BENIGN` | Normal vehicle, no attack |
| `S1_DP_FR` | Data-plane: full-rate grey hole drop |
| `S2_DP_IT` | Data-plane: intermittent drop (on/off every 10s) |
| `S3_DP_TS` | Data-plane: target-specific drop (only drops from one source) |
| `S4_CP_FR` | Control-plane: malicious FlowMod, full-rate |
| `S5_CP_IT` | Control-plane: malicious FlowMod, intermittent |
| `S6_CP_TS` | Control-plane: malicious FlowMod, target-specific |

RSU zones (based on vehicle x-position along the 1 km highway):

```
0 m ──── RSU_01 ──── 350 m ──── RSU_02 ──── 650 m ──── RSU_03 ──── 1000 m
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ns3/events` | Receive events from NS-3 (JSON array in body) |
| GET | `/api/ns3/status` | Check if events file has been received |

### Check status from browser or curl

```bash
curl http://YOUR_IP/api/ns3/status
```

```json
{"file_ready": true, "event_count": 3360}
```

### Send events manually (for testing)

```bash
curl -X POST http://YOUR_IP/api/ns3/events \
  -H "Content-Type: application/json" \
  -d '[{"node_id":1,"timestamp":0.5,"packets_received":10,"packets_forwarded":9,"pdr":0.9,"speed_kmh":70,"rsu_id":"RSU_01","flow_id":"flow_1","is_handoff":false,"src_vehicle":0,"dst_vehicle":2,"ground_truth_label":"BENIGN","is_attacker":false}]'
```

---

## Troubleshooting

### "Connection refused" or "Could not connect"

1. Confirm Docker is running: `docker compose ps`
2. Confirm both computers are on **the same WiFi/hotspot**
3. Confirm the firewall rule was added (Step A3)
4. Try pinging from friend's computer: `ping YOUR_IP`
5. Try opening `http://YOUR_IP` in the friend's browser — should show the SHIELD-GH dashboard

### "Pipeline does not update after sending events"

You must manually run the `docker compose run` commands in Part C — the pipeline does not re-run automatically.

### NS-3 produces no output / wrong format

Run the schema validator on friend's machine:

```bash
python -c "
import json, sys
with open('vehicle_events.jsonl') as f:
    for i, line in enumerate(f, 1):
        ev = json.loads(line)
        required = ['node_id','timestamp','packets_received','packets_forwarded',
                    'pdr','speed_kmh','rsu_id','is_handoff','src_vehicle','dst_vehicle']
        missing = [k for k in required if k not in ev]
        if missing:
            print(f'Line {i}: missing {missing}')
print('Validation done')
"
```

### "Port 80 already in use"

Another service is using port 80. Either stop it, or change the frontend port in `docker-compose.yml`:

```yaml
ports:
  - "8080:80"    # access at http://localhost:8080 instead
```

---

## Full Workflow Summary

```
Friend's computer                          Your computer
──────────────────                         ──────────────
1. python generate_mock_events.py
   --send --host YOUR_IP
        │
        │ HTTP POST /api/ns3/events
        ▼
                              2. docker compose run --rm pipeline \
                                 python ...run_mock_pipeline.py \
                                 /app/ns3_input/events.jsonl
                              
                              3. docker compose run --rm pipeline \
                                 python ...run_mock_fl.py

                              4. Open http://localhost
                                 → Dashboard shows NS-3 results
```
