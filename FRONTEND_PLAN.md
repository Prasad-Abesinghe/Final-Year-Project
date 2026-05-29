# SHIELD-GH Frontend Plan
## Dashboard · Network Visualiser · Blockchain Monitor · FL Training · Attack Detection

---

## 1. Overview

A web dashboard that reads the JSON output files produced by the Blockchain (Part 2)
and Federated Learning (Part 3) modules and presents them as live visual panels.

No blockchain node or FL server needs to be running — the dashboard is a **read-only
viewer** over the output files, served through a small FastAPI backend.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Browser                              │
│                                                             │
│   React + TypeScript (Vite)                                 │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│   │Dashboard │ │ Network  │ │Blockchain│ │  FL Training │  │
│   │Overview  │ │Topology  │ │ Monitor  │ │   Dashboard  │  │
│   └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │ REST API (JSON)
                         │
┌────────────────────────▼────────────────────────────────────┐
│              FastAPI Backend  (Python)                      │
│   Reads output JSON files — no database needed              │
│                                                             │
│   /api/blockchain/records    ← bc_record_{id}.json          │
│   /api/fl/scores             ← fl_score_{id}.json           │
│   /api/fl/rounds             ← round_log.json               │
│   /api/fl/ledger             ← mock_ledger.json             │
│   /api/system/summary        ← aggregated stats             │
└─────────────────────────────────────────────────────────────┘
         │                          │
         ▼                          ▼
shield_gh_blockchain/          shield_gh_fl/
output/bc_records/             output/fl_scores/
                               output/round_log.json
                               output/mock_ledger.json
```

---

## 3. Technology Stack

### Frontend
| Technology | Version | Purpose |
|-----------|---------|---------|
| React | 18.x | UI component framework |
| TypeScript | 5.x | Type safety |
| Vite | 5.x | Fast build tool (replaces CRA) |
| Tailwind CSS | 3.x | Utility-first styling — dark theme |
| Recharts | 2.x | Line/bar/pie charts for metrics |
| React Force Graph | 1.x | SDVN network topology graph |
| React Router | 6.x | Multi-page navigation |
| Axios | 1.x | HTTP client for API calls |
| Lucide React | — | Icon library |

### Backend
| Technology | Version | Purpose |
|-----------|---------|---------|
| FastAPI | 0.110+ | REST API server |
| Uvicorn | 0.29+ | ASGI server |
| Python | 3.12 | Already installed |

### Design Theme
- **Dark background** (`#0f172a` slate-900) — cybersecurity feel
- **Green** (`#22c55e`) — BENIGN / trusted / accepted
- **Red** (`#ef4444`) — ISOLATED / attacked / rejected
- **Yellow** (`#eab308`) — SUSPICIOUS / rate-limited
- **Blue** (`#3b82f6`) — FL data / blockchain operations
- **Monospace font** for hash values and node IDs

---

## 4. Pages & Components

### 4.1 Page 1 — Dashboard Overview (`/`)

**Purpose:** Single-glance summary of the entire SHIELD-GH system.

```
┌─────────────────────────────────────────────────────────────┐
│  SHIELD-GH                              [Last run: 2 min ago]│
├──────────┬──────────┬──────────┬────────────────────────────┤
│ Vehicles │ Isolated │ FL Rounds│  Global Accuracy           │
│    7     │    2     │   15     │     95.5%                  │
│ monitored│ (DEBSC)  │ complete │  [████████████░░] 95.5%    │
├──────────┴──────────┴──────────┴────────────────────────────┤
│  System Status                                              │
│  [●] Blockchain Module    — 7 records, 2 isolated           │
│  [●] FL Module            — 15 rounds, 120 gradients verified│
│  [●] PQC Mitigation       — Dilithium + Kyber active        │
├─────────────────────────┬───────────────────────────────────┤
│  Recent Isolation Events │  FL Training Loss (last 15 rounds)│
│  ● Node 100 — ISOLATED  │     2.0 ┤                         │
│    ZKP FAIL · Rep=0.30  │     1.5 ┤\                        │
│  ● Node 101 — ISOLATED  │     1.0 ┤ \___                    │
│    ZKP FAIL · Rep=0.33  │     0.5 ┤     \___                │
│                         │     0.0 ┤         \___            │
│                         │         1  5  10  15              │
└─────────────────────────┴───────────────────────────────────┘
```

**Components:**
- `SummaryCard` — stat boxes (vehicles, isolated, rounds, accuracy)
- `SystemStatusPanel` — green/red indicator per module
- `IsolationEventFeed` — list of recent DEBSC isolation events
- `TrainingLossCurve` — Recharts LineChart, Node 3 loss vs others

---

### 4.2 Page 2 — Network Topology (`/network`)

**Purpose:** Visual map of the SDVN — vehicles, RSUs, and trust state.

```
┌─────────────────────────────────────────────────────────────┐
│  SDVN Network Topology                  [Filter: All nodes] │
│                                                             │
│         RSU_01 ──── RSU_02 ──── RSU_03                     │
│           │           │           │                         │
│         [v1]        [v3]        [v5]                        │
│        (green)     (green)    (green)                       │
│           │                                                 │
│         [v2]    [v100] [v101]                               │
│        (green)  (RED)   (RED)                               │
│                ISOLATED ISOLATED                            │
│                                                             │
│  Node Legend:                                               │
│  ● Green = BENIGN    ● Red = ISOLATED    ● Yellow = SUSPECT │
│                                                             │
│  Click a node to inspect →                                  │
└──────────────────────────────┬──────────────────────────────┘
                               │  Node Inspector Panel
                               │  Node 100
                               │  Status:   ISOLATED
                               │  Rep Score: 0.303
                               │  ZKP:      FAIL
                               │  MATD:     0.385
                               │  FL Score: 0.0026
                               │  [View Full Record]
```

**Components:**
- `SDVNGraph` — React Force Graph, nodes = vehicles + RSUs, edges = connections
- Node colour coded by `isolation_status` from `bc_record`
- `NodeInspectorPanel` — slide-in panel on click, shows combined BC + FL data
- RSU nodes rendered as squares, vehicles as circles

---

### 4.3 Page 3 — Blockchain Monitor (`/blockchain`)

**Purpose:** Display all `bc_record_{id}.json` files as a sortable table + detail view.

```
┌─────────────────────────────────────────────────────────────┐
│  Blockchain Records               [Sort: Rep ▲] [Filter ▼] │
├──────┬───────┬──────┬──────────┬──────────┬─────────────────┤
│ Node │  Rep  │  ZKP │   MATD   │  Deficit │ DEBSC Decision  │
├──────┼───────┼──────┼──────────┼──────────┼─────────────────┤
│  1   │ 0.700 │  OK  │  0.810   │  0.300   │ ● BENIGN        │
│  2   │ 0.683 │  OK  │  0.703   │  0.317   │ ● BENIGN        │
│  3   │ 0.713 │  OK  │  0.680   │  0.287   │ ● BENIGN        │
│  4   │ 0.686 │  OK  │  0.712   │  0.314   │ ● BENIGN        │
│  5   │ 0.677 │  OK  │  0.762   │  0.323   │ ● BENIGN        │
│ 100  │ 0.303 │ FAIL │  0.385   │  0.697   │ ● ISOLATED      │
│ 101  │ 0.334 │ FAIL │  0.318   │  0.666   │ ● ISOLATED      │
├──────┴───────┴──────┴──────────┴──────────┴─────────────────┤
│  Reputation Score Distribution                              │
│  [Bar chart — one bar per node, red bar = below threshold]  │
│                                                             │
│  Threshold line at 0.60 ─────────────────────────────────  │
│  ████ ████ ████ ████ ████  ░░░░  ░░░░                       │
│   1    2    3    4    5   100  101                          │
└─────────────────────────────────────────────────────────────┘
```

**Components:**
- `BlockchainTable` — sortable table, colour-coded rows
- `ReputationBarChart` — Recharts BarChart with threshold reference line
- `ZKPStatusBadge` — green "OK" / red "FAIL" pill
- `IsolationStatusBadge` — colour-coded decision pill
- `RecordDetailModal` — full JSON view of a selected bc_record

---

### 4.4 Page 4 — FL Training Dashboard (`/federated-learning`)

**Purpose:** Show the FL training process, round-by-round progress, and gradient verification.

```
┌─────────────────────────────────────────────────────────────┐
│  Federated Learning — 15 Rounds · 8 Clients                 │
├──────────────────────────────┬──────────────────────────────┤
│  Training Loss per Round     │  Accepted / Rejected Clients │
│                              │                              │
│  2.5 ┤ Node 3 (attacker)    │  Round  Accept  Reject       │
│  2.0 ┤ ╲                    │   1      8        0          │
│  1.5 ┤  ╲___________________│   2      8        0          │
│  1.0 ┤                      │   ...                        │
│  0.5 ┤ Others (converge)    │   15     8        0          │
│  0.0 ┤_____________________ │                              │
│      1   5   10   15        │  [View Gradient Ledger]      │
├──────────────────────────────┴──────────────────────────────┤
│  Per-Node FL Scores (after Round 15)                        │
│                                                             │
│  Node  mal_prob  Prediction   Confidence  Local Acc  Status │
│   0    0.029     BENIGN       99.7%       100.0%     OK     │
│   1    0.024     BENIGN       99.8%       100.0%     OK     │
│   2    0.016     BENIGN       99.8%       100.0%     OK     │
│   3    0.003     BENIGN       99.7%        64.0%  <- LOW ACC│
│   4    0.002     BENIGN       99.8%       100.0%     OK     │
│   5    0.002     BENIGN       99.8%       100.0%     OK     │
│   6    0.017     BENIGN       99.8%       100.0%     OK     │
│   7    0.015     BENIGN       99.8%       100.0%     OK     │
├─────────────────────────────────────────────────────────────┤
│  Gradient Ledger (Blockchain Verified)                      │
│  120 commitments · 0 rejected · 0 poisoning attempts        │
│                                                             │
│  grad_0_1  9bdfb869ca28...  ● Verified                      │
│  grad_1_1  485c18c49e11...  ● Verified                      │
│  grad_3_1  0b1c0fa34460...  ● Verified                      │
└─────────────────────────────────────────────────────────────┘
```

**Components:**
- `TrainingLossChart` — Recharts LineChart, one line per node (Node 3 highlighted red)
- `RoundAcceptanceTable` — table of rounds with accepted/rejected counts
- `FLScoreTable` — per-node malicious_prob, accuracy, prediction
- `GradientLedgerPanel` — searchable list of hash commitments with verification status
- `MaliciousProbGauge` — small gauge chart per node

---

### 4.5 Page 5 — Node Inspector (`/node/:id`)

**Purpose:** Deep-dive into one vehicle — combines all data sources.

```
┌─────────────────────────────────────────────────────────────┐
│  Node 100 — ISOLATED                          [← Back]      │
├─────────────────────────────────────────────────────────────┤
│  BLOCKCHAIN DATA                │  FL DATA                  │
│  ┌─────────────────────────┐   │  ┌───────────────────┐    │
│  │ Record ID: bc_0064      │   │  │ Node: 100 (not in │    │
│  │ Rep Score: 0.303        │   │  │ FL partition)     │    │
│  │ ZKP:       FAIL         │   │  └───────────────────┘    │
│  │ MATD:      0.385        │   │                           │
│  │ Deficit:   0.697        │   │  PQC MITIGATION           │
│  │ Isolated:  YES          │   │  ┌───────────────────┐    │
│  │ DEBSC:     TRIGGERED    │   │  │ Dilithium sig: OK │    │
│  └─────────────────────────┘   │  │ Kyber KEM:     OK │    │
│                                │  │ Threshold: 2/3    │    │
│  Reputation over time          │  │ Flowmod: SIGNED   │    │
│  [mini sparkline chart]        │  └───────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Backend API Endpoints

```python
# FastAPI  — shield_gh_dashboard/backend/main.py

GET  /api/blockchain/records        # all bc_record_{id}.json
GET  /api/blockchain/records/{id}   # single bc_record
GET  /api/fl/scores                 # all fl_score_{id}.json
GET  /api/fl/scores/{id}            # single fl_score
GET  /api/fl/rounds                 # round_log.json
GET  /api/fl/ledger                 # mock_ledger.json (gradient hashes)
GET  /api/system/summary            # aggregated counts for dashboard cards
GET  /api/network/topology          # nodes + edges for graph view
```

All endpoints return JSON. No writes — read-only dashboard.

---

## 6. Directory Structure

```
shield_gh_dashboard/
├── backend/
│   ├── main.py              # FastAPI app + all endpoints
│   └── requirements.txt     # fastapi, uvicorn
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── api/
│   │   │   └── client.ts        # Axios API functions
│   │   ├── components/
│   │   │   ├── layout/
│   │   │   │   ├── Sidebar.tsx
│   │   │   │   └── TopBar.tsx
│   │   │   ├── charts/
│   │   │   │   ├── TrainingLossChart.tsx
│   │   │   │   ├── ReputationBarChart.tsx
│   │   │   │   └── MaliciousProbGauge.tsx
│   │   │   ├── network/
│   │   │   │   └── SDVNGraph.tsx
│   │   │   └── shared/
│   │   │       ├── SummaryCard.tsx
│   │   │       ├── StatusBadge.tsx
│   │   │       └── NodeInspectorPanel.tsx
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── NetworkTopology.tsx
│   │   │   ├── BlockchainMonitor.tsx
│   │   │   ├── FLDashboard.tsx
│   │   │   └── NodeInspector.tsx
│   │   ├── types/
│   │   │   └── index.ts         # TypeScript types for all JSON schemas
│   │   ├── App.tsx
│   │   └── main.tsx
│   ├── index.html
│   ├── package.json
│   ├── tailwind.config.js
│   └── vite.config.ts
└── run_dashboard.py         # starts both backend + frontend together
```

---

## 7. Data Flow

```
JSON Output Files
       │
       ▼
FastAPI Backend
  reads files on each request (always fresh — no caching needed)
       │
       ▼  HTTP GET /api/...
React Frontend
  fetches on page load + optional auto-refresh every 30s
       │
       ▼
Recharts / React Force Graph / Tables
  renders the data visually
```

---

## 8. Key Visual Design Decisions

| Concern | Decision | Reason |
|---------|----------|--------|
| Theme | Dark (slate-900) | Cybersecurity dashboard convention |
| Layout | Sidebar navigation + main content area | Standard dashboard UX |
| Colour coding | Green/Red/Yellow per DEBSC status | Instantly readable |
| Network graph | Force-directed, auto-layout | Shows SDVN topology naturally |
| Charts | Recharts (React-native) | No D3 complexity, easier to maintain |
| Refresh | Manual button + optional 30s auto-refresh | Avoids flicker during FL runs |
| Node 3 highlight | Red line in training chart | Makes attacker visible in FL view |

---

## 9. Implementation Order

| Step | Task | Est. Time |
|------|------|-----------|
| 1 | FastAPI backend — all 8 endpoints | 30 min |
| 2 | React project setup (Vite + Tailwind) | 20 min |
| 3 | Layout — sidebar, topbar, routing | 30 min |
| 4 | Dashboard Overview page | 45 min |
| 5 | Blockchain Monitor page + table | 45 min |
| 6 | FL Training Dashboard + charts | 60 min |
| 7 | Network Topology graph | 60 min |
| 8 | Node Inspector page | 30 min |
| **Total** | | **~5 hours** |

---

## 10. Prerequisites to Install

```bash
# Backend
pip install fastapi uvicorn

# Frontend (run inside shield_gh_dashboard/frontend/)
npm create vite@latest . -- --template react-ts
npm install
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
npm install recharts react-router-dom axios lucide-react
npm install react-force-graph
```

---

## 11. How to Run (once built)

```powershell
# Terminal 1 — Backend
cd shield_gh_dashboard/backend
uvicorn main:app --reload --port 8000

# Terminal 2 — Frontend
cd shield_gh_dashboard/frontend
npm run dev
# Opens at http://localhost:5173
```

Or use the combined launcher:
```powershell
python shield_gh_dashboard/run_dashboard.py
```
