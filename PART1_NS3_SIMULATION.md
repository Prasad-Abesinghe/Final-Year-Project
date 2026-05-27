# PART 1 — NS-3 SDVN Simulation
## SHIELD-GH · Grey Hole Attack Traffic Generator
**Owner:** D. Abenayaka (EG/2021/4376)
**Tools:** NS-3.35, SUMO, Python 3.10+, C++17
**Output:** `vehicle_event.json`, `flow_rule_events.json`, labelled CSV datasets

---

## Project Context

You are implementing the NS-3 simulation layer for SHIELD-GH, a grey hole attack detection framework for Software-Defined Vehicular Networks (SDVN). This module produces all traffic data consumed by the Blockchain, Federated Learning, and LLM modules.

A **grey hole attack** is when a malicious vehicle selectively drops a fraction of packets it receives while appearing to participate normally. This is different from a black hole (drops everything) because the selective nature mimics natural packet loss, making it hard to detect.

The network is a **Software-Defined Vehicular Network (SDVN)**: vehicles communicate via V2V and V2I links, an SDN controller manages flow rules centrally, and RSUs (Roadside Units) are the infrastructure access points.

---

## Shared Data Contract

Every file you produce **must** conform to these schemas exactly. Other team members depend on them.

### Schema 1: `vehicle_event.json`
One JSON object per line (JSONL format), one entry per vehicle per time slot:
```json
{
  "node_id": 3,
  "timestamp": 2.9638,
  "packets_received": 30,
  "packets_forwarded": 14,
  "pdr": 0.4667,
  "speed_kmh": 72.4,
  "rsu_id": "RSU_02",
  "flow_id": "flow_29",
  "is_handoff": false,
  "src_vehicle": 1,
  "dst_vehicle": 4,
  "ground_truth_label": "S1_DP_FR",
  "is_attacker": true
}
```

### Schema 2: `flow_rule_events.json`
Controller-plane events — one entry per FlowMod install:
```json
{
  "timestamp": 1.5000,
  "controller_id": "ctrl_01",
  "target_node": "RSU_02",
  "action": "DROP",
  "match_field": "WILDCARD",
  "drop_probability": 0.50,
  "is_malicious": true,
  "attack_variant": "S4_CP_FR"
}
```

### Schema 3: `simulation_dataset.csv`
Feature-extracted rows for FL and LLM training:
```
node_id, window_start, window_end, pdr_mean, pdr_var, pdr_corrected,
speed_kmh, is_handoff, kl_divergence, autocorr_peak, rsu_id,
packets_received_total, packets_forwarded_total,
ground_truth_label, is_attacker
```

---

## Directory Structure to Create

```
shield_gh_ns3/
├── scratch/
│   ├── shield_gh_topology.cc        # main NS-3 simulation script
│   ├── attack_injector.cc           # grey hole attack logic
│   └── log_exporter.cc              # JSON/CSV log writer
├── mobility/
│   ├── generate_sumo_scenario.py    # generate SUMO mobility files
│   ├── sdvn_highway.sumocfg         # SUMO config
│   └── sdvn_highway.rou.xml         # vehicle routes
├── scripts/
│   ├── run_all_variants.sh          # run all 6 attack variants
│   ├── parse_ns3_logs.py            # convert NS-3 output to JSON schema
│   ├── extract_features.py          # build simulation_dataset.csv
│   └── validate_schema.py           # verify output matches contract
├── mock_data/
│   ├── generate_mock_events.py      # generate mock data (no NS-3 needed)
│   └── mock_vehicle_events.jsonl    # pre-generated mock output
├── output/
│   ├── vehicle_events/              # per-run JSONL files
│   ├── flow_rule_events/            # controller-plane logs
│   └── datasets/                    # CSV files for FL/LLM
└── requirements.txt
```

---

## Step 1 — Environment Setup

### 1.1 Install NS-3.35

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y gcc g++ python3 python3-pip cmake \
  libsqlite3-dev libboost-all-dev tcpdump wireshark \
  qt5-default mercurial gdb valgrind

# Download and build NS-3.35
wget https://www.nsnam.org/releases/ns-allinone-3.35.tar.bz2
tar xjf ns-allinone-3.35.tar.bz2
cd ns-allinone-3.35
python3 build.py --enable-examples --enable-tests

# Verify build
cd ns-3.35
./waf --run hello-simulator
```

### 1.2 Install OpenFlow module for NS-3

```bash
# Install ns3-ofsoftswitch13 (required for SDN simulation)
cd ns-allinone-3.35
git clone https://github.com/ljerezchaves/ofsoftswitch13
cd ofsoftswitch13
./boot.sh && ./configure --with-ns3=../ns-3.35
make

# Enable in NS-3 build
cd ../ns-3.35
./waf configure --enable-modules=openflow --with-ofsoftswitch=../ofsoftswitch13
./waf build
```

### 1.3 Install SUMO

```bash
sudo add-apt-repository ppa:sumo/stable
sudo apt-get update
sudo apt-get install -y sumo sumo-tools sumo-doc
echo 'export SUMO_HOME="/usr/share/sumo"' >> ~/.bashrc
source ~/.bashrc
```

### 1.4 Python dependencies

```bash
pip install numpy pandas matplotlib sumolib traci jsonschema
```

---

## Step 2 — SUMO Mobility Generation

### File: `mobility/generate_sumo_scenario.py`

```python
#!/usr/bin/env python3
"""
Generate SUMO mobility scenario for SHIELD-GH simulation.
Creates a 1km highway segment with 8-10 vehicles.
"""

import subprocess
import os

SUMO_HOME = os.environ.get("SUMO_HOME", "/usr/share/sumo")

# ── Network XML ──────────────────────────────────────────────────────────────
NETWORK_XML = """<?xml version="1.0" encoding="UTF-8"?>
<net version="1.9" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <edge id="highway_e1" from="node0" to="node1" priority="1">
    <lane id="highway_e1_0" index="0" speed="33.33" length="1000.0"
          shape="0.00,1.60 1000.00,1.60"/>
  </edge>
  <junction id="node0" type="dead_end" x="0.00"    y="0.00"/>
  <junction id="node1" type="dead_end" x="1000.00" y="0.00"/>
</net>"""

# ── Routes XML ───────────────────────────────────────────────────────────────
ROUTES_XML = """<?xml version="1.0" encoding="UTF-8"?>
<routes>
  <vType id="car" accel="2.6" decel="4.5" sigma="0.5"
         length="5" minGap="2.5" maxSpeed="33.33" color="1,0,0"/>
  <route id="route_highway" edges="highway_e1"/>

  <!-- 8 vehicles with staggered departure times -->
  <vehicle id="V0" type="car" route="route_highway" depart="0.0"  departPos="0"   departSpeed="20"/>
  <vehicle id="V1" type="car" route="route_highway" depart="1.0"  departPos="50"  departSpeed="22"/>
  <vehicle id="V2" type="car" route="route_highway" depart="1.5"  departPos="100" departSpeed="18"/>
  <vehicle id="V3" type="car" route="route_highway" depart="2.0"  departPos="150" departSpeed="25"/>
  <vehicle id="V4" type="car" route="route_highway" depart="2.5"  departPos="200" departSpeed="20"/>
  <vehicle id="V5" type="car" route="route_highway" depart="3.0"  departPos="250" departSpeed="23"/>
  <vehicle id="V6" type="car" route="route_highway" depart="3.5"  departPos="300" departSpeed="19"/>
  <vehicle id="V7" type="car" route="route_highway" depart="4.0"  departPos="350" departSpeed="21"/>
</routes>"""

# ── SUMO Config ──────────────────────────────────────────────────────────────
SUMO_CFG = """<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <input>
    <net-file value="sdvn_highway.net.xml"/>
    <route-files value="sdvn_highway.rou.xml"/>
  </input>
  <time>
    <begin value="0"/>
    <end value="100"/>
    <step-length value="0.5"/>
  </time>
  <output>
    <fcd-output value="fcd_output.xml"/>
    <fcd-output.period value="1"/>
  </output>
</configuration>"""

def generate_files():
    os.makedirs("mobility", exist_ok=True)
    with open("mobility/sdvn_highway.net.xml",  "w") as f: f.write(NETWORK_XML)
    with open("mobility/sdvn_highway.rou.xml",  "w") as f: f.write(ROUTES_XML)
    with open("mobility/sdvn_highway.sumocfg",  "w") as f: f.write(SUMO_CFG)
    print("[OK] SUMO scenario files generated in mobility/")

def run_sumo_and_export_ns3():
    """Run SUMO and export NS-3 compatible mobility trace."""
    cmd = [
        f"{SUMO_HOME}/tools/traceExporter.py",
        "--fcd-input", "mobility/fcd_output.xml",
        "--ns2mobility-output", "mobility/ns3_mobility.tcl"
    ]
    # First run SUMO to generate FCD output
    sumo_cmd = ["sumo", "-c", "mobility/sdvn_highway.sumocfg",
                "--fcd-output", "mobility/fcd_output.xml"]
    subprocess.run(sumo_cmd, check=True)
    subprocess.run(cmd, check=True)
    print("[OK] NS-3 mobility trace exported to mobility/ns3_mobility.tcl")

if __name__ == "__main__":
    generate_files()
    run_sumo_and_export_ns3()
```

---

## Step 3 — NS-3 Main Simulation Script

### File: `scratch/shield_gh_topology.cc`

```cpp
/* SHIELD-GH NS-3 Simulation
 * SDVN topology with OpenFlow SDN, 3 RSUs, 8 vehicles, grey hole attack injection
 * Produces per-node forwarding logs in JSON format
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/applications-module.h"
#include "ns3/openflow-module.h"
#include "ns3/netanim-module.h"
#include <fstream>
#include <map>
#include <vector>
#include <cmath>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ShieldGH");

// ── Attack Configuration ──────────────────────────────────────────────────
struct AttackConfig {
    int     attackerNodeId   = 3;        // node that acts as grey hole
    double  dropRate         = 0.50;     // fraction of packets to drop
    bool    intermittent     = false;    // if true: alternate on/off
    double  intermittentPeriod = 10.0;  // seconds per on/off epoch
    bool    targetSpecific   = false;    // if true: only drop from src srcTarget
    int     srcTarget        = 1;        // target source node for S3
    bool    controllerPlane  = false;    // if true: controller installs bad FlowMod
    std::string variant      = "S1_DP_FR";
};

// ── Per-node forwarding counters ──────────────────────────────────────────
struct NodeStats {
    uint32_t rx    = 0;
    uint32_t fwd   = 0;
    uint32_t drop  = 0;
    double   speedKmh = 0.0;
    std::string rsuId;
    bool     inHandoff = false;
};

std::map<uint32_t, NodeStats> g_nodeStats;
AttackConfig g_attack;
std::ofstream g_eventLog;   // vehicle_events.jsonl
std::ofstream g_flowLog;    // flow_rule_events.jsonl

// ── Packet drop decision ──────────────────────────────────────────────────
bool ShouldDrop(Ptr<Packet> packet, uint32_t nodeId, double now) {
    if ((int)nodeId != g_attack.attackerNodeId) return false;

    if (g_attack.intermittent) {
        double epochPos = fmod(now, g_attack.intermittentPeriod * 2);
        if (epochPos < g_attack.intermittentPeriod) return false;  // normal epoch
    }

    if (g_attack.targetSpecific) {
        // Extract source from packet tag (simplified: use flow ID)
        // In real implementation: parse IP header src field
        // For simulation: use a pseudo-random check based on flow
        uint32_t pktHash = packet->GetUid() % 2;
        if (pktHash != (uint32_t)g_attack.srcTarget % 2) return false;
    }

    double r = (double)rand() / RAND_MAX;
    return r < g_attack.dropRate;
}

// ── Log a forwarding event ────────────────────────────────────────────────
void LogEvent(uint32_t nodeId, double timestamp, uint32_t rx, uint32_t fwd,
              double speed, const std::string& rsuId, bool handoff,
              uint32_t srcNode, uint32_t dstNode) {
    double pdr = (rx > 0) ? (double)fwd / rx : 1.0;
    bool isAttacker = ((int)nodeId == g_attack.attackerNodeId);
    std::string label = isAttacker ? g_attack.variant : "BENIGN";

    g_eventLog << "{"
        << "\"node_id\":" << nodeId << ","
        << "\"timestamp\":" << std::fixed << std::setprecision(4) << timestamp << ","
        << "\"packets_received\":" << rx << ","
        << "\"packets_forwarded\":" << fwd << ","
        << "\"pdr\":" << std::fixed << std::setprecision(4) << pdr << ","
        << "\"speed_kmh\":" << std::fixed << std::setprecision(1) << speed << ","
        << "\"rsu_id\":\"" << rsuId << "\","
        << "\"flow_id\":\"flow_" << nodeId << "\","
        << "\"is_handoff\":" << (handoff ? "true" : "false") << ","
        << "\"src_vehicle\":" << srcNode << ","
        << "\"dst_vehicle\":" << dstNode << ","
        << "\"ground_truth_label\":\"" << label << "\","
        << "\"is_attacker\":" << (isAttacker ? "true" : "false")
        << "}\n";
    g_eventLog.flush();
}

// ── Periodic stats collection ─────────────────────────────────────────────
void CollectStats(NodeContainer vehicles, double interval) {
    double now = Simulator::Now().GetSeconds();

    for (uint32_t i = 0; i < vehicles.GetN(); i++) {
        Ptr<Node> node = vehicles.Get(i);
        Ptr<MobilityModel> mob = node->GetObject<MobilityModel>();

        Vector vel = mob->GetVelocity();
        double speed = std::sqrt(vel.x*vel.x + vel.y*vel.y) * 3.6;  // m/s → km/h

        NodeStats& stats = g_nodeStats[i];
        stats.speedKmh = speed;

        // Determine current RSU (based on x position)
        Vector pos = mob->GetPosition();
        std::string rsu = (pos.x < 400) ? "RSU_01" :
                          (pos.x < 700) ? "RSU_02" : "RSU_03";

        bool handoff = (stats.rsuId != "" && stats.rsuId != rsu);
        stats.inHandoff = handoff;
        stats.rsuId     = rsu;

        if (stats.rx > 0) {
            LogEvent(i, now, stats.rx, stats.fwd, speed, rsu, handoff,
                     (i > 0) ? i-1 : 0, (i < 7) ? i+1 : 7);
        }

        // Reset counters for next window
        stats.rx   = 0;
        stats.fwd  = 0;
        stats.drop = 0;
    }

    // Schedule next collection
    if (now + interval < Simulator::GetMaximumSimulationTime().GetSeconds()) {
        Simulator::Schedule(Seconds(interval), &CollectStats, vehicles, interval);
    }
}

int main(int argc, char* argv[]) {
    // ── Command-line parameters ───────────────────────────────────────────
    std::string variant  = "S1_DP_FR";
    double dropRate      = 0.50;
    double simTime       = 60.0;
    double logInterval   = 1.0;   // collect stats every 1 second
    uint32_t seed        = 1;

    CommandLine cmd;
    cmd.AddValue("variant",   "Attack variant (S1_DP_FR/S2_DP_IT/S3_DP_TS/S4_CP_FR/S5_CP_IT/S6_CP_TS/BENIGN)", variant);
    cmd.AddValue("dropRate",  "Packet drop rate for attacker (0.0-1.0)", dropRate);
    cmd.AddValue("simTime",   "Simulation duration (seconds)", simTime);
    cmd.AddValue("seed",      "Random seed", seed);
    cmd.Parse(argc, argv);

    // ── Configure attack ──────────────────────────────────────────────────
    RngSeedManager::SetSeed(seed);
    g_attack.dropRate    = dropRate;
    g_attack.variant     = variant;
    if (variant == "S2_DP_IT") g_attack.intermittent   = true;
    if (variant == "S3_DP_TS") g_attack.targetSpecific = true;
    if (variant == "S4_CP_FR") g_attack.controllerPlane= true;
    if (variant == "S5_CP_IT") { g_attack.controllerPlane=true; g_attack.intermittent=true; }
    if (variant == "S6_CP_TS") { g_attack.controllerPlane=true; g_attack.targetSpecific=true; }
    if (variant == "BENIGN")   g_attack.attackerNodeId = -1;  // no attacker

    // ── Open log files ────────────────────────────────────────────────────
    std::string suffix = variant + "_drop" + std::to_string((int)(dropRate*100))
                         + "_seed" + std::to_string(seed);
    g_eventLog.open("output/vehicle_events/events_" + suffix + ".jsonl");
    g_flowLog.open("output/flow_rule_events/flows_" + suffix + ".jsonl");

    // ── Create nodes ──────────────────────────────────────────────────────
    NodeContainer vehicles;  vehicles.Create(8);
    NodeContainer rsus;      rsus.Create(3);
    Ptr<Node>     controller = CreateObject<Node>();

    // ── WiFi (802.11p DSRC) ───────────────────────────────────────────────
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211p);
    YansWifiPhyHelper phy;
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    channel.AddPropagationLoss("ns3::FriisPropagationLossModel");
    phy.SetChannel(channel.Create());
    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer vehicleDevs = wifi.Install(phy, mac, vehicles);
    NetDeviceContainer rsuDevs     = wifi.Install(phy, mac, rsus);

    // ── Internet stack ────────────────────────────────────────────────────
    InternetStackHelper internet;
    internet.Install(vehicles);
    internet.Install(rsus);
    internet.Install(controller);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer vehicleIfaces = ipv4.Assign(vehicleDevs);
    ipv4.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer rsuIfaces     = ipv4.Assign(rsuDevs);

    // ── Mobility: vehicles on highway (x: 0–1000m) ───────────────────────
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> posAlloc = CreateObject<ListPositionAllocator>();
    for (int i = 0; i < 8; i++) posAlloc->Add(Vector(50.0 + i*100.0, 0.0, 0.0));
    mobility.SetPositionAllocator(posAlloc);
    mobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    mobility.Install(vehicles);
    // Set different speeds per vehicle (km/h → m/s)
    double speeds[] = {60,72,55,80,65,70,58,75};
    for (int i = 0; i < 8; i++) {
        vehicles.Get(i)->GetObject<ConstantVelocityMobilityModel>()
            ->SetVelocity(Vector(speeds[i]/3.6, 0.0, 0.0));
    }

    // ── RSUs: fixed positions ─────────────────────────────────────────────
    Ptr<ListPositionAllocator> rsuPos = CreateObject<ListPositionAllocator>();
    rsuPos->Add(Vector(200.0, 50.0, 0.0));   // RSU_01
    rsuPos->Add(Vector(500.0, 50.0, 0.0));   // RSU_02
    rsuPos->Add(Vector(800.0, 50.0, 0.0));   // RSU_03
    mobility.SetPositionAllocator(rsuPos);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(rsus);

    // ── UDP Applications (V2V traffic) ────────────────────────────────────
    uint16_t port = 9;
    for (uint32_t i = 0; i < vehicles.GetN() - 1; i++) {
        // Vehicle i sends to vehicle i+1
        UdpEchoServerHelper server(port);
        ApplicationContainer serverApp = server.Install(vehicles.Get(i+1));
        serverApp.Start(Seconds(1.0));
        serverApp.Stop(Seconds(simTime));

        UdpEchoClientHelper client(vehicleIfaces.GetAddress(i+1), port);
        client.SetAttribute("MaxPackets", UintegerValue(1000000));
        client.SetAttribute("Interval",  TimeValue(MilliSeconds(100)));  // 10 pkt/s
        client.SetAttribute("PacketSize",UintegerValue(512));
        ApplicationContainer clientApp = client.Install(vehicles.Get(i));
        clientApp.Start(Seconds(1.0));
        clientApp.Stop(Seconds(simTime));
    }

    // ── Schedule stats collection ─────────────────────────────────────────
    Simulator::Schedule(Seconds(logInterval), &CollectStats, vehicles, logInterval);

    // ── If controller-plane attack: log malicious FlowMod at t=5 ─────────
    if (g_attack.controllerPlane) {
        Simulator::Schedule(Seconds(5.0), [&]() {
            g_flowLog << "{"
                << "\"timestamp\":5.0,"
                << "\"controller_id\":\"ctrl_01\","
                << "\"target_node\":\"RSU_02\","
                << "\"action\":\"DROP\","
                << "\"match_field\":" << (g_attack.targetSpecific ? "\"src=V1\"" : "\"WILDCARD\"") << ","
                << "\"drop_probability\":" << g_attack.dropRate << ","
                << "\"is_malicious\":true,"
                << "\"attack_variant\":\"" << variant << "\""
                << "}\n";
            g_flowLog.flush();
        });
    }

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    g_eventLog.close();
    g_flowLog.close();

    NS_LOG_UNCOND("[DONE] Simulation complete. Variant=" << variant
        << " DropRate=" << dropRate << " Seed=" << seed);
    return 0;
}
```

---

## Step 4 — Run All Attack Variants

### File: `scripts/run_all_variants.sh`

```bash
#!/bin/bash
# Run all 6 attack variants across multiple seeds and drop rates

NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
SIM_SCRIPT="shield_gh_topology"
SEEDS=(1 2 3 4 5)
DROP_RATES=(0.20 0.40 0.60 0.80)
VARIANTS=("S1_DP_FR" "S2_DP_IT" "S3_DP_TS" "S4_CP_FR" "S5_CP_IT" "S6_CP_TS")

mkdir -p output/vehicle_events output/flow_rule_events output/datasets

echo "=== Running BENIGN baseline (5 seeds) ==="
for seed in "${SEEDS[@]}"; do
    $NS3_DIR/waf --run "$SIM_SCRIPT --variant=BENIGN --dropRate=0 --seed=$seed" 2>/dev/null
    echo "  [OK] BENIGN seed=$seed"
done

echo "=== Running attack variants ==="
for variant in "${VARIANTS[@]}"; do
    for drop in "${DROP_RATES[@]}"; do
        for seed in "${SEEDS[@]}"; do
            $NS3_DIR/waf --run \
              "$SIM_SCRIPT --variant=$variant --dropRate=$drop --seed=$seed" 2>/dev/null
            echo "  [OK] $variant drop=$drop seed=$seed"
        done
    done
done

echo "=== All simulations complete ==="
echo "Total files: $(ls output/vehicle_events/ | wc -l)"
```

---

## Step 5 — Feature Extraction

### File: `scripts/extract_features.py`

```python
#!/usr/bin/env python3
"""
Convert raw vehicle_event JSONL files into feature-extracted CSV
for use by the FL and LLM modules.
"""

import json
import math
import glob
import pandas as pd
import numpy as np
from pathlib import Path

# MATD parameters — must match Blockchain module values
LAMBDA_S  = 0.01    # mobility decay coefficient
DELTA_T   = 1.0     # observation slot seconds
ALPHA     = 1.0     # Beta prior
BETA      = 1.0     # Beta prior
RSU_R     = 300.0   # RSU coverage radius (metres)
DELTA_THO = 0.3     # average handoff duration (seconds)
RHO_MAX   = 0.15    # max handoff-induced loss rate
WINDOW    = 10      # slots per feature window

def compute_handoff_loss(speed_kmh):
    """Eq 3.4 — expected handoff-induced loss rate"""
    speed_ms = speed_kmh / 3.6
    return (speed_ms * DELTA_THO / RSU_R) * RHO_MAX

def compute_pdr_corrected(pdr, speed_kmh):
    """Eq 3.5 — mobility-corrected PDR"""
    return min(1.0, pdr + compute_handoff_loss(speed_kmh))

def compute_kl_divergence(src_pdrs: dict) -> float:
    """Eq 3.8 — KL divergence of per-source PDR distribution vs uniform"""
    if len(src_pdrs) < 2:
        return 0.0
    values = np.array(list(src_pdrs.values()), dtype=float)
    values = np.clip(values, 1e-9, 1.0)
    values /= values.sum()
    n = len(values)
    uniform = np.ones(n) / n
    return float(np.sum(values * np.log(values / uniform)))

def compute_autocorr(pdr_series: list, lag_range=(2, 15)) -> float:
    """Signature S2 — peak autocorrelation of binary drop indicator"""
    if len(pdr_series) < lag_range[1] + 2:
        return 0.0
    threshold = 0.75
    indicator = [1 if p < threshold else 0 for p in pdr_series]
    n  = len(indicator)
    mean_ind = np.mean(indicator)
    best = 0.0
    for lag in range(lag_range[0], min(lag_range[1]+1, n//2)):
        corr = np.corrcoef(indicator[:-lag], indicator[lag:])[0,1]
        if not np.isnan(corr):
            best = max(best, abs(corr))
    return float(best)

def extract_windows_from_file(filepath: str) -> list:
    """Slide a window of WINDOW slots over one simulation run."""
    rows = []
    with open(filepath) as f:
        events = [json.loads(line) for line in f if line.strip()]

    # Group by node
    by_node = {}
    for ev in events:
        by_node.setdefault(ev["node_id"], []).append(ev)

    for node_id, node_events in by_node.items():
        node_events.sort(key=lambda x: x["timestamp"])
        pdrs_by_src = {}  # src -> list of per-slot PDR

        for i in range(len(node_events) - WINDOW + 1):
            window_evs = node_events[i:i+WINDOW]
            pdrs   = [e["pdr"] for e in window_evs]
            speeds = [e["speed_kmh"] for e in window_evs]
            rx_tot = sum(e["packets_received"] for e in window_evs)
            fwd_tot= sum(e["packets_forwarded"] for e in window_evs)

            pdr_mean = np.mean(pdrs)
            pdr_var  = np.var(pdrs)
            speed_mean = np.mean(speeds)
            pdr_corr = compute_pdr_corrected(pdr_mean, speed_mean)

            # Accumulate per-source PDR for KL
            for ev in window_evs:
                src = ev.get("src_vehicle", 0)
                pdrs_by_src.setdefault(src, []).append(ev["pdr"])
            src_mean_pdrs = {s: np.mean(v) for s, v in pdrs_by_src.items()}
            kl_div = compute_kl_divergence(src_mean_pdrs)

            autocorr_peak = compute_autocorr(pdrs)
            handoffs = sum(1 for e in window_evs if e.get("is_handoff", False))
            label    = window_evs[-1].get("ground_truth_label", "BENIGN")
            is_attacker = window_evs[-1].get("is_attacker", False)

            rows.append({
                "node_id":               node_id,
                "window_start":          window_evs[0]["timestamp"],
                "window_end":            window_evs[-1]["timestamp"],
                "pdr_mean":              round(pdr_mean, 4),
                "pdr_var":               round(pdr_var, 4),
                "pdr_corrected":         round(pdr_corr, 4),
                "speed_kmh":             round(speed_mean, 1),
                "is_handoff":            int(handoffs > 0),
                "kl_divergence":         round(kl_div, 4),
                "autocorr_peak":         round(autocorr_peak, 4),
                "rsu_id":                window_evs[-1].get("rsu_id", "RSU_01"),
                "packets_received_total":rx_tot,
                "packets_forwarded_total":fwd_tot,
                "ground_truth_label":    label,
                "is_attacker":           int(is_attacker),
            })
    return rows

def main():
    all_rows = []
    files = glob.glob("output/vehicle_events/*.jsonl")
    print(f"Processing {len(files)} simulation log files...")

    for f in files:
        rows = extract_windows_from_file(f)
        all_rows.extend(rows)
        print(f"  {Path(f).name}: {len(rows)} windows")

    df = pd.DataFrame(all_rows)
    df.to_csv("output/datasets/simulation_dataset.csv", index=False)
    print(f"\n[OK] Saved {len(df)} rows to output/datasets/simulation_dataset.csv")
    print(f"Label distribution:\n{df['ground_truth_label'].value_counts()}")

if __name__ == "__main__":
    main()
```

---

## Step 6 — Mock Data Generator (No NS-3 Required)

### File: `mock_data/generate_mock_events.py`

Run this immediately so other team members can start without waiting for NS-3.

```python
#!/usr/bin/env python3
"""
Generate mock vehicle_event.jsonl files that match the NS-3 output schema.
Other team members use this while NS-3 is being set up.
"""

import json
import math
import random
import numpy as np
from pathlib import Path

ATTACK_CONFIGS = {
    "BENIGN":    {"drop": 0.00, "intermittent": False, "target": False},
    "S1_DP_FR":  {"drop": 0.50, "intermittent": False, "target": False},
    "S2_DP_IT":  {"drop": 0.50, "intermittent": True,  "target": False},
    "S3_DP_TS":  {"drop": 0.50, "intermittent": False, "target": True},
    "S4_CP_FR":  {"drop": 0.50, "intermittent": False, "target": False},
    "S5_CP_IT":  {"drop": 0.50, "intermittent": True,  "target": False},
    "S6_CP_TS":  {"drop": 0.50, "intermittent": False, "target": True},
}

RSU_ZONES = [(0, 350, "RSU_01"), (350, 650, "RSU_02"), (650, 1000, "RSU_03")]

def get_rsu(x_pos):
    for lo, hi, rsu in RSU_ZONES:
        if lo <= x_pos < hi:
            return rsu
    return "RSU_03"

def generate_run(variant: str, drop_rate: float, seed: int,
                 n_vehicles=8, duration=60.0, dt=1.0):
    random.seed(seed)
    np.random.seed(seed)

    cfg = ATTACK_CONFIGS[variant]
    attacker_id = 3 if variant != "BENIGN" else -1

    # Vehicle positions and speeds
    positions = [50.0 + i * 100.0 for i in range(n_vehicles)]
    speeds    = np.random.uniform(50, 90, n_vehicles)  # km/h

    events = []
    t = 1.0
    while t <= duration:
        for vid in range(n_vehicles):
            positions[vid] += speeds[vid] / 3.6 * dt
            if positions[vid] > 1000:
                positions[vid] = 0.0  # loop back

            rsu_id   = get_rsu(positions[vid])
            prev_rsu = get_rsu(max(0, positions[vid] - speeds[vid]/3.6 * dt))
            handoff  = (rsu_id != prev_rsu)

            # Determine base PDR (with some natural noise)
            base_pdr = np.random.uniform(0.85, 0.99)
            if handoff:
                base_pdr *= np.random.uniform(0.75, 0.90)  # handoff degrades PDR

            # Apply attack logic
            if vid == attacker_id:
                is_malicious = True
                if cfg["intermittent"]:
                    epoch = int(t / 10) % 2  # 10s on, 10s off
                    is_malicious = (epoch == 1)

                if is_malicious:
                    effective_drop = drop_rate
                    if cfg["target"]:
                        # Only drop from src node 1
                        src = (vid - 1) % n_vehicles
                        effective_drop = drop_rate if src == 1 else 0.0
                    base_pdr = max(0.0, base_pdr - effective_drop
                                   + np.random.normal(0, 0.02))

            n_rx  = random.randint(8, 15)
            n_fwd = max(0, int(n_rx * base_pdr + np.random.normal(0, 0.5)))
            n_fwd = min(n_fwd, n_rx)
            pdr   = n_fwd / n_rx if n_rx > 0 else 1.0

            is_attacker = (vid == attacker_id)
            label = variant if is_attacker else "BENIGN"

            events.append({
                "node_id":              vid,
                "timestamp":            round(t, 3),
                "packets_received":     n_rx,
                "packets_forwarded":    n_fwd,
                "pdr":                  round(pdr, 4),
                "speed_kmh":            round(float(speeds[vid]), 1),
                "rsu_id":               rsu_id,
                "flow_id":              f"flow_{vid}",
                "is_handoff":           handoff,
                "src_vehicle":          (vid - 1) % n_vehicles,
                "dst_vehicle":          (vid + 1) % n_vehicles,
                "ground_truth_label":   label,
                "is_attacker":          is_attacker,
            })
        t += dt

    return events

def main():
    out_dir = Path("mock_data/output")
    out_dir.mkdir(parents=True, exist_ok=True)

    for variant in ATTACK_CONFIGS:
        for drop in [0.20, 0.40, 0.60, 0.80]:
            if variant == "BENIGN" and drop > 0.20:
                continue  # only one benign run
            for seed in [1, 2, 3]:
                events = generate_run(variant, drop, seed)
                fname  = f"{variant}_drop{int(drop*100)}_seed{seed}.jsonl"
                fpath  = out_dir / fname
                with open(fpath, "w") as f:
                    for ev in events:
                        f.write(json.dumps(ev) + "\n")
        print(f"[OK] {variant} — generated")

    print(f"\nMock data in mock_data/output/ — share this with your team!")

if __name__ == "__main__":
    main()
```

---

## Step 7 — Schema Validator

### File: `scripts/validate_schema.py`

Run this before sending data to other team members.

```python
#!/usr/bin/env python3
"""Validate that vehicle_event output matches the shared contract."""

import json, sys, glob
from pathlib import Path

REQUIRED_FIELDS = {
    "node_id": int,
    "timestamp": float,
    "packets_received": int,
    "packets_forwarded": int,
    "pdr": float,
    "speed_kmh": float,
    "rsu_id": str,
    "flow_id": str,
    "is_handoff": bool,
    "src_vehicle": int,
    "dst_vehicle": int,
    "ground_truth_label": str,
    "is_attacker": bool,
}
VALID_LABELS = {"BENIGN","S1_DP_FR","S2_DP_IT","S3_DP_TS","S4_CP_FR","S5_CP_IT","S6_CP_TS"}

def validate_file(path: str) -> bool:
    ok = True
    with open(path) as f:
        for i, line in enumerate(f, 1):
            try:
                ev = json.loads(line.strip())
            except json.JSONDecodeError as e:
                print(f"  [ERR] Line {i}: JSON parse error: {e}"); ok = False; continue

            for field, ftype in REQUIRED_FIELDS.items():
                if field not in ev:
                    print(f"  [ERR] Line {i}: Missing field '{field}'"); ok = False
                elif not isinstance(ev[field], ftype):
                    print(f"  [ERR] Line {i}: Field '{field}' wrong type (got {type(ev[field]).__name__}, expected {ftype.__name__})"); ok = False

            if "ground_truth_label" in ev and ev["ground_truth_label"] not in VALID_LABELS:
                print(f"  [ERR] Line {i}: Invalid label '{ev['ground_truth_label']}'"); ok = False
            if "pdr" in ev and not (0.0 <= ev["pdr"] <= 1.0):
                print(f"  [ERR] Line {i}: PDR out of range: {ev['pdr']}"); ok = False
    return ok

if __name__ == "__main__":
    pattern = sys.argv[1] if len(sys.argv) > 1 else "output/vehicle_events/*.jsonl"
    files   = glob.glob(pattern) or glob.glob("mock_data/output/*.jsonl")
    if not files:
        print("No files found."); sys.exit(1)
    all_ok = True
    for f in files:
        result = validate_file(f)
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} {Path(f).name}")
        all_ok = all_ok and result
    sys.exit(0 if all_ok else 1)
```

---

## Step 8 — Quick Metric Check

### File: `scripts/check_metrics.py`

```python
#!/usr/bin/env python3
"""Compute PDR, detection accuracy, and jitter from simulation logs."""

import json, glob, sys
import numpy as np
from collections import defaultdict

def compute_metrics(filepath):
    events = [json.loads(l) for l in open(filepath) if l.strip()]
    by_node = defaultdict(list)
    for ev in events:
        by_node[ev["node_id"]].append(ev)

    print(f"\n=== {filepath} ===")
    total_rx = total_fwd = 0
    for nid, evs in sorted(by_node.items()):
        rx  = sum(e["packets_received"]  for e in evs)
        fwd = sum(e["packets_forwarded"] for e in evs)
        pdr = fwd / rx if rx > 0 else 1.0
        tag = " [ATTACKER]" if any(e["is_attacker"] for e in evs) else ""
        print(f"  Node {nid}{tag}: PDR={pdr:.4f} ({fwd}/{rx})")
        total_rx  += rx
        total_fwd += fwd

    net_pdr = total_fwd / total_rx if total_rx > 0 else 1.0
    print(f"  Network-wide PDR: {net_pdr:.4f}")

if __name__ == "__main__":
    files = sys.argv[1:] or glob.glob("mock_data/output/S1*.jsonl")[:2]
    for f in files:
        compute_metrics(f)
```

---

## Completion Checklist

Before handing off to other team members, verify:

- [ ] `mock_data/output/` contains JSONL files for all 7 labels × 4 drop rates × 3 seeds
- [ ] `scripts/validate_schema.py` passes on all generated files
- [ ] NS-3 simulation runs without errors for at least S1 (BENIGN and S1_DP_FR)
- [ ] `output/datasets/simulation_dataset.csv` contains at least 1000 rows with balanced labels
- [ ] All output files are shared with the team (or placed in the shared drive / repo)

---

## Files to Hand Off

| File | Used By |
|------|---------|
| `mock_data/output/*.jsonl` | Blockchain, FL, LLM (immediate) |
| `output/vehicle_events/*.jsonl` | Blockchain, FL, LLM (after NS-3 runs) |
| `output/datasets/simulation_dataset.csv` | FL training, LLM fine-tuning |
| `output/flow_rule_events/*.jsonl` | Integration (controller-plane testing) |
