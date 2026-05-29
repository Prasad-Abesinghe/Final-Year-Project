"""
SHIELD-GH LLM Threat Scoring Module

Fuses blockchain (ZKP, MATD reputation, DEBSC) and FL (malicious_prob, variant)
evidence into structured semantic threat assessments.

Modes
-----
template  (default) — deterministic rule-based narratives, no API key required
llm       (ANTHROPIC_API_KEY env var set) — calls claude-haiku-4-5 for richer text
"""

import json
import os
import random
import datetime
from pathlib import Path
from typing import Optional

# ── Attack variant reference ───────────────────────────────────────────────────

VARIANT_INFO = {
    "S1_DP_FR": {
        "name": "Data-Plane Full-Rate Grey Hole",
        "desc": "consistently drops 85–90% of forwarded packets at a steady rate",
        "plane": "data",
        "pattern": "steady",
    },
    "S2_DP_IT": {
        "name": "Data-Plane Intermittent Grey Hole",
        "desc": "alternates between dropping all packets and normal forwarding every ~10 s",
        "plane": "data",
        "pattern": "intermittent",
    },
    "S3_DP_TS": {
        "name": "Data-Plane Target-Specific Drop",
        "desc": "selectively drops packets from specific source vehicles while forwarding others",
        "plane": "data",
        "pattern": "selective",
    },
    "S4_CP_FR": {
        "name": "Control-Plane Full-Rate FlowMod Injection",
        "desc": "injects malicious OpenFlow FlowMod rules at full rate, corrupting RSU routing tables",
        "plane": "control",
        "pattern": "steady",
    },
    "S5_CP_IT": {
        "name": "Control-Plane Intermittent FlowMod Injection",
        "desc": "periodically injects malicious FlowMod rules to evade time-averaged detection",
        "plane": "control",
        "pattern": "intermittent",
    },
    "S6_CP_TS": {
        "name": "Control-Plane Target-Specific FlowMod",
        "desc": "injects malicious FlowMod rules targeting specific destination vehicles only",
        "plane": "control",
        "pattern": "selective",
    },
    "BENIGN": {
        "name": "Normal Vehicle",
        "desc": "exhibits normal VANET packet-forwarding behaviour within expected PDR bounds",
        "plane": "n/a",
        "pattern": "normal",
    },
}

# ── Recommended actions per threat level ───────────────────────────────────────

ACTIONS = {
    "CRITICAL": (
        "ISOLATE IMMEDIATELY — trigger DEBSC smart contract, revoke RSU session keys via "
        "PQC LKH group re-keying, and broadcast Dilithium-signed isolation alert to all "
        "RSUs in the cluster. Flag node for forensic analysis."
    ),
    "HIGH": (
        "ESCALATE — submit node for DEBSC review, increase RSU telemetry polling frequency "
        "to every 0.5 s, and prepare isolation payload pending confirmation from one "
        "additional FL aggregation round."
    ),
    "MEDIUM": (
        "MONITOR CLOSELY — increase telemetry sampling rate, register node as a DEBSC "
        "candidate, and re-evaluate after the next FL global model update. Alert network "
        "operators if reputation continues to decline."
    ),
    "LOW": (
        "STANDARD MONITORING — no action required. Continue routine MATD reputation "
        "tracking and ZKP verification on each interaction cycle."
    ),
}

# ── Threat score + level computation ──────────────────────────────────────────

def compute_threat_score(bc: dict, fl: dict, llm: dict = None) -> float:
    """Weighted fusion: BC reputation, FL malicious probability, ZKP failure, and DistilBERT Q_i."""
    rep_deficit = 1.0 - bc.get("reputation_score", 1.0)
    mal_prob    = fl.get("malicious_prob", 0.0)
    zkp_penalty = 0.0 if bc.get("zkp_valid", True) else 1.0
    if llm is not None:
        q_i   = llm.get("Q_i", 0.0)
        score = 0.25 * rep_deficit + 0.30 * mal_prob + 0.15 * zkp_penalty + 0.30 * q_i
    else:
        score = 0.35 * rep_deficit + 0.45 * mal_prob + 0.20 * zkp_penalty
    return round(min(1.0, max(0.0, score)), 4)


def score_to_level(threat_score: float, debsc_triggered: bool) -> str:
    if debsc_triggered or threat_score >= 0.75:
        return "CRITICAL"
    if threat_score >= 0.50:
        return "HIGH"
    if threat_score >= 0.25:
        return "MEDIUM"
    return "LOW"


# ── Template-based narrative generation ───────────────────────────────────────

_NARRATIVES = {
    "CRITICAL": [
        (
            "Vehicle node {node_id} has been definitively confirmed as a grey-hole attacker "
            "executing a {variant_name} attack. The ZKP forwarding proof is cryptographically "
            "invalid — the node committed to relaying packets but RSU telemetry confirms "
            "only {actual_pct:.0f}% were actually forwarded. "
            "The MATD trust engine records a CRYSTALS-Dilithium-verified reputation of "
            "{rep:.3f}, well below the DEBSC isolation threshold of 0.40, and the global "
            "FL model assigns a malicious probability of {mal_prob:.1%}. "
            "The DEBSC smart contract has triggered network isolation and PQC group "
            "re-keying is in progress across the RSU cluster."
        ),
        (
            "All three detection layers in SHIELD-GH have independently flagged node {node_id} "
            "as executing a {variant_name} attack. "
            "ZKP forensics reveal a systematic discrepancy between claimed and RSU-observed "
            "forwarding counts — the defining signature of grey-hole behaviour. "
            "The MATD-corrected reputation ({rep:.3f}) has collapsed below the DEBSC "
            "isolation threshold, and the federated learning classifier reports {mal_prob:.1%} "
            "malicious probability after {rounds} training rounds. "
            "Isolation is enacted; PQC-secured re-keying alerts have been dispatched to "
            "all neighbouring RSUs."
        ),
    ],
    "HIGH": [
        (
            "Vehicle node {node_id} exhibits strong multi-layer indicators of a "
            "{variant_name} attack. The ZKP forwarding proof has failed, indicating "
            "dishonest packet-count reporting to the RSU. "
            "The MATD reputation score of {rep:.3f} reflects sustained malicious behaviour "
            "after handoff-induced PDR correction, and the FL global model classifies this "
            "node as likely malicious with probability {mal_prob:.1%}. "
            "The node is approaching the DEBSC isolation threshold and is under active "
            "elevated monitoring."
        ),
    ],
    "MEDIUM": [
        (
            "Vehicle node {node_id} shows elevated risk indicators consistent with early-stage "
            "or low-intensity grey-hole activity. "
            "The FL global model assigns a malicious probability of {mal_prob:.1%}, "
            "suggesting anomalous packet-dropping patterns that do not yet dominate "
            "the node's behaviour profile. "
            "The MATD reputation score ({rep:.3f}) remains above the DEBSC isolation "
            "threshold but has been declining across recent interaction windows. "
            "Enhanced monitoring is recommended pending further evidence accumulation."
        ),
    ],
    "LOW": [
        (
            "Vehicle node {node_id} currently presents no significant threat indicators. "
            "The ZKP forwarding proof is valid, the MATD reputation score is {rep:.3f}, "
            "and the FL model assigns a low malicious probability of {mal_prob:.1%}. "
            "All observed behaviour is consistent with a legitimate VANET participant. "
            "Standard monitoring continues."
        ),
    ],
}

_ATTACK_PATTERNS = {
    "S1_DP_FR": (
        "Full-rate data-plane grey hole: the node receives packets at the network layer "
        "but silently discards approximately {drop_pct:.0f}% without forwarding, while "
        "submitting inflated forwarding counts to the RSU via dishonest ZKP commitments."
    ),
    "S2_DP_IT": (
        "Intermittent data-plane grey hole: the node alternates on a ~10-second cycle between "
        "aggressive dropping (PDR < 40%) and legitimate forwarding (PDR > 85%), exploiting "
        "time-averaged detection metrics to stay below naive detection thresholds. "
        "The MATD autocorrelation peak exposes the periodic switching pattern."
    ),
    "S3_DP_TS": (
        "Target-specific data-plane drop: the node selectively discards packets from designated "
        "source vehicles while forwarding all other traffic, making the attack appear as a "
        "legitimate link-quality degradation rather than intentional grey-hole behaviour."
    ),
    "S4_CP_FR": (
        "Full-rate control-plane attack: malicious OpenFlow FlowMod messages are continuously "
        "injected into the SDN controller plane, corrupting the flow tables of local RSUs and "
        "redirecting affected vehicle-to-vehicle traffic to black-hole routes at full rate."
    ),
    "S5_CP_IT": (
        "Intermittent control-plane attack: malicious FlowMod rules are injected periodically, "
        "causing transient routing disruption while the node mimics legitimate controller "
        "interactions between injection windows to evade signature-based detection."
    ),
    "S6_CP_TS": (
        "Target-specific control-plane attack: FlowMod injections are crafted to redirect only "
        "specific vehicle-to-vehicle flows, maximising disruption to targeted communications "
        "while leaving general VANET traffic unaffected and detection metrics stable."
    ),
    "BENIGN": (
        "No attack pattern detected. Forwarding behaviour is consistent with normal VANET "
        "operation within expected PDR variance bounds for the current RSU handoff frequency."
    ),
}


def _template_report(
    node_id: int, bc: dict, fl: dict, threat_score: float, threat_level: str
) -> dict:
    variant  = fl.get("predicted_variant", "BENIGN")
    vinfo    = VARIANT_INFO.get(variant, VARIANT_INFO["BENIGN"])
    rep      = bc.get("reputation_score", 1.0)
    mal_prob = fl.get("malicious_prob", 0.0)
    zkp_valid = bc.get("zkp_valid", True)
    rounds   = fl.get("round_num", 15)
    drop_pct = max(0.0, (1.0 - rep) * 100)
    actual_pct = rep * 100

    rng = random.Random(node_id)
    narrative = rng.choice(_NARRATIVES[threat_level]).format(
        node_id=node_id,
        variant_name=vinfo["name"],
        rep=rep,
        mal_prob=mal_prob,
        actual_pct=actual_pct,
        rounds=rounds,
    )

    pattern = _ATTACK_PATTERNS.get(variant, _ATTACK_PATTERNS["BENIGN"]).format(
        drop_pct=drop_pct,
    )

    confidence_assessment = (
        f"{'High' if threat_score > 0.6 else 'Moderate' if threat_score > 0.3 else 'Low'} confidence: "
        f"ZKP {'failed' if not zkp_valid else 'passed'}, "
        f"MATD reputation {rep:.3f} "
        f"({'below' if rep < 0.40 else 'above'} isolation threshold 0.40), "
        f"FL malicious probability {mal_prob:.1%}."
    )

    return {
        "node_id":              node_id,
        "threat_level":         threat_level,
        "threat_score":         threat_score,
        "attack_variant":       variant,
        "attack_plane":         vinfo["plane"],
        "attack_pattern_label": vinfo["name"],
        "narrative":            narrative,
        "attack_pattern":       pattern,
        "recommended_action":   ACTIONS[threat_level],
        "confidence_assessment": confidence_assessment,
        "evidence": {
            "zkp_failed":            not zkp_valid,
            "reputation_score":      rep,
            "reputation_deficit":    bc.get("reputation_deficit", 0.0),
            "matd_corrected_trust":  bc.get("matd_corrected_trust", 1.0),
            "malicious_probability": mal_prob,
            "fl_predicted_variant":  variant,
            "fl_confidence":         fl.get("confidence", 0.0),
            "fl_local_accuracy":     fl.get("local_accuracy", 1.0),
            "total_interactions":    bc.get("total_interactions", 0),
            "debsc_triggered":       bc.get("debsc_triggered", False),
        },
        "generated_by":  "shield_gh_template_engine_v1",
        "generated_at":  datetime.datetime.utcnow().isoformat() + "Z",
    }


# ── LLM-backed generation (Anthropic Claude Haiku) ────────────────────────────

_SYSTEM = (
    "You are a cybersecurity analyst for SHIELD-GH, a grey-hole attack detection and "
    "mitigation system for Software-Defined Vehicular Networks (SDVN). "
    "You produce concise, technically precise threat assessments from cryptographic "
    "proof results, trust-score evidence, and federated learning predictions. "
    "Write in formal professional prose. Never use markdown formatting in your response."
)


def _user_prompt(node_id: int, bc: dict, fl: dict, threat_score: float, threat_level: str) -> str:
    variant   = fl.get("predicted_variant", "BENIGN")
    vinfo     = VARIANT_INFO.get(variant, VARIANT_INFO["BENIGN"])
    rep       = bc.get("reputation_score", 1.0)
    mal_prob  = fl.get("malicious_prob", 0.0)
    zkp_str   = "FAILED (dishonest ZKP commitment)" if not bc.get("zkp_valid", True) else "PASSED"
    debsc_str = "ISOLATED" if bc.get("debsc_triggered") else "MONITORED"

    return f"""Produce a threat assessment for VANET vehicle node {node_id}.

EVIDENCE:
- ZKP Forwarding Proof: {zkp_str}
- Blockchain Reputation Score: {rep:.4f}  (DEBSC isolation threshold: 0.40)
- MATD Corrected Trust: {bc.get("matd_corrected_trust", 1.0):.4f}
- Total Monitored Interactions: {bc.get("total_interactions", 0)}
- FL Malicious Probability: {mal_prob:.4f}  (0 = benign, 1 = confirmed attacker)
- FL Predicted Attack Variant: {variant} — {vinfo["desc"]}
- FL Local Model Accuracy on Node Data: {fl.get("local_accuracy", 1.0):.4f}
- DEBSC Decision: {debsc_str}
- Computed Threat Score: {threat_score:.4f}
- Threat Level: {threat_level}

ATTACK VARIANT REFERENCE:
S1_DP_FR  Data-plane full-rate grey hole (drops ~85-90% of packets steadily)
S2_DP_IT  Data-plane intermittent drop (alternates attack/normal ~10 s cycle)
S3_DP_TS  Data-plane target-specific drop (only drops from one source vehicle)
S4_CP_FR  Control-plane full-rate malicious FlowMod injection
S5_CP_IT  Control-plane intermittent malicious FlowMod injection
S6_CP_TS  Control-plane target-specific malicious FlowMod injection
BENIGN    Normal forwarding behaviour

Respond with ONLY a valid JSON object — no markdown, no preamble:
{{
  "narrative": "3-4 sentences of professional threat analysis citing specific evidence values",
  "attack_pattern": "1-2 sentences describing the technical attack behaviour",
  "recommended_action": "specific mitigation recommendation for network operators",
  "confidence_assessment": "1 sentence on confidence level based on evidence strength"
}}"""


def _llm_report(
    node_id: int, bc: dict, fl: dict,
    threat_score: float, threat_level: str, api_key: str
) -> dict:
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=600,
            system=_SYSTEM,
            messages=[{"role": "user", "content": _user_prompt(node_id, bc, fl, threat_score, threat_level)}],
        )
        raw = msg.content[0].text.strip()
        # Strip optional markdown fences
        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1].lstrip("json").strip() if len(parts) > 1 else raw
        llm = json.loads(raw)
    except Exception as exc:
        print(f"  [LLM] API error for node {node_id}: {exc!r} — using template fallback")
        report = _template_report(node_id, bc, fl, threat_score, threat_level)
        report["generated_by"] = f"shield_gh_template_engine_v1 (llm_error: {type(exc).__name__})"
        return report

    variant  = fl.get("predicted_variant", "BENIGN")
    vinfo    = VARIANT_INFO.get(variant, VARIANT_INFO["BENIGN"])
    rep      = bc.get("reputation_score", 1.0)
    mal_prob = fl.get("malicious_prob", 0.0)
    zkp_valid = bc.get("zkp_valid", True)

    return {
        "node_id":              node_id,
        "threat_level":         threat_level,
        "threat_score":         threat_score,
        "attack_variant":       variant,
        "attack_plane":         vinfo["plane"],
        "attack_pattern_label": vinfo["name"],
        "narrative":            llm.get("narrative", ""),
        "attack_pattern":       llm.get("attack_pattern", ""),
        "recommended_action":   llm.get("recommended_action", ACTIONS[threat_level]),
        "confidence_assessment": llm.get("confidence_assessment", ""),
        "evidence": {
            "zkp_failed":            not zkp_valid,
            "reputation_score":      rep,
            "reputation_deficit":    bc.get("reputation_deficit", 0.0),
            "matd_corrected_trust":  bc.get("matd_corrected_trust", 1.0),
            "malicious_probability": mal_prob,
            "fl_predicted_variant":  variant,
            "fl_confidence":         fl.get("confidence", 0.0),
            "fl_local_accuracy":     fl.get("local_accuracy", 1.0),
            "total_interactions":    bc.get("total_interactions", 0),
            "debsc_triggered":       bc.get("debsc_triggered", False),
        },
        "generated_by":  "claude-haiku-4-5-20251001",
        "generated_at":  datetime.datetime.utcnow().isoformat() + "Z",
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def score_all_nodes(
    bc_records: dict,
    fl_scores: dict,
    output_dir: Path,
    llm_scores: dict = None,
) -> dict:
    """
    Score every node. Writes llm_report_{node_id}.json and llm_summary.json.
    Returns the summary dict.

    bc_records / fl_scores / llm_scores: {node_id (int): record_dict}
    llm_scores: Q_i scores from DistilBERT (optional; improves fusion accuracy).
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    mode    = "llm" if api_key else "template"
    qi_mode = "with Q_i" if llm_scores else "without Q_i"
    print(f"[LLM Scorer] Mode: {mode.upper()}  ({qi_mode})")
    if mode == "llm":
        print("[LLM Scorer] Using claude-haiku-4-5-20251001")

    all_ids = sorted(set(list(bc_records) + list(fl_scores)))
    reports = []
    counts  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for node_id in all_ids:
        bc  = bc_records.get(node_id, {})
        fl  = fl_scores.get(node_id, {})
        llm = (llm_scores or {}).get(node_id)

        threat_score = compute_threat_score(bc, fl, llm)
        threat_level = score_to_level(threat_score, bc.get("debsc_triggered", False))

        if mode == "llm":
            report = _llm_report(node_id, bc, fl, threat_score, threat_level, api_key)
        else:
            report = _template_report(node_id, bc, fl, threat_score, threat_level)

        with open(output_dir / f"llm_report_{node_id}.json", "w") as f:
            json.dump(report, f, indent=2)

        counts[threat_level] += 1
        flag = "  *** THREAT ***" if threat_level in ("CRITICAL", "HIGH") else ""
        print(f"  Node {node_id:>2}: {threat_level:<8}  score={threat_score:.3f}  "
              f"variant={report['attack_variant']}{flag}")
        reports.append(report)

    # ── Network-wide executive summary ────────────────────────────────────────
    threat_nodes = [r for r in reports if r["threat_level"] in ("CRITICAL", "HIGH")]
    n_total  = len(all_ids)
    n_threat = len(threat_nodes)

    if n_threat == 0:
        net_status = "SECURE"
        exec_summary = (
            f"The monitored SDVN of {n_total} vehicle nodes is operating securely. "
            "No grey-hole attack indicators have been detected across the blockchain ZKP, "
            "MATD reputation, or federated learning layers. "
            "Routine MATD tracking continues at standard polling frequency."
        )
    elif n_threat == 1:
        t = threat_nodes[0]
        net_status = "COMPROMISED"
        exec_summary = (
            f"One vehicle node (node {t['node_id']}, {t['attack_variant']}) has been "
            f"confirmed as a grey-hole attacker with a computed threat score of "
            f"{t['threat_score']:.3f}. "
            "The DEBSC smart contract has enacted isolation and PQC group re-keying is "
            "in progress. All remaining nodes show normal behaviour."
        )
    else:
        net_status = "UNDER ATTACK"
        node_list = ", ".join(
            f"node {t['node_id']} ({t['attack_variant']})" for t in threat_nodes
        )
        scores = [t["threat_score"] for t in threat_nodes]
        exec_summary = (
            f"Multiple grey-hole attackers have been confirmed: {node_list}. "
            f"Threat scores range from {min(scores):.3f} to {max(scores):.3f}. "
            "DEBSC isolation has been triggered for all confirmed attackers. "
            "Immediate network operator review and PQC re-keying across all RSU "
            "clusters are required."
        )

    summary = {
        "network_status":    net_status,
        "total_nodes":       n_total,
        "threats_detected":  n_threat,
        "threat_breakdown":  counts,
        "attacker_nodes":    [t["node_id"] for t in threat_nodes],
        "executive_summary": exec_summary,
        "scoring_mode":      mode,
        "generated_at":      datetime.datetime.utcnow().isoformat() + "Z",
    }

    with open(output_dir / "llm_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    return summary
