#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generate_report.py - Professional, MITRE-standardized reporting for HunterEngine.

Reads HunterEngine session data (results.json) and produces clean PNG charts plus
a text executive summary for a non-technical audience. Standalone: only READS
session data, runs no analysis, never modifies the pipeline.

DESIGN PRINCIPLES
  * NO message content anywhere. The raw lure text is never shown on any chart or
    in the summary. Individual inputs are referenced only by anonymized case IDs
    (CASE-001, ...). Reports are safe to share with non-technical stakeholders.
  * MITRE nomenclature only. Techniques are shown by their official ATT&CK ID and
    name (e.g. "T1566 Phishing"); tactics by their official display name and TA-ID
    (e.g. "Initial Access (TA0001)") in canonical kill-chain order. Nothing is
    invented or renamed.
  * Honest measurement. HunterEngine maps ATT&CK *behaviours*, not CVEs, so counts
    are "detection frequency" (number of cases mapping to a technique/tactic), not
    vulnerability counts. The correlation view is skipped when there are too few
    cases for it to be statistically meaningful.

USAGE
  python3 generate_report.py                       # newest session
  python3 generate_report.py <session_dir> [...]   # specific session(s)
  python3 generate_report.py --all                 # aggregate ALL sessions
  python3 generate_report.py --all --out report/   # custom output dir

DEPENDENCIES
  pip install matplotlib numpy
"""
from __future__ import annotations

import os
import sys
import json
import glob
import argparse
import datetime
from collections import Counter, defaultdict
from typing import List, Dict, Any

import uuid

try:
    import numpy as np
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap
    from matplotlib.patches import Patch
except ImportError:
    sys.exit("Missing dependency. Run: pip install matplotlib numpy")

# STIX 2.1 export uses the official 'stix2' library when available (guarantees
# spec compliance) and otherwise falls back to hand-built spec-compliant JSON.
try:
    import stix2 as _stix2
    _HAVE_STIX2 = True
except Exception:
    _HAVE_STIX2 = False

# ---- MITRE ATT&CK Enterprise tactics: official shortname -> (display, TA-id) ----
# Canonical kill-chain order. Source: MITRE ATT&CK Enterprise matrix.
TACTICS = [
    ("reconnaissance",        "Reconnaissance",        "TA0043"),
    ("resource-development",  "Resource Development",  "TA0042"),
    ("initial-access",        "Initial Access",        "TA0001"),
    ("execution",             "Execution",             "TA0002"),
    ("persistence",           "Persistence",           "TA0003"),
    ("privilege-escalation",  "Privilege Escalation",  "TA0004"),
    ("defense-evasion",       "Defense Evasion",       "TA0005"),
    ("credential-access",     "Credential Access",     "TA0006"),
    ("discovery",             "Discovery",             "TA0007"),
    ("lateral-movement",      "Lateral Movement",      "TA0008"),
    ("collection",            "Collection",            "TA0009"),
    ("command-and-control",   "Command and Control",   "TA0011"),
    ("exfiltration",          "Exfiltration",          "TA0010"),
    ("impact",                "Impact",                "TA0040"),
]
TACTIC_DISPLAY = {s: d for s, d, _ in TACTICS}
TACTIC_TAID = {s: t for s, _, t in TACTICS}
TACTIC_RANK = {s: i for i, (s, _, _) in enumerate(TACTICS)}

LEVEL_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
LEVEL_COLORS = {
    "INFO": "#9aa0a6", "LOW": "#f4c430", "MEDIUM": "#f08c2e",
    "HIGH": "#d83b2e", "CRITICAL": "#7a1116",
}
HEAT = LinearSegmentedColormap.from_list("attck", ["#f7fbff", "#f59e6b", "#9b1c1c"])
MIN_CASES_FOR_CORRELATION = 20

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "axes.titleweight": "bold",
    "axes.titlesize": 13,
    "axes.edgecolor": "#444",
    "axes.linewidth": 0.8,
    "figure.facecolor": "white",
})


# --------------------------------------------------------------------------- #
def load_results(session_dirs: List[str]) -> List[Dict[str, Any]]:
    items = []
    for d in session_dirs:
        rj = os.path.join(d, "results.json")
        if not os.path.isfile(rj):
            print(f"  [warn] no results.json in {d}; skipping")
            continue
        try:
            data = json.load(open(rj, encoding="utf-8"))
        except Exception as e:
            print(f"  [warn] cannot read {rj}: {e}")
            continue
        items.extend(data if isinstance(data, list) else data.get("results", []))
    return items


def tactic_label(short: str, with_id: bool = True) -> str:
    disp = TACTIC_DISPLAY.get(short, short.replace("-", " ").title())
    return f"{disp}\n({TACTIC_TAID[short]})" if with_id and short in TACTIC_TAID else disp


def ordered_present_tactics(items) -> List[str]:
    seen = set()
    for it in items:
        for m in it.get("mitre_matches", []):
            t = m.get("tactic")
            # keep only real MITRE ATT&CK tactics; ignore non-tactic values
            # (e.g. heuristic tags like 'stealth') and 'unknown'.
            if t and t in TACTIC_RANK:
                seen.add(t)
    return sorted(seen, key=lambda s: TACTIC_RANK[s])


def technique_catalog(items):
    counts, names, t_tactic = Counter(), {}, {}
    for it in items:
        for m in it.get("mitre_matches", []):
            tid = m.get("id")
            if not tid:
                continue
            counts[tid] += 1
            names[tid] = m.get("name", tid)
            t_tactic[tid] = m.get("tactic", "unknown")
    return counts, names, t_tactic


# --------------------------------------------------------------------------- #
# 1. Technique frequency — MITRE IDs + official names, no message text
# --------------------------------------------------------------------------- #
def chart_technique_frequency(items, out, top_n=25):
    counts, names, _ = technique_catalog(items)
    if not counts:
        print("  [skip] technique_frequency: no techniques"); return
    top = counts.most_common(top_n)
    labels = [f"{tid}  {names[tid]}" for tid, _ in top][::-1]
    vals = [c for _, c in top][::-1]
    fig, ax = plt.subplots(figsize=(10, max(3.5, 0.42 * len(top) + 1.6)))
    norm = np.array(vals) / max(vals)
    ax.barh(range(len(vals)), vals, color=[HEAT(0.25 + 0.75 * n) for n in norm],
            edgecolor="#2b2b2b", linewidth=0.4)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=8, fontfamily="monospace")
    ax.set_xlabel("Detection frequency  (cases mapped to technique)", fontsize=10)
    ax.set_title("ATT&CK Techniques by Detection Frequency", pad=12)
    for i, v in enumerate(vals):
        ax.text(v + max(vals) * 0.012, i, str(v), va="center", fontsize=8)
    ax.margins(x=0.08)
    ax.grid(axis="x", alpha=0.25)
    fig.tight_layout(); fig.savefig(out, dpi=160, bbox_inches="tight"); plt.close(fig)
    print(f"  wrote {out}")


# --------------------------------------------------------------------------- #
# 2. Tactic coverage — official tactic names + TA-ids, kill-chain order
# --------------------------------------------------------------------------- #
def chart_tactic_coverage(items, out):
    tactics = ordered_present_tactics(items)
    if not tactics:
        print("  [skip] tactic_coverage: no tactics"); return
    case_counts = Counter()
    for it in items:
        present = {m.get("tactic") for m in it.get("mitre_matches", [])
                   if m.get("tactic") in TACTIC_RANK}
        for t in present:
            case_counts[t] += 1
    vals = [case_counts.get(t, 0) for t in tactics]
    fig, ax = plt.subplots(figsize=(max(7, 1.0 * len(tactics) + 2), 5))
    norm = np.array(vals) / max(vals) if max(vals) else np.zeros(len(vals))
    bars = ax.bar(range(len(tactics)), vals,
                  color=[HEAT(0.25 + 0.75 * n) for n in norm],
                  edgecolor="#2b2b2b", linewidth=0.5)
    ax.set_xticks(range(len(tactics)))
    ax.set_xticklabels([tactic_label(t) for t in tactics], fontsize=8)
    ax.set_ylabel("Cases observed", fontsize=10)
    ax.set_title("ATT&CK Tactic Coverage  (kill-chain order)", pad=12)
    for b, v in zip(bars, vals):
        if v:
            ax.text(b.get_x() + b.get_width() / 2, v + max(vals) * 0.02, str(v),
                    ha="center", fontsize=8, fontweight="bold")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout(); fig.savefig(out, dpi=160, bbox_inches="tight"); plt.close(fig)
    print(f"  wrote {out}")


# --------------------------------------------------------------------------- #
# 3. Severity x Tactic (stacked) — standard tactic names, severity legend
# --------------------------------------------------------------------------- #
def chart_severity_by_tactic(items, out):
    data = defaultdict(Counter)
    for it in items:
        lvl = it["analysis"]["risk_level"]
        for t in {m.get("tactic") for m in it.get("mitre_matches", [])
                  if m.get("tactic") in TACTIC_RANK}:
            data[t][lvl] += 1
    if not data:
        print("  [skip] severity_by_tactic: no tactics"); return
    tactics = sorted(data, key=lambda s: TACTIC_RANK.get(s, 999))
    fig, ax = plt.subplots(figsize=(9.5, max(3.5, 0.55 * len(tactics) + 1.6)))
    left = np.zeros(len(tactics))
    present = [lv for lv in LEVEL_ORDER if any(data[t].get(lv) for t in tactics)]
    for lv in present:
        vals = np.array([data[t].get(lv, 0) for t in tactics])
        ax.barh(range(len(tactics)), vals, left=left, color=LEVEL_COLORS[lv],
                label=lv, edgecolor="white", linewidth=0.4)
        left += vals
    ax.set_yticks(range(len(tactics)))
    ax.set_yticklabels([f"{TACTIC_DISPLAY[t]} ({TACTIC_TAID[t]})" for t in tactics],
                       fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("Cases", fontsize=10)
    ax.set_title("Severity Distribution by ATT&CK Tactic", pad=12)
    ax.legend(title="Severity", fontsize=8, title_fontsize=8, loc="lower right")
    ax.grid(axis="x", alpha=0.25)
    fig.tight_layout(); fig.savefig(out, dpi=160, bbox_inches="tight"); plt.close(fig)
    print(f"  wrote {out}")


# --------------------------------------------------------------------------- #
# 4. Case x Tactic heatmap — ANONYMIZED case IDs, never message text
# --------------------------------------------------------------------------- #
def chart_case_tactic_heatmap(items, out, max_cases=40):
    tactics = ordered_present_tactics(items)
    if not tactics:
        print("  [skip] case_tactic_heatmap: no tactics"); return
    # only non-benign cases (something mapped), anonymized, capped for readability
    rows, ids = [], []
    n = 0
    for it in items:
        present = Counter(m.get("tactic") for m in it.get("mitre_matches", [])
                          if m.get("tactic") in TACTIC_RANK)
        if sum(present.values()) == 0:
            continue
        n += 1
        if n > max_cases:
            break
        rows.append([present.get(t, 0) for t in tactics])
        ids.append(f"CASE-{n:03d}")
    if not rows:
        print("  [skip] case_tactic_heatmap: no mapped cases"); return
    arr = np.array(rows)
    fig, ax = plt.subplots(figsize=(max(7, 1.0 * len(tactics) + 2),
                                    max(3, 0.32 * len(rows) + 1.8)))
    im = ax.imshow(arr, cmap=HEAT, aspect="auto", vmin=0)
    ax.set_xticks(range(len(tactics)))
    ax.set_xticklabels([tactic_label(t) for t in tactics], fontsize=8)
    ax.set_yticks(range(len(ids)))
    ax.set_yticklabels(ids, fontsize=7, fontfamily="monospace")
    ax.set_title("Case \u00d7 ATT&CK Tactic Heatmap  (anonymized)", pad=12)
    cb = fig.colorbar(im, ax=ax, shrink=0.7)
    cb.set_label("techniques mapped", fontsize=8)
    for i in range(arr.shape[0]):
        for j in range(arr.shape[1]):
            if arr[i, j]:
                ax.text(j, i, str(arr[i, j]), ha="center", va="center", fontsize=7,
                        color="white" if arr[i, j] > arr.max() / 2 else "#222")
    fig.tight_layout(); fig.savefig(out, dpi=160, bbox_inches="tight"); plt.close(fig)
    print(f"  wrote {out}")


# --------------------------------------------------------------------------- #
# 5. Risk distribution donut
# --------------------------------------------------------------------------- #
def chart_risk_distribution(items, out):
    counts = Counter(it["analysis"]["risk_level"] for it in items)
    levels = [lv for lv in LEVEL_ORDER if counts.get(lv)]
    if not levels:
        print("  [skip] risk_distribution: no data"); return
    vals = [counts[lv] for lv in levels]
    fig, ax = plt.subplots(figsize=(6.5, 6.5))
    wedges, _, autot = ax.pie(
        vals, labels=[f"{lv}\n({counts[lv]})" for lv in levels],
        colors=[LEVEL_COLORS[lv] for lv in levels],
        autopct=lambda p: f"{p:.0f}%", startangle=90, pctdistance=0.78,
        wedgeprops=dict(width=0.44, edgecolor="white", linewidth=1.5),
        textprops=dict(fontsize=9))
    for t in autot:
        t.set_color("white"); t.set_fontweight("bold"); t.set_fontsize(9)
    ax.set_title(f"Risk Severity Distribution  ({sum(vals)} cases)", pad=14)
    fig.tight_layout(); fig.savefig(out, dpi=160, bbox_inches="tight"); plt.close(fig)
    print(f"  wrote {out}")


# --------------------------------------------------------------------------- #
# 6. Tactic correlation — gated on N
# --------------------------------------------------------------------------- #
def chart_tactic_correlation(items, out):
    n = len(items)
    if n < MIN_CASES_FOR_CORRELATION:
        print(f"  [skip] tactic_correlation: {n} cases; need "
              f">={MIN_CASES_FOR_CORRELATION} for a statistically meaningful "
              f"correlation."); return
    tactics = ordered_present_tactics(items)
    if len(tactics) < 2:
        print("  [skip] tactic_correlation: <2 tactics"); return
    M = np.zeros((n, len(tactics)))
    for i, it in enumerate(items):
        present = {m.get("tactic") for m in it.get("mitre_matches", [])}
        for j, t in enumerate(tactics):
            M[i, j] = 1.0 if t in present else 0.0
    with np.errstate(invalid="ignore", divide="ignore"):
        corr = np.nan_to_num(np.corrcoef(M.T))
    fig, ax = plt.subplots(figsize=(max(6.5, 0.7 * len(tactics) + 2.5),
                                    max(5.5, 0.7 * len(tactics) + 2)))
    im = ax.imshow(corr, cmap="RdBu_r", vmin=-1, vmax=1, aspect="auto")
    lbls = [f"{TACTIC_DISPLAY[t]} ({TACTIC_TAID[t]})" for t in tactics]
    ax.set_xticks(range(len(tactics)))
    ax.set_xticklabels(lbls, rotation=45, ha="right", fontsize=8)
    ax.set_yticks(range(len(tactics)))
    ax.set_yticklabels(lbls, fontsize=8)
    ax.set_title(f"Tactic Co-occurrence Correlation  (n={n} cases)", pad=12)
    fig.colorbar(im, ax=ax, shrink=0.75, label="Pearson correlation")
    fig.tight_layout(); fig.savefig(out, dpi=160, bbox_inches="tight"); plt.close(fig)
    print(f"  wrote {out}")


# --------------------------------------------------------------------------- #
# Text executive summary — MITRE terms only, no message content
# --------------------------------------------------------------------------- #
def write_exec_summary(items, out, session_dirs):
    counts, names, t_tactic = technique_catalog(items)
    lvl_counts = Counter(it["analysis"]["risk_level"] for it in items)
    tac_cases = Counter()
    for it in items:
        for t in {m.get("tactic") for m in it.get("mitre_matches", [])
                  if m.get("tactic") in TACTIC_RANK}:
            tac_cases[t] += 1
    total = len(items)
    mapped = sum(1 for it in items if it.get("mitre_matches"))
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    L = []
    L.append("=" * 70)
    L.append("  THREAT ENRICHMENT — EXECUTIVE SUMMARY")
    L.append("  Framework: MITRE ATT&CK (Enterprise)")
    L.append(f"  Generated: {now}")
    L.append(f"  Sessions analyzed: {len(session_dirs)}")
    L.append("=" * 70)
    L.append("")
    L.append("OVERVIEW")
    L.append(f"  Total cases analyzed ....... {total}")
    L.append(f"  Cases mapped to ATT&CK ..... {mapped}")
    L.append(f"  Distinct techniques ........ {len(counts)}")
    L.append(f"  Distinct tactics ........... {len(tac_cases)}")
    L.append("")
    L.append("SEVERITY BREAKDOWN")
    for lv in LEVEL_ORDER:
        if lv_count := lvl_counts.get(lv, 0):
            pct = 100 * lv_count / total if total else 0
            L.append(f"  {lv:9} {lv_count:4}  ({pct:4.0f}%)")
    L.append("")
    L.append("TOP ATT&CK TECHNIQUES  (by detection frequency)")
    for tid, c in counts.most_common(10):
        tac = t_tactic.get(tid, "unknown")
        tac_disp = TACTIC_DISPLAY.get(tac, tac)
        L.append(f"  {tid:11} {names[tid][:34]:34} {c:3} case(s)   [{tac_disp}]")
    L.append("")
    L.append("ATT&CK TACTIC COVERAGE  (kill-chain order)")
    for s, disp, taid in TACTICS:
        if s in tac_cases:
            L.append(f"  {taid}  {disp:24} {tac_cases[s]:3} case(s)")
    L.append("")
    L.append("NOTES")
    L.append("  * Counts are detection frequency (cases mapping to an ATT&CK")
    L.append("    technique/tactic), not vulnerability counts. HunterEngine maps")
    L.append("    adversary behaviour per MITRE ATT&CK, not CVEs.")
    L.append("  * Individual cases are anonymized; no message content is included.")
    L.append("  * Technique/tactic IDs and names follow MITRE ATT&CK nomenclature.")
    L.append("=" * 70)
    open(out, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print(f"  wrote {out}")


# --------------------------------------------------------------------------- #
# STIX 2.1 bundle export — machine-readable, standards-compliant findings.
# Mirrors how MITRE publishes ATT&CK as STIX: attack-pattern objects carry an
# external_reference to mitre-attack (external_id = technique ID); each case is
# an anonymized indicator; 'indicates' relationships link cases to techniques.
# IoC values (URLs/domains) are real in the STIX pattern (that is the point of
# shareable intel) but NO message content is ever included. Pass defang_iocs to
# also neutralize the pattern values.
# --------------------------------------------------------------------------- #
ATTACK_URL = "https://attack.mitre.org/techniques/"


def _now_stix():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z")


def _defang(value: str) -> str:
    return value.replace("http://", "hxxp://").replace("https://", "hxxps://") \
                .replace(".", "[.]")


def _attack_url(tid: str) -> str:
    # sub-techniques: T1566.002 -> T1566/002
    return ATTACK_URL + tid.replace(".", "/")


def _stix_pattern_for(indicators: Dict[str, List[str]], defang: bool) -> str:
    """Build a STIX pattern from extracted IoCs (urls / domains / ips / emails)."""
    parts = []
    for url in indicators.get("urls", []):
        v = _defang(url) if defang else url
        parts.append(f"[url:value = '{v}']")
    for dom in indicators.get("domains", []):
        v = _defang(dom) if defang else dom
        parts.append(f"[domain-name:value = '{v}']")
    for ip in indicators.get("ips", []):
        parts.append(f"[ipv4-addr:value = '{ip}']")
    for em in indicators.get("emails", []):
        parts.append(f"[email-addr:value = '{em}']")
    return " OR ".join(parts)


def export_stix_bundle(items, out, defang_iocs=False):
    """Write a STIX 2.1 bundle of findings to `out`. Returns object count."""
    # one shared attack-pattern per distinct technique
    counts, names, t_tactic = technique_catalog(items)
    if not counts:
        print("  [skip] stix_bundle: no ATT&CK techniques to export"); return 0

    now = _now_stix()
    tech_objs = {}     # tid -> stix id
    objects = []

    def new_id(prefix):
        return f"{prefix}--{uuid.uuid4()}"

    # attack-pattern objects (one per technique), MITRE external_reference
    for tid in sorted(counts):
        ap_id = new_id("attack-pattern")
        tech_objs[tid] = ap_id
        ap = {
            "type": "attack-pattern", "spec_version": "2.1", "id": ap_id,
            "created": now, "modified": now, "name": names[tid],
            "external_references": [{
                "source_name": "mitre-attack", "external_id": tid,
                "url": _attack_url(tid),
            }],
        }
        objects.append(ap)

    # indicator per mapped case (anonymized), + 'indicates' relationships
    case_no = 0
    for it in items:
        matches = it.get("mitre_matches", [])
        if not matches:
            continue
        case_no += 1
        case_id = f"CASE-{case_no:03d}"
        level = it["analysis"]["risk_level"]
        iocs = it.get("indicators", {}) or {}
        pattern = _stix_pattern_for(iocs, defang_iocs)
        ind_id = new_id("indicator")
        indicator = {
            "type": "indicator", "spec_version": "2.1", "id": ind_id,
            "created": now, "modified": now, "name": case_id,
            "description": (f"HunterEngine detection ({level}). "
                            f"Case anonymized; no message content included."),
            "indicator_types": ["malicious-activity"],
            "pattern_type": "stix",
            "pattern": pattern if pattern else "[x-hunterengine:detection = 'true']",
            "valid_from": now,
            "labels": [level],
        }
        objects.append(indicator)
        seen = set()
        for m in matches:
            tid = m.get("id")
            if not tid or tid in seen:
                continue
            seen.add(tid)
            rel = {
                "type": "relationship", "spec_version": "2.1",
                "id": new_id("relationship"), "created": now, "modified": now,
                "relationship_type": "indicates",
                "source_ref": ind_id, "target_ref": tech_objs[tid],
            }
            objects.append(rel)

    # If the official library is present, round-trip through it for validation.
    if _HAVE_STIX2:
        try:
            parsed = [_stix2.parse(o, allow_custom=True) for o in objects]
            bundle = _stix2.Bundle(objects=parsed, allow_custom=True)
            open(out, "w", encoding="utf-8").write(bundle.serialize(pretty=True))
            print(f"  wrote {out}  ({len(objects)} STIX objects, stix2-validated)")
            return len(objects)
        except Exception as e:
            print(f"  [warn] stix2 validation failed ({e}); writing raw bundle")

    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    open(out, "w", encoding="utf-8").write(json.dumps(bundle, indent=2))
    print(f"  wrote {out}  ({len(objects)} STIX objects)")
    return len(objects)


# --------------------------------------------------------------------------- #
def newest_session(box):
    s = sorted(glob.glob(os.path.join(box, "session_*")))
    return [s[-1]] if s else []


def main():
    ap = argparse.ArgumentParser(description="MITRE-standardized HunterEngine report generator.")
    ap.add_argument("sessions", nargs="*")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--box", default="HunterEngineBox")
    ap.add_argument("--out", default=None)
    ap.add_argument("--no-stix", action="store_true",
                    help="skip the STIX 2.1 bundle export")
    ap.add_argument("--defang", action="store_true",
                    help="defang IoC values in the STIX pattern (hxxp, [.])")
    args = ap.parse_args()

    if args.all:
        dirs = sorted(glob.glob(os.path.join(args.box, "session_*")))
        default_out = "report_aggregate"
    elif args.sessions:
        dirs = args.sessions
        default_out = (os.path.join(dirs[0], "report") if len(dirs) == 1
                       else "report_aggregate")
    else:
        dirs = newest_session(args.box)
        default_out = os.path.join(dirs[0], "report") if dirs else "report"

    if not dirs:
        sys.exit(f"No sessions under {args.box}/. Run the engine first.")
    out = args.out or default_out
    os.makedirs(out, exist_ok=True)

    print(f"Reading {len(dirs)} session(s).")
    items = load_results(dirs)
    if not items:
        sys.exit("No results found.")
    print(f"Loaded {len(items)} case(s). Writing MITRE-standardized report to {out}/\n")

    chart_technique_frequency(items, os.path.join(out, "01_technique_frequency.png"))
    chart_tactic_coverage(items, os.path.join(out, "02_tactic_coverage.png"))
    chart_severity_by_tactic(items, os.path.join(out, "03_severity_by_tactic.png"))
    chart_case_tactic_heatmap(items, os.path.join(out, "04_case_tactic_heatmap.png"))
    chart_risk_distribution(items, os.path.join(out, "05_risk_distribution.png"))
    chart_tactic_correlation(items, os.path.join(out, "06_tactic_correlation.png"))
    write_exec_summary(items, os.path.join(out, "EXECUTIVE_SUMMARY.txt"), dirs)
    if not args.no_stix:
        export_stix_bundle(items, os.path.join(out, "findings_stix_bundle.json"),
                           defang_iocs=args.defang)

    print(f"\nDone. Report in: {out}/")
    print("Open:  xdg-open " + out)


if __name__ == "__main__":
    main()
