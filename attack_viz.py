#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
attack_viz.py - Standards-based ATT&CK technique output and visualization.

Produces, from a batch of HunterEngine results:
  * _attack_navigator.json - a MITRE ATT&CK Navigator layer (v4.5 schema). Drop
    it into https://mitre-attack.github.io/attack-navigator/ (or any tool that
    reads the layer format) for the canonical interactive technique heatmap.
  * _attack_heatmap.svg - a self-contained heatmap of the techniques that fired,
    ranked by count, viewable without any external tool.

Counts are how many inputs mapped to each technique across the run. No network,
no new dependencies; everything is derived from results already in memory.
"""
from __future__ import annotations

import json
import html
from collections import Counter
from typing import List, Dict, Any, Tuple

NAVIGATOR_VERSION = "4.5"
LAYER_VERSION = "4.5"


def _technique_counts(results: List[Dict[str, Any]]) -> Tuple[Counter, Dict[str, str]]:
    """Return (counts by technique id, id->name)."""
    counts: Counter = Counter()
    names: Dict[str, str] = {}
    for r in results:
        for m in r.get("mitre_matches", []):
            tid = m.get("id")
            if not tid:
                continue
            counts[tid] += 1
            names[tid] = m.get("name", tid)
    return counts, names


def build_navigator_layer(results: List[Dict[str, Any]], session_id: str,
                          name: str = "HunterEngine") -> Dict[str, Any]:
    """Build a MITRE ATT&CK Navigator layer dict from results."""
    counts, names = _technique_counts(results)
    max_count = max(counts.values()) if counts else 0

    techniques = []
    for tid, count in counts.most_common():
        techniques.append({
            "techniqueID": tid,
            "score": count,
            "comment": f"{names.get(tid, tid)} — matched in {count} input(s)",
            "enabled": True,
        })

    return {
        "name": f"{name} {session_id}",
        "versions": {
            "attack": "14",
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": (
            "Techniques mapped by HunterEngine across this session. Score = number "
            "of inputs that mapped to the technique."),
        "sorting": 3,  # descending by score
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe8e8", "#fc3d3d"],
            "minValue": 0,
            "maxValue": max_count if max_count else 1,
        },
        "legendItems": [],
        "metadata": [
            {"name": "tool", "value": "HunterEngine"},
            {"name": "session", "value": session_id},
            {"name": "total_inputs", "value": str(len(results))},
        ],
    }


def write_navigator_layer(results: List[Dict[str, Any]], path: str,
                          session_id: str) -> bool:
    layer = build_navigator_layer(results, session_id)
    if not layer["techniques"]:
        return False
    with open(path, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)
    return True


# --------------------------------------------------------------------------- #
# Self-contained SVG heatmap (no external tool needed).
# --------------------------------------------------------------------------- #
def _heat_color(count: int, max_count: int) -> str:
    """Interpolate light->dark red by count."""
    if max_count <= 0:
        return "#ffe8e8"
    t = count / max_count
    # from (255,232,232) to (252,61,61)
    r = int(255 + (252 - 255) * t)
    g = int(232 + (61 - 232) * t)
    b = int(232 + (61 - 232) * t)
    return f"#{r:02x}{g:02x}{b:02x}"


def build_heatmap_svg(results: List[Dict[str, Any]], session_id: str) -> str:
    counts, names = _technique_counts(results)
    if not counts:
        return ""
    items = counts.most_common()
    max_count = max(counts.values())

    row_h = 30
    top = 70
    width = 760
    height = top + row_h * len(items) + 30
    bar_x = 250
    bar_max_w = width - bar_x - 70

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" font-family="Segoe UI, Helvetica, Arial, sans-serif">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        f'<text x="20" y="32" font-size="20" font-weight="700" fill="#1a1a1a">'
        f'ATT&amp;CK Technique Heatmap</text>',
        f'<text x="20" y="52" font-size="12" fill="#666">Session {html.escape(session_id)} '
        f'— {len(results)} input(s), {len(items)} technique(s)</text>',
    ]

    y = top
    for tid, count in items:
        nm = html.escape(names.get(tid, tid))
        if len(nm) > 26:
            nm = nm[:25] + "\u2026"
        bar_w = max(4, int(bar_max_w * count / max_count))
        color = _heat_color(count, max_count)
        parts.append(
            f'<text x="20" y="{y + 20}" font-size="13" font-weight="600" '
            f'fill="#222">{html.escape(tid)}</text>')
        parts.append(
            f'<text x="95" y="{y + 20}" font-size="12" fill="#555">{nm}</text>')
        parts.append(
            f'<rect x="{bar_x}" y="{y + 6}" width="{bar_w}" height="{row_h - 12}" '
            f'rx="3" fill="{color}" stroke="#e0c0c0" stroke-width="0.5"/>')
        parts.append(
            f'<text x="{bar_x + bar_w + 8}" y="{y + 20}" font-size="12" '
            f'font-weight="600" fill="#444">{count}</text>')
        y += row_h

    parts.append('</svg>')
    return "\n".join(parts)


def write_heatmap_svg(results: List[Dict[str, Any]], path: str,
                      session_id: str) -> bool:
    svg = build_heatmap_svg(results, session_id)
    if not svg:
        return False
    with open(path, "w", encoding="utf-8") as f:
        f.write(svg)
    return True
