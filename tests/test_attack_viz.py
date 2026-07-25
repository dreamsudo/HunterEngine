# -*- coding: utf-8 -*-
"""attack_viz.py tests: Navigator layer correctness and SVG output safety."""
from attack_viz import build_heatmap_svg, build_navigator_layer


def results_with(*tids):
    return [{"mitre_matches": [{"id": t, "name": f"Tech {t}",
                                "tactic": "initial-access"} for t in tids]}]


def test_navigator_layer_counts_and_scores():
    results = results_with("T1566") + results_with("T1566", "T1598")
    layer = build_navigator_layer(results, "sess-1")
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores == {"T1566": 2, "T1598": 1}
    assert layer["gradient"]["maxValue"] == 2
    assert layer["domain"] == "enterprise-attack"


def test_navigator_layer_claims_no_stale_attack_version():
    layer = build_navigator_layer(results_with("T1566"), "s")
    assert "attack" not in layer["versions"], \
        "layer must not pin a hardcoded ATT&CK release"


def test_heatmap_escapes_hostile_text():
    results = [{"mitre_matches": [
        {"id": "T0001", "name": '<img src=x onerror=alert(1)>',
         "tactic": "initial-access"}]}]
    svg = build_heatmap_svg(results, '<script>alert(1)</script>')
    # hostile markup must be entity-escaped text, never live tags
    assert "<script>" not in svg
    assert "<img" not in svg
    assert "&lt;script&gt;" in svg
    assert "&lt;img" in svg


def test_heatmap_empty_results():
    assert build_heatmap_svg([], "s") == ""
