# -*- coding: utf-8 -*-
"""Deterministic-core tests: scoring, IoC extraction, ATT&CK mapping,
YARA generation, output writing. Fully offline."""
import json
import os
import stat

import pytest

import HunterEngine
from HunterEngine import (
    _dedupe_yara_rules, _md_inline, load_inputs, save_results,
)

try:
    import yara
except ImportError:
    yara = None

LURE = ("URGENT: verify your PayPal account was suspended, "
        "click http://evil.example.com now")


# --------------------------------------------------------------------------- #
# Scoring / risk levels
# --------------------------------------------------------------------------- #
def test_risk_level_boundaries(engine):
    assert engine.get_risk_level(0) == "INFO"
    assert engine.get_risk_level(4) == "LOW"
    assert engine.get_risk_level(5) == "MEDIUM"
    assert engine.get_risk_level(8) == "MEDIUM"
    assert engine.get_risk_level(12) == "HIGH"
    assert engine.get_risk_level(13) == "CRITICAL"


def test_enrich_text_score_composition(engine):
    result = engine.enrich_text(LURE)
    analysis = result["analysis"]
    # urgency 3 + authority 4 + action_request 3 + consequence 4
    # + has_indicator 5 + mitre_ttp 6
    assert analysis["risk_score"] == 25
    assert analysis["risk_level"] == "CRITICAL"
    assert "has_indicator" in analysis["tags"]
    assert "initial-access" in analysis["tags"]


def test_enrichment_is_deterministic(engine):
    assert engine.enrich_text(LURE) == engine.enrich_text(LURE)


def test_no_tag_input_logged_privately(engine, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = engine.enrich_text("completely benign text with no signals")
    assert result["analysis"]["risk_score"] == 0
    assert result["analysis"]["risk_level"] == "INFO"
    miss_log = tmp_path / HunterEngine.MISS_LOG
    assert miss_log.exists()
    if os.name != "nt":
        mode = stat.S_IMODE(miss_log.stat().st_mode)
        assert mode == 0o600, "raw-input logs must be owner-only"


# --------------------------------------------------------------------------- #
# Indicator extraction
# --------------------------------------------------------------------------- #
def test_extract_indicators(engine):
    text = ("Go to http://evil.example.com/x now, or bad.example.net, "
            "mail admin@corp.example.org from 10.1.2.3")
    inds = engine._extract_indicators(text)
    assert "http://evil.example.com/x" in inds["urls"]
    # domain inside the URL is deduplicated; standalone domain kept
    assert "bad.example.net" in inds["domains"]
    assert "evil.example.com" not in inds.get("domains", [])
    assert "admin@corp.example.org" in inds["emails"]
    assert "10.1.2.3" in inds["ipv4"]


def test_extract_indicators_rejects_invalid_ip(engine):
    inds = engine._extract_indicators("connect to 999.999.999.999 please")
    assert "ipv4" not in inds


# --------------------------------------------------------------------------- #
# ATT&CK mapping (combo rules, fail-closed)
# --------------------------------------------------------------------------- #
def test_map_attack_fires_only_when_all_signals_present(engine):
    assert {m["id"] for m in engine._map_attack({"action_request", "authority"})} \
        == {"T1566"}
    hits = engine._map_attack(
        {"action_request", "authority", "has_indicator"})
    assert {m["id"] for m in hits} == {"T1566", "T1566.002"}
    assert engine._map_attack({"urgency"}) == []


def test_map_attack_unknown_id_fails_closed(engine, caplog):
    hits = engine._map_attack({"authority"})  # T9999.999 rule matches signals
    assert hits == [], "unknown technique IDs must be skipped, never emitted"
    assert "T9999.999" in caplog.text


def test_map_attack_uses_dataset_names_not_config(engine):
    (hit,) = engine._map_attack({"action_request", "authority"})
    assert hit["name"] == "Phishing"
    assert hit["tactic"] == "initial-access"
    assert hit["via"] == ["action_request", "authority"]


# --------------------------------------------------------------------------- #
# YARA generation
# --------------------------------------------------------------------------- #
def test_yara_rule_structure(engine):
    result = engine.enrich_text(LURE)
    rule = result["yara_rule"]
    assert rule.strip().startswith("rule threat_heuristic_")
    # weak single tokens (click, paypal, urgent...) filtered; url + 'suspended' kept
    assert '"http://evil.example.com"' in rule
    assert '"suspended"' in rule
    assert '"click"' not in rule
    assert "all of them" in rule


def test_yara_string_strength_filter(engine):
    assert engine._yara_string_is_strong("multi word phrase")
    assert engine._yara_string_is_strong("http://x.example")
    assert engine._yara_string_is_strong("a@b.example")
    assert engine._yara_string_is_strong("10.0.0.1")
    assert engine._yara_string_is_strong("credentials")     # >= min token len
    assert not engine._yara_string_is_strong("click")       # short + generic


def test_yara_sanitizer_escapes_hostile_input(engine):
    hostile = 'x" nocase } condition: true } rule pwn { $a = "y\\z\x01'
    out = engine._sanitize_yara_string(hostile)
    assert '\\"' in out and "\\\\" in out and "\\x01" in out
    assert '" nocase' not in out.replace('\\"', "")


def test_zero_score_input_gets_no_rule(engine):
    assert engine.enrich_text("benign nothing here")["yara_rule"] == ""


def test_dedupe_yara_rules():
    a = "rule alpha\n{ condition: true }"
    b = "rule beta\n{ condition: true }"
    assert _dedupe_yara_rules([a, a, b, a]) == [a, b]


@pytest.mark.skipif(yara is None, reason="yara-python not installed")
def test_generated_rules_compile_with_duplicates_collapsed(
        engine, tmp_path, monkeypatch):
    """Regression: identical inputs used to emit identically-named rules,
    making the whole deployable ruleset fail to compile."""
    monkeypatch.chdir(tmp_path)
    results = [engine.enrich_text(LURE) for _ in range(2)]
    results.append(engine.enrich_text(
        "IT Security here — login suspended, verify at "
        "http://mail-portal-reset.example immediately"))
    save_results(results)
    (session,) = (tmp_path / HunterEngine.OUTPUT_ROOT).iterdir()
    rules_file = session / "_all_yara_rules.yara"
    text = rules_file.read_text(encoding="utf-8")
    assert text.count("rule threat_heuristic_") == 2, "duplicates must collapse"
    yara.compile(filepath=str(rules_file))  # raises on any invalid output


# --------------------------------------------------------------------------- #
# Output/session handling
# --------------------------------------------------------------------------- #
def test_sessions_never_merge_on_same_second(engine, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    results = [engine.enrich_text(LURE)]
    save_results(results)
    save_results(results)  # same wall-clock second
    sessions = sorted((tmp_path / HunterEngine.OUTPUT_ROOT).iterdir())
    assert len(sessions) == 2, "concurrent runs must not share a session dir"


def test_report_neutralizes_hostile_input(engine, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = engine.enrich_text(
        "click to verify your suspended paypal account urgent")
    # simulate multi-line hostile input arriving via JSON ingestion
    result["input"] = "line1\n# Forged Heading\nline2 `code` end" + result["input"]
    result["analysis"]["risk_level"] = "CRITICAL"
    save_results([result])
    (session,) = (tmp_path / HunterEngine.OUTPUT_ROOT).iterdir()
    report = (session / "_summary_report.md").read_text(encoding="utf-8")
    assert "\n# Forged Heading" not in report
    assert "`code`" not in report


def test_md_inline():
    assert _md_inline("a\nb\tc") == "a b c"
    assert "`" not in _md_inline("x`whoami`y")


# --------------------------------------------------------------------------- #
# Input loading
# --------------------------------------------------------------------------- #
def test_load_inputs_txt(tmp_path):
    p = tmp_path / "in.txt"
    p.write_text("one\n\n  two  \n", encoding="utf-8")
    assert list(load_inputs(str(p))) == ["one", "two"]


def test_load_inputs_csv_first_column(tmp_path):
    p = tmp_path / "in.csv"
    p.write_text('first,extra\n"second, quoted",x\n', encoding="utf-8")
    assert list(load_inputs(str(p))) == ["first", "second, quoted"]


def test_load_inputs_json_variants(tmp_path):
    p = tmp_path / "in.json"
    p.write_text(json.dumps([{"input": "from dict"}, "bare string"]),
                 encoding="utf-8")
    assert list(load_inputs(str(p))) == ["from dict", "bare string"]


def test_input_length_cap(engine):
    huge = "urgent " * 60_000
    result = engine.enrich_text(huge)
    assert len(result["input"]) <= HunterEngine.MAX_INPUT_LEN
