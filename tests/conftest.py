# -*- coding: utf-8 -*-
"""Shared fixtures for the HunterEngine test suite.

All tests run fully offline: MITRE data is injected as small fixtures, and the
AI layers are exercised with stub providers — no network, no API keys.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from HunterEngine import ThreatEnrichmentEngine  # noqa: E402


TEST_CONFIG = {
    "config": {
        "fuzzy_threshold": 85,
        "risk_thresholds": {"LOW": 4, "MEDIUM": 8, "HIGH": 12},
        "score_boosts": {"has_indicator": 5, "mitre_ttp": 6},
    },
    "attack_map": [
        {"id": "T1566", "when": ["action_request", "authority"]},
        {"id": "T1566.002", "when": ["action_request", "has_indicator"]},
        {"id": "T9999.999", "when": ["authority"]},  # unknown: must fail closed
    ],
    "primitives": {
        "urgency": {"score": 3, "keywords": ["urgent", "immediately"]},
        "authority": {"score": 4, "keywords": ["paypal", "it security"]},
        "action_request": {"score": 3, "keywords": ["click", "verify", "login"]},
        "consequence": {"score": 4, "keywords": ["suspended"]},
    },
}

# Minimal stand-in for the real ATT&CK dataset (normally in mitre_cache.json).
FAKE_MITRE_INDEX = {
    "T1566": {"id": "T1566", "name": "Phishing", "tactic": "initial-access"},
    "T1566.002": {"id": "T1566.002", "name": "Spearphishing Link",
                  "tactic": "initial-access"},
}


@pytest.fixture
def config_file(tmp_path):
    path = tmp_path / "primitives.json"
    path.write_text(json.dumps(TEST_CONFIG), encoding="utf-8")
    return str(path)


@pytest.fixture
def engine(config_file):
    """A fully configured engine with fixture MITRE data — no network."""
    eng = ThreatEnrichmentEngine(config_path=config_file)
    eng._load_configuration()
    eng._mitre_index = dict(FAKE_MITRE_INDEX)
    eng.mitre_keywords = {tid: [t["name"].lower()]
                          for tid, t in FAKE_MITRE_INDEX.items()}
    eng.mitre_metadata = list(FAKE_MITRE_INDEX.values())
    return eng
