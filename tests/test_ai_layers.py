# -*- coding: utf-8 -*-
"""AI advisory + AI-YARA tests using stub providers. No network, no keys.

These encode the security properties of the AI layers:
  * egress guard: loopback-only unless HUNTER_AI_ALLOW_REMOTE=1
  * model output is untrusted: validated, truncated, single-line
  * hostile YARA string suggestions are neutralized by escaping
  * failures degrade gracefully (fail-open, run continues)
"""
import json

import pytest

import yara_ai
from ai_enrichment import (
    AIAdvisor, _extract_json, _is_local_url, _redact, _validate,
    build_provider_from_env,
)

try:
    import yara
except ImportError:
    yara = None


@pytest.fixture(autouse=True)
def clean_ai_env(monkeypatch):
    for var in ("HUNTER_AI_PROVIDER", "HUNTER_AI_MODEL", "HUNTER_AI_BASE_URL",
                "HUNTER_AI_API_KEY", "HUNTER_AI_ALLOW_REMOTE",
                "HUNTER_AI_TIMEOUT", "HUNTER_AI_MAX_CALLS",
                "HUNTER_AI_MAX_INPUT_CHARS", "HUNTER_AI_MAX_TOKENS"):
        monkeypatch.delenv(var, raising=False)


def make_item(level="CRITICAL", score=20, text="click http://evil.example"):
    return {"input": text, "indicators": {},
            "mitre_matches": [],
            "analysis": {"risk_score": score, "risk_level": level, "tags": []}}


class StubProvider:
    """Deterministic in-process 'model'."""

    def __init__(self, reply):
        self.reply = reply
        self.calls = 0
        self.label = "stub:test"

    def complete(self, system, user, max_tokens):
        self.calls += 1
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


# --------------------------------------------------------------------------- #
# Egress guard
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("url,expected", [
    ("http://localhost:11434/v1", True),
    ("http://127.0.0.1:8080", True),
    ("http://127.9.9.9", True),
    ("http://[::1]:9", True),
    ("http://0.0.0.0:1", True),
    ("http://evil.local/v1", False),        # mDNS: resolves to OTHER machines
    ("https://api.anthropic.com", False),
    ("http://192.168.1.5:11434", False),
    ("http://10.0.0.1", False),
    ("", False),
])
def test_is_local_url(url, expected):
    assert _is_local_url(url) is expected


def test_remote_provider_refused_without_optin(monkeypatch, caplog):
    monkeypatch.setenv("HUNTER_AI_PROVIDER", "anthropic")
    monkeypatch.setenv("HUNTER_AI_MODEL", "some-model")
    monkeypatch.setenv("HUNTER_AI_API_KEY", "sk-test-dummy")
    provider, _ = build_provider_from_env()
    assert provider is None, "cloud egress must require explicit opt-in"


def test_remote_provider_allowed_with_optin(monkeypatch):
    monkeypatch.setenv("HUNTER_AI_PROVIDER", "anthropic")
    monkeypatch.setenv("HUNTER_AI_MODEL", "some-model")
    monkeypatch.setenv("HUNTER_AI_API_KEY", "sk-test-dummy")
    monkeypatch.setenv("HUNTER_AI_ALLOW_REMOTE", "1")
    provider, _ = build_provider_from_env()
    assert provider is not None


def test_local_provider_needs_no_optin(monkeypatch):
    monkeypatch.setenv("HUNTER_AI_PROVIDER", "openai-compatible")
    monkeypatch.setenv("HUNTER_AI_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.setenv("HUNTER_AI_MODEL", "local-model")
    provider, _ = build_provider_from_env()
    assert provider is not None


def test_ai_disabled_by_default():
    provider, _ = build_provider_from_env()
    assert provider is None


# --------------------------------------------------------------------------- #
# Model-output validation (untrusted input)
# --------------------------------------------------------------------------- #
def test_extract_json_from_fenced_prose():
    raw = 'Sure!\n```json\n{"summary": "s"}\n```\nHope this helps.'
    assert _extract_json(raw) == {"summary": "s"}


def test_extract_json_garbage_returns_none():
    assert _extract_json("a poem instead of JSON") is None
    assert _extract_json("") is None


def test_validate_collapses_newlines():
    """Regression: newlines in model output could forge markdown structure
    (fake headings/sections) in the analyst report."""
    out = _validate({
        "summary": "line1\n\n# Injected Heading\nline2",
        "analyst_notes": "a\nb",
        "recommended_actions": ["ok", "x\ny", 42, "z" * 500] + ["pad"] * 10,
    })
    assert "\n" not in out["summary"]
    assert "\n" not in out["analyst_notes"]
    assert all("\n" not in a for a in out["recommended_actions"])
    assert len(out["recommended_actions"]) <= 6
    assert all(len(a) <= 200 for a in out["recommended_actions"])


def test_validate_rejects_junk():
    assert _validate(None) is None
    assert _validate("not a dict") is None
    assert _validate({"summary": "   "}) is None, "empty summary means no advisory"


def test_redact_credentials():
    s = _redact("Bearer abc.def-123 sk-ant-abcdefgh1234 x-api-key: topsecret9")
    assert "abc.def-123" not in s
    assert "sk-ant-abcdefgh1234" not in s
    assert "topsecret9" not in s


# --------------------------------------------------------------------------- #
# Advisor orchestration
# --------------------------------------------------------------------------- #
GOOD_REPLY = json.dumps({"summary": "Phish.", "injection_observed": False,
                         "analyst_notes": "n", "recommended_actions": ["a"]})


def advisor_with(provider, max_calls=25):
    return AIAdvisor(provider, max_calls=max_calls,
                     max_input_chars=4000, max_tokens=512)


def test_annotate_only_high_and_critical():
    provider = StubProvider(GOOD_REPLY)
    items = [make_item("LOW", 3), make_item("MEDIUM", 6),
             make_item("HIGH", 13), make_item("CRITICAL", 20)]
    advisor_with(provider).annotate(items)
    assert provider.calls == 2
    assert "ai_advisory" not in items[0] and "ai_advisory" not in items[1]
    assert items[2]["ai_advisory"]["summary"] == "Phish."
    assert items[3]["ai_advisory"]["_model"] == "stub:test"


def test_annotate_respects_call_budget():
    provider = StubProvider(GOOD_REPLY)
    items = [make_item() for _ in range(5)]
    advisor_with(provider, max_calls=2).annotate(items)
    assert provider.calls == 2


def test_annotate_never_touches_scores():
    provider = StubProvider(json.dumps(
        {"summary": "s", "risk_score": 0, "risk_level": "INFO"}))
    item = make_item("CRITICAL", 20)
    advisor_with(provider).annotate([item])
    assert item["analysis"]["risk_score"] == 20
    assert item["analysis"]["risk_level"] == "CRITICAL"


def test_annotate_survives_provider_errors_and_garbage():
    items = [make_item()]
    advisor_with(StubProvider(RuntimeError("boom"))).annotate(items)
    assert "ai_advisory" not in items[0]
    advisor_with(StubProvider("not json at all")).annotate(items)
    assert "ai_advisory" not in items[0]


# --------------------------------------------------------------------------- #
# AI-YARA drafting
# --------------------------------------------------------------------------- #
HOSTILE_DRAFT = json.dumps({
    "strings": ["evil-domain.example",
                '" nocase } condition: true } rule pwn { $a = "x',
                "legit multi word phrase"],
    "min_matches": 2,
    "rationale": 'inject" \\ attempt',
})


def test_validate_draft_clamps_and_dedupes():
    parsed = yara_ai._validate_draft({
        "strings": ["a" * 999, "dup", "dup", ""] + [f"s{i}" for i in range(20)],
        "min_matches": 99,
    })
    strings, min_matches, _ = parsed
    assert len(strings) <= yara_ai.MAX_STRINGS
    assert strings.count("dup") == 1
    assert all(len(s) <= yara_ai.MAX_STRING_LEN for s in strings)
    assert min_matches <= len(strings)
    assert yara_ai._validate_draft({"strings": "not a list"}) is None
    assert yara_ai._validate_draft(None) is None


def test_assemble_rule_neutralizes_hostile_strings():
    item = make_item()
    strings, mm, rationale = yara_ai._validate_draft(json.loads(HOSTILE_DRAFT))
    rule = yara_ai._assemble_rule(item, strings, mm, rationale, "stub:test")
    assert rule.startswith("rule ai_draft_")
    assert '\\"' in rule  # hostile quotes escaped into the string literal
    if yara is not None:
        compiled = yara.compile(source=rule)
        # the breakout attempt stayed inert data: exactly ONE rule exists,
        # and the attacker's "rule pwn" was never created
        assert [r.identifier for r in compiled] == [rule.split()[1]]


@pytest.mark.skipif(yara is None, reason="yara-python not installed")
def test_draft_ai_yara_dedupes_and_gates(monkeypatch):
    provider = StubProvider(HOSTILE_DRAFT)
    monkeypatch.setattr(yara_ai, "build_provider_from_env",
                        lambda purpose="ai": (provider, {
                            "max_calls": 25, "max_input_chars": 4000,
                            "max_tokens": 512}))
    same = make_item(text="identical wire fraud lure")
    results = [same, dict(same), make_item(text="a different lure entirely"),
               make_item("LOW", 2, "benign")]
    rules, summary = yara_ai.draft_ai_yara(results)
    assert provider.calls == 2, "duplicate inputs must not burn provider calls"
    assert summary["drafted"] == 2 and summary["compiled_ok"] == 2
    combined = yara_ai.quarantine_header("stub:test", "TEST") + "\n".join(rules)
    assert "HUMAN REVIEW REQUIRED" in combined
    yara.compile(source=combined)  # whole quarantine file must compile


def test_draft_ai_yara_requires_compile_gate(monkeypatch):
    """No yara-python -> no gate -> the feature must refuse to run."""
    monkeypatch.setattr(yara_ai, "yara", None)
    rules, summary = yara_ai.draft_ai_yara([make_item()])
    assert rules == []
    assert summary["status"].startswith("skipped")
