# HunterEngine - Heuristic Threat Enrichment Engine

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)

`HunterEngine` is a standalone security tool that enriches unstructured text data
with actionable threat intelligence and automatically generates high-fidelity
YARA rules for proactive threat hunting. It optionally attaches an **advisory-only**
AI analysis note to high-risk findings via a model-agnostic interface.

---

## Key Features

- **Automated Triage:** Ingests raw text (emails, SMS, logs) and assigns a risk
  score and level (Info, Low, Medium, High, Critical).
- **High-Fidelity YARA Generation:** Creates specific, low-noise YARA rules based
  on concrete evidence, preventing false-positive floods.
- **MITRE ATT&CK Mapping:** Adds strategic context by mapping inputs to relevant
  adversary tactics and techniques.
- **Context-Rich IoC Reporting:** Extracts URLs, IPs, domains, and emails and
  links them back to their source input and risk level.
- **Optional AI Advisory Layer:** Model- and capability-agnostic. Adds a
  plain-English summary to HIGH/CRITICAL items. **Advisory only** - it never
  changes the deterministic score and never drives an action. Off by default.
- **Tunable:** Detection logic lives in external JSON "primitive" files.

## Getting Started

### 1. Installation

```bash
cd HunterEngine
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. First Run

The first run downloads and caches the MITRE ATT&CK data (~70MB), with size caps
to guard against a tampered/oversized source.

```bash
python3 HunterEngine.py /path/to/your/input.txt
```

### 3. Custom Profiles

```bash
# Business Email Compromise profile
python3 HunterEngine.py emails.csv -c primitives/bec_financial_primitives.json

# Insider/exfiltration profile
python3 HunterEngine.py syslogs.txt -c primitives/insider_exfil_primitives.json
```

### 4. Optional AI Advisory Layer (off by default)

The AI layer is fully optional and model-agnostic. It only annotates items the
engine already rated HIGH or CRITICAL, and its output never affects the score.

**Local model (no data leaves your host, no extra flag needed):**

```bash
export HUNTER_AI_PROVIDER=openai-compatible
export HUNTER_AI_BASE_URL=http://localhost:11434/v1   # e.g. Ollama
export HUNTER_AI_MODEL=<your-local-model>
python3 HunterEngine.py emails.csv
```

**Cloud model (sends input text to a third party - opt in explicitly):**

```bash
export HUNTER_AI_PROVIDER=anthropic        # or: openai
export HUNTER_AI_MODEL=<your-model-string>
export HUNTER_AI_API_KEY=<key>             # never hardcode; env only
export HUNTER_AI_ALLOW_REMOTE=1            # REQUIRED for any non-local endpoint
python3 HunterEngine.py emails.csv
```

> **Privacy:** Inputs frequently contain PII. Remote/cloud AI ships that text to a
> provider. The tool refuses to do this unless `HUNTER_AI_ALLOW_REMOTE=1` is set.
> Disable AI entirely at any time with `--no-ai`.

## Understanding the Output

All results are saved under `HunterEngineBox/session_<timestamp>/` (created
owner-only where the OS supports it):

- `_summary_report.md`: Start here. High-level report of critical findings,
  including any AI advisory notes.
- `_all_yara_rules.yara`: All generated YARA rules, ready for review/deployment.
- `_all_indicators.json`: All IoCs, linked to source input and risk level.
- `results.json`: Raw detailed JSON for every input.
- `_stats.json`: Run statistics.

## Customization

The JSON files in `primitives/` are your control panel. See `MANUAL.md` for a full
guide to creating and tuning primitive files.

## License

MIT License. See `LICENSE`. Review `LEGAL_DISCLOSURE.md` for the ethical-use policy.
