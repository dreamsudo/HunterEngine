# HunterEngine - The Complete User Manual

## 1. Introduction
Welcome to `HunterEngine`, a standalone Heuristic Threat Enrichment Engine. This
manual is a comprehensive guide for security operators on using, configuring, and
mastering the tool. `HunterEngine` bridges the gap between raw, unstructured text
and actionable security intelligence, automating initial threat triage and
detection engineering.

## 2. Core Concepts
- **Heuristic Primitives:** Malicious communications often share common
  psychological triggers ("primitives", e.g. `urgency`, `authority`). Identifying
  these building blocks yields flexible, resilient detections.
- **Additive Scoring:** Each finding (matched primitive, IoC, MITRE TTP) adds a
  pre-defined value to a running total. The score is transparent and explainable.
- **Fidelity First:** YARA generation includes a guardrail that prevents rules
  built on weak evidence, avoiding false-positive floods.
- **AI is Advisory Only:** The optional AI layer never computes or changes the
  risk score and never takes an action. The deterministic engine is the sole
  source of truth; the model only adds a human-readable note on already-flagged
  HIGH/CRITICAL items.

## 3. Installation & Setup
```bash
cd HunterEngine
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```
The first run downloads the MITRE ATT&CK dataset (~70MB) and builds a local cache
(`mitre_cache.json`) for fast subsequent runs.

## 4. Execution Guide

### Basic Syntax
```bash
python3 HunterEngine.py <input_file> [options]
```
- `<input_file>`: (Required) Path to your input file (`.txt`, `.csv`, `.json`).

### Options
- `-c, --config <path>`: Path to a custom primitives JSON file.
- `--no-banner`: Suppress the startup banner/manual (useful in scripts).
- `--no-ai`: Force-disable the optional AI advisory layer regardless of env.

### Input Formats
- `.txt`: one input per line.
- `.csv`: the first column of each row is used as the input.
- `.json`: a list of strings, or a list of objects each with an `input` field.

### Example Commands
```bash
python3 HunterEngine.py suspicious_sms.txt
python3 HunterEngine.py emails.csv -c primitives/bec_financial_primitives.json
python3 HunterEngine.py logs.json --no-banner --no-ai
```

## 5. The Art of Customization: A Cookbook
The JSON files in `primitives/` are your control panel.

### Anatomy of a Primitive File
- `config`: Global engine settings.
  - `fuzzy_threshold`: How closely a phrase must match a MITRE TTP description
    (0-100).
  - `risk_thresholds`: Score boundaries for LOW, MEDIUM, and HIGH levels.
  - `score_boosts`: Points added when an IoC or MITRE TTP is found.
- `primitives`: The detection logic.
  - Each key (e.g. `urgency`) is a primitive.
  - `score`: Points added when this primitive matches.
  - `keywords`: Words/phrases that trigger this primitive.

### Recipe 1: Creating a New Primitive
Goal: detect package-delivery scams. Under `primitives`, add:
```json
"delivery_lure": {
  "score": 3,
  "keywords": ["delivery failed", "package on hold", "track your shipment", "customs fee", "missed delivery", "reschedule delivery"]
}
```
Save the file; the engine uses the new logic on the next run.

### Recipe 2: Tuning for a Specific Environment
Goal: a financial institution wants more aggressive fraud flagging. Start from
`primitives/bec_financial_primitives.json`, raise the `bec_financial_lure` score
from 6 to 8, and lower the `HIGH` threshold from 10 to 8. Now a single
high-confidence BEC match flags an email as HIGH.

### Recipe 3: Reducing Noise
Goal: `admin` triggers on legitimate IT password-reset emails. Options:
- Lower the `authority` primitive score (e.g. 4 -> 2).
- Use a more specific keyword (`admin` -> `domain admin`).
- Add known-good IT phrasing to the `benign` primitive.

## 6. The Optional AI Advisory Layer

### What it does
For each item the engine rates HIGH or CRITICAL, the AI layer can attach:
- a <=2 sentence summary,
- analyst notes (why it looks malicious / what to verify),
- a short list of recommended next actions,
- an `injection_observed` flag if the input text tried to manipulate the model.

### What it never does
- It never computes or changes the risk score or level.
- It never takes an action (no network calls beyond the model API, no file/rule
  deployment, no remediation execution).

### Configuration (environment variables)
| Variable | Default | Meaning |
|---|---|---|
| `HUNTER_AI_PROVIDER` | `none` | `anthropic`, `openai`, `openai-compatible`, or `none` |
| `HUNTER_AI_MODEL` | (none) | Model string (required when enabled) |
| `HUNTER_AI_BASE_URL` | provider default | Endpoint base URL |
| `HUNTER_AI_API_KEY` | (none) | Credential for cloud providers; never logged |
| `HUNTER_AI_ALLOW_REMOTE` | `0` | Must be `1` to use any non-local endpoint |
| `HUNTER_AI_TIMEOUT` | `30` | Per-call timeout (seconds) |
| `HUNTER_AI_MAX_CALLS` | `25` | Per-run call budget |
| `HUNTER_AI_MAX_INPUT_CHARS` | `4000` | Raw input chars sent per item |
| `HUNTER_AI_MAX_TOKENS` | `512` | Max output tokens per call |

### Security model
- **Inputs are hostile.** Attacker text is wrapped in `BEGIN_DATA`/`END_DATA` and
  the system prompt instructs the model to treat it strictly as data. Output is
  parsed as strict JSON and length-capped.
- **Fail-open.** Any provider/parse error is logged (with secrets redacted) and the
  run continues without that annotation.
- **Safe defaults.** Disabled unless configured; local-only unless
  `HUNTER_AI_ALLOW_REMOTE=1`.

### Adding another provider
Subclass `LLMProvider` in `ai_enrichment.py`, implement `label` and
`complete(system, user, max_tokens)`, and wire it into `AIAdvisor.from_env`. No
other code changes are required - the engine is agnostic to which model answers.

## 7. Troubleshooting
- **`ModuleNotFoundError`:** run `pip install -r requirements.txt`.
- **MITRE download fails:** check connectivity/firewall; the script must reach
  `github.com`.
- **No output generated:** ensure the input file is non-empty and in a supported
  format; check the console for errors.
- **AI layer does nothing:** confirm `HUNTER_AI_PROVIDER` and `HUNTER_AI_MODEL` are
  set, and for cloud endpoints that `HUNTER_AI_ALLOW_REMOTE=1`.
