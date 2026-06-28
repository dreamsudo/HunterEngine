# HunterEngine — Comprehensive Operator & Developer Manual

**A deterministic heuristic threat-enrichment engine for suspicious text
(phishing, BEC, insider-exfiltration lures), with glass-box MITRE ATT&CK
mapping, optional advisory AI, YARA generation, visualization, and
STIX 2.1 / TAXII-ready export.**

---

## Table of Contents

1. [What HunterEngine Is](#1-what-hunterengine-is)
2. [Design Philosophy: Glass-Box, Deterministic-First](#2-design-philosophy)
3. [Installation & Environment](#3-installation--environment)
4. [Quick Start](#4-quick-start)
5. [Core Concepts](#5-core-concepts)
6. [Running the Engine (CLI Reference)](#6-running-the-engine-cli-reference)
7. [Input Formats](#7-input-formats)
8. [Output Artifacts](#8-output-artifacts)
9. [The Scoring Model](#9-the-scoring-model)
10. [ATT&CK Technique Mapping](#10-attck-technique-mapping)
11. [The Optional AI Advisory Layer](#11-the-optional-ai-advisory-layer)
12. [AI-Assisted YARA Drafting](#12-ai-assisted-yara-drafting)
13. [Visualization: Navigator Layer & Heatmap](#13-visualization)
14. [Reporting: `generate_report.py`](#14-reporting-generate_reportpy)
15. [STIX 2.1 / TAXII Export](#15-stix-21--taxii-export)
16. [The Pipeline Test Harness](#16-the-pipeline-test-harness)
17. [Writing & Extending Primitive Profiles](#17-writing--extending-primitive-profiles)
18. [Environment Variable Reference](#18-environment-variable-reference)
19. [Security Considerations](#19-security-considerations)
20. [Troubleshooting](#20-troubleshooting)
21. [File-by-File Reference](#21-file-by-file-reference)

---

## 1. What HunterEngine Is

HunterEngine ingests a batch of text items — email bodies, chat messages,
ticket text, any short documents — and for each one produces:

- a **risk score** and **severity level** (INFO / LOW / MEDIUM / HIGH / CRITICAL),
- a set of **heuristic tags** describing *why* it scored (e.g. `urgency`,
  `authority_impersonation`, `exfil_channel`),
- extracted **indicators of compromise** (URLs, domains, IPs, emails),
- a list of **MITRE ATT&CK techniques** the text exhibits, each validated
  against a local copy of the real ATT&CK dataset,
- a **YARA rule** for detection reuse,
- and (optionally) a short **AI advisory note** with analyst action items.

Across a batch it also emits session-level **statistics**, a **MITRE ATT&CK
Navigator layer**, and a **heatmap**. A separate reporting tool turns one or
many sessions into clean charts, a plain-language executive summary, and a
**STIX 2.1 bundle** for sharing into other security platforms.

It is built for **defensive** use: triage queues, phishing-report inboxes,
SOC enrichment, threat-intel production, and detection engineering.

---

## 2. Design Philosophy

### Deterministic-first, glass-box

The verdict is computed **entirely by deterministic rules**. The same input
always produces the same score, the same tags, and the same technique mapping.
You can read the code and trace exactly why any item scored the way it did.

### AI is strictly advisory and downstream

The optional AI layer runs **after** the verdict is finalized. It can attach a
human-readable note and suggested actions. **It can never change a score, a
severity, a tag, or a technique mapping.** If you turn the AI off, the numbers
are byte-for-byte identical. This is deliberate: the trustworthy part of the
system is auditable and offline; the AI is a convenience on top.

### Fail-closed on ATT&CK

Every technique ID the engine would emit is validated against the locally
cached ATT&CK dataset. If an ID is unknown or has been renumbered, it is
**logged and skipped** — never guessed, never emitted from model memory. Names
and tactics come from the real dataset, not from anywhere else.

---

## 3. Installation & Environment

### Requirements

- Python 3.10+ (tested on 3.13)
- The Python packages in `requirements.txt`:
  `requests`, `tqdm`, `rapidfuzz`, `stix2`
- Optional, feature-gated:
  - `yara-python` — required only for `--ai-yara`
  - `matplotlib`, `numpy` — required only for `generate_report.py`

### Setup (recommended: virtual environment)

On Debian/Kali and other PEP-668 "externally managed" systems you **must** use
a virtual environment or you will get an `externally-managed-environment` error.

```bash
cd HunterEngine
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# optional features:
pip install yara-python          # for AI-YARA drafting
pip install matplotlib numpy     # for the reporting tool
```

Re-activate the environment (`source .venv/bin/activate`) in every new shell
before running the engine.

### First run downloads ATT&CK

On first use the engine builds `mitre_cache.json` from the ATT&CK dataset
(~900+ enterprise techniques). This happens once and is then reused. If the
cache becomes stale or corrupt, delete it and it will rebuild:

```bash
rm mitre_cache.json
```

---

## 4. Quick Start

```bash
# 1. activate the venv
source .venv/bin/activate

# 2. analyze a file of suspicious messages (one per line), deterministic only
python3 HunterEngine.py test_input.txt --no-ai -c primitives/merged_primitives.json

# 3. look at the results
ls HunterEngineBox/session_*/
cat HunterEngineBox/session_*/_summary_report.md

# 4. build a professional report across all sessions
python3 generate_report.py --all
xdg-open report_aggregate
```

That is the whole loop: analyze → inspect → report.

---

## 5. Core Concepts

| Term | Meaning |
|------|---------|
| **Primitive** | A named heuristic with a score and a keyword list (e.g. `urgency`). When any keyword matches, the primitive "fires" and contributes its score and tag. |
| **Profile** | A JSON file bundling primitives, engine config, and ATT&CK combo-rules. Selected with `-c`. |
| **Signal** | A primitive that fired on a given input, plus derived signals like `has_indicator`. Signals drive ATT&CK mapping. |
| **Combo-rule** | An entry in `attack_map` that fires a technique only when **all** listed signals are present. |
| **Session** | One run. Each run writes a timestamped folder under `HunterEngineBox/`. |
| **Advisory** | The optional AI note attached to HIGH/CRITICAL items. Never affects scoring. |

---

## 6. Running the Engine (CLI Reference)

```
python3 HunterEngine.py <input_file> [options]
```

| Argument / Flag | Description |
|-----------------|-------------|
| `input_file` (positional) | Path to input: `.txt` (one item per line), `.csv`, or `.json`. |
| `-c, --config <path>` | Path to a primitive profile JSON. Defaults to the built-in default phishing profile if omitted. Use `primitives/merged_primitives.json` for general-purpose any-input handling. |
| `--no-banner` | Suppress the startup banner. |
| `--no-ai` | Force the AI advisory layer **off** regardless of environment variables. Pure deterministic run. |
| `--ai-yara` | Enable AI-assisted YARA drafting (requires `yara-python` and a configured AI provider). Output goes to a separate review file, never the deployable rules. |

The AI advisory layer is **off by default** unless AI environment variables are
set (see §11 and §18). `--no-ai` is an explicit override that wins over the
environment.

### Examples

```bash
# Deterministic only, merged profile
python3 HunterEngine.py inbox.txt --no-ai -c primitives/merged_primitives.json

# With cloud AI advisory (requires env vars from §11)
python3 HunterEngine.py inbox.txt -c primitives/merged_primitives.json

# Deterministic verdict + AI-drafted YARA candidates for review
python3 HunterEngine.py inbox.txt --no-ai --ai-yara -c primitives/merged_primitives.json
```

---

## 7. Input Formats

- **`.txt`** — one item per line. Blank lines are skipped.
- **`.csv`** — the engine reads text from each row. Use this for exported
  ticket/email tables.
- **`.json`** — a list of objects, each with an `input` field (other fields are
  ignored), or a list of strings.

Keep items reasonably short (the AI layer truncates very long items per
`HUNTER_AI_MAX_INPUT_CHARS`; deterministic scoring reads the whole item).

---

## 8. Output Artifacts

Every run creates `HunterEngineBox/session_<timestamp>/` containing:

| File | Contents |
|------|----------|
| `results.json` | The full structured result for every input. This is the canonical machine-readable output and the input to `generate_report.py`. |
| `_summary_report.md` | Human-readable per-item report: score, level, tags, indicators, techniques, and any AI advisory. |
| `_all_yara_rules.yara` | Deterministically generated YARA rules, one per scored item. Deployable. |
| `_ai_yara_NEEDS_REVIEW.yara` | *(only with `--ai-yara`)* AI-drafted YARA candidates. **Not deployable as-is** — compile-checked but unverified. |
| `_all_indicators.json` | Extracted IoCs per item (URLs/domains/IPs/emails). |
| `_stats.json` | Session statistics: counts by level, tag frequencies, top techniques. |
| `_attack_navigator.json` | MITRE ATT&CK Navigator layer (v4.5 schema). Upload to the Navigator. |
| `_attack_heatmap.svg` | Self-contained ranked technique heatmap. |

### The `results.json` schema

Each element of the list looks like:

```json
{
  "input": "…raw text…",
  "analysis": {
    "risk_score": 28,
    "risk_level": "CRITICAL",
    "tags": ["authority_impersonation", "bec_financial_lure", "..."]
  },
  "indicators": { "urls": ["http://..."], "domains": [], "ips": [], "emails": [] },
  "mitre_matches": [
    { "id": "T1657", "name": "Financial Theft", "tactic": "impact",
      "via": ["bec_financial_lure"] }
  ]
}
```

`via` lists the signals that triggered each technique — this is how the report
explains *why* a technique was mapped.

---

## 9. The Scoring Model

The score is the **sum of fired primitive scores**, plus configured boosts:

1. Every primitive whose keywords match the (lower-cased) input contributes its
   `score` and adds its name as a tag.
2. If any indicator (URL/domain/IP/email) is found, the `has_indicator` boost
   is added (default **+5**) and `has_indicator` becomes a derived signal.
3. If at least one ATT&CK technique maps, the `mitre_ttp` boost is added
   (default **+6**) and `mitre_ttp` is added as a tag.

The total is bucketed into a severity level using the profile thresholds
(defaults shown):

| Level | Condition (default thresholds) |
|-------|-------------------------------|
| INFO | score == 0 |
| LOW | score ≤ 4 |
| MEDIUM | score ≤ 8 |
| HIGH | score ≤ 12 |
| CRITICAL | score > 12 |

Thresholds and boosts are **set in the profile's `config` block** (§17), so you
can tune sensitivity without touching code.

> **Note on the merged profile.** Because the merged profile stacks many
> primitives, realistic lures tend to accumulate score quickly and land at
> CRITICAL. Technique mapping stays precise regardless. If you want more spread
> across levels, raise the thresholds in the profile's `config` block.

---

## 10. ATT&CK Technique Mapping

Mapping is **deterministic and combo-rule based**, defined in the profile's
`attack_map`:

```json
"attack_map": [
  { "id": "T1566",     "when": ["action_request", "authority"] },
  { "id": "T1566.002", "when": ["action_request", "has_indicator"] },
  { "id": "T1684.001", "when": ["authority"] }
]
```

A technique fires **only when every signal in its `when` list is present** on
that input. `when` entries may be:

- any primitive name (fires when that primitive matched), or
- the derived signal `has_indicator` (fires when an IoC was extracted).

Each mapped technique records `via` — the signals that triggered it — which the
report surfaces so an analyst can see the reasoning.

### Validation (fail-closed)

Before a technique is emitted, its ID is checked against `mitre_cache.json`. If
the ID is not present (unknown, retired, or renumbered), it is **logged and
skipped**. The technique **name** and **tactic** shown in output always come
from the cached real dataset, never from anywhere else.

> Real-world example this caught: `T1656` (Impersonation) was renumbered to
> `T1684.001` in current ATT&CK. The validator flagged the stale ID, and the
> profile was corrected. This is the fail-closed design working as intended.

### Optional fuzzy fallback

A description-based fuzzy matcher exists as an **opt-in fallback**
(`attack_fuzzy_fallback`, off by default). The combo-rules are the primary,
precise path; fuzzy matching is noisier and disabled unless you explicitly want
broad coverage.

---

## 11. The Optional AI Advisory Layer

When enabled, the AI layer attaches a short note to **HIGH and CRITICAL** items:
a one-line summary, analyst notes, and concrete action items.

### Enabling it

The layer is **off** unless configured. To enable a **cloud** provider:

```bash
export HUNTER_AI_PROVIDER=anthropic
export HUNTER_AI_MODEL=claude-sonnet-4-5
export HUNTER_AI_API_KEY=<your-key>
export HUNTER_AI_ALLOW_REMOTE=1     # REQUIRED for any non-local endpoint
```

To enable a **local** provider (nothing leaves the box — no remote flag needed):

```bash
export HUNTER_AI_PROVIDER=openai-compatible
export HUNTER_AI_BASE_URL=http://localhost:11434/v1   # e.g. Ollama
export HUNTER_AI_MODEL=llama3.1
```

`--no-ai` overrides all of the above and forces a pure deterministic run.

### What it can and cannot do

- **Can:** add an advisory note + action items; bring outside-world knowledge
  (e.g. "this domain does not belong to PayPal's infrastructure").
- **Cannot:** alter the score, level, tags, indicators, or technique mapping.

### A note on advisory quality

The **action items are consistently sharp and useful**. The free-text summary
is generated by a model and can occasionally be loosely worded — treat the
narrative as a starting point and trust the structured actions. The advisory is
always labelled *advisory only — verify before acting* with the model name.

### Budget & safety knobs

`HUNTER_AI_MAX_CALLS` (default 25), `HUNTER_AI_TIMEOUT` (30s),
`HUNTER_AI_MAX_INPUT_CHARS` (4000), `HUNTER_AI_MAX_TOKENS` (512) bound cost,
latency, and how much text is sent. See §18.

> **Data egress warning.** A cloud provider sends item text off-box. Only enable
> remote AI for data you are authorized to send externally. For sensitive
> corpora use a local provider, or run deterministic-only.

---

## 12. AI-Assisted YARA Drafting

`--ai-yara` asks the AI to propose distinctive string literals for a detection
rule. This is the one place the AI does something the keyword generator
structurally cannot: it selects **contextual phrases** ("this is the CEO",
"urgent wire transfer") rather than isolated keywords, which tends to mean fewer
false positives.

### Mandatory compile gate

AI-YARA **requires `yara-python`**. Every drafted rule must compile under
`yara-python` or it is discarded. This gate is non-negotiable — the feature
refuses to run without the library installed.

### Quarantined output

Survivors are written to **`_ai_yara_NEEDS_REVIEW.yara`**, never merged into the
deployable `_all_yara_rules.yara`. Each carries `_generated_by`, `_review =
"REQUIRED"`, and a `rationale` meta field, behind a header banner stating the
rules are compile-checked but **not** validated for detection quality. **An
analyst must review before any deployment.**

### Provider requirement

AI-YARA needs an AI provider configured exactly like the advisory layer (§11),
**including `HUNTER_AI_ALLOW_REMOTE=1` for cloud**. If only an API key is set but
the provider/remote flag is missing, drafting will skip — set all of
`HUNTER_AI_PROVIDER`, `HUNTER_AI_MODEL`, and `HUNTER_AI_ALLOW_REMOTE` (or use a
local provider).

---

## 13. Visualization

Each run (when anything maps) emits two ATT&CK visual artifacts:

### Navigator layer — `_attack_navigator.json`

A MITRE ATT&CK Navigator layer (v4.5 schema). To view the interactive matrix:

1. Go to <https://mitre-attack.github.io/attack-navigator/>
2. Choose **Open Existing Layer → Upload from local**
3. Select `_attack_navigator.json`

Each technique's score is the number of inputs that mapped to it; the gradient
shades by frequency.

### Heatmap — `_attack_heatmap.svg`

A self-contained ranked-bar heatmap of mapped techniques. Opens in any browser
or SVG viewer; no dependencies.

Both no-op silently if nothing mapped in the session.

---

## 14. Reporting: `generate_report.py`

A **standalone** reporting tool. It only **reads** session `results.json`; it
runs no analysis and never modifies the engine or its output. Use it to turn one
or many sessions into a professional, shareable report.

### Principles

- **No message content anywhere.** The raw item text never appears on a chart
  or in the summary. Where per-item rows are needed (the case heatmap), items
  are anonymized as `CASE-001`, `CASE-002`, … Reports are safe to hand to
  non-technical stakeholders.
- **MITRE nomenclature only.** Techniques are shown by official ID + name
  (`T1566 Phishing`); tactics by display name + TA-ID (`Initial Access
  (TA0001)`) in canonical kill-chain order. Nothing is invented or renamed.
- **Honest measurement.** Counts are **detection frequency** (number of cases
  mapping to a technique/tactic), explicitly **not** vulnerability/CVE counts —
  HunterEngine maps adversary *behaviour*. The correlation matrix is **skipped**
  below 20 cases because it is statistically meaningless on a small sample, and
  says so rather than drawing noise.

### Usage

```bash
python3 generate_report.py                      # newest session
python3 generate_report.py <session_dir> [...]  # specific session(s)
python3 generate_report.py --all                # aggregate ALL sessions
python3 generate_report.py --all --out report/  # custom output directory
```

| Flag | Effect |
|------|--------|
| `--all` | Aggregate across every session under the box dir (corpus-level view). |
| `--box <dir>` | Sessions root (default `HunterEngineBox`). |
| `--out <dir>` | Output directory for the report. |
| `--no-stix` | Skip the STIX 2.1 bundle export. |
| `--defang` | Defang IoC values in the STIX pattern (`hxxp://`, `[.]`). |

### Output (in the report directory)

| File | Contents |
|------|----------|
| `01_technique_frequency.png` | Techniques ranked by detection frequency (MITRE IDs + names). |
| `02_tactic_coverage.png` | Tactic coverage in kill-chain order (TA-IDs). |
| `03_severity_by_tactic.png` | Severity stacked per tactic. |
| `04_case_tactic_heatmap.png` | Anonymized CASE-### × tactic heatmap. |
| `05_risk_distribution.png` | Severity distribution donut. |
| `06_tactic_correlation.png` | Tactic co-occurrence correlation (**only if ≥20 cases**). |
| `EXECUTIVE_SUMMARY.txt` | Plain-language brief: totals, severity breakdown, top techniques, tactic coverage, honest measurement notes. |
| `findings_stix_bundle.json` | STIX 2.1 bundle (see §15). |

> **Corpus tip.** `--all` is where this becomes intelligence: run it across many
> sessions to see which techniques and tactics dominate your environment, and to
> let the correlation matrix cross the significance threshold.

---

## 15. STIX 2.1 / TAXII Export

`generate_report.py` emits `findings_stix_bundle.json`, a **STIX 2.1 bundle**
that any STIX/TAXII-aware platform (MISP, OpenCTI, ATT&CK Workbench, many SIEMs)
can ingest. This mirrors how MITRE itself publishes ATT&CK as STIX.

### What is in the bundle

- **`attack-pattern`** — one per distinct technique, citing the technique via an
  `external_references` entry with `source_name: mitre-attack` and
  `external_id: <technique ID>` (the canonical ATT&CK citation form).
- **`indicator`** — one per mapped case, named `CASE-###` (anonymized), labelled
  with its severity, carrying a STIX pattern for any extracted IoCs. **No message
  content is ever included.**
- **`relationship`** — `indicator —indicates→ attack-pattern`, linking each case
  to the techniques it exhibits.

### Validation

If the `stix2` library is installed (it is in `requirements.txt`), the bundle is
constructed and **validated through the official library** before writing — the
run log will say `stix2-validated`. If the library is unavailable, a
spec-compliant JSON bundle is written directly as a fallback.

### IoC handling

A genuine malicious URL/domain is an indicator of compromise, not message
content, so by default it appears in the STIX `pattern` (that is the point of
shareable intel — "block this domain"). Use `--defang` to neutralize those
values in the pattern (`hxxp://`, `[.]`) if your downstream workflow requires it.

---

## 16. The Pipeline Test Harness

`run_pipeline_test.sh` exercises the whole engine in every mode and then opens
all artifacts, so you can validate an install end to end in one command.

### Modes

| Mode | What it runs | Prerequisite |
|------|--------------|--------------|
| 1. Offline / no AI | Pure deterministic engine | none |
| 2. AI-YARA only | Deterministic + AI YARA drafting | `yara-python` + an AI provider |
| 3. Cloud AI advisory | Full stack with cloud advisory | `HUNTER_AI_API_KEY` |
| 4. Local AI advisory | Full stack with local model | Ollama on `:11434` |

Modes whose prerequisites are missing **skip with a notice** rather than
failing, so the harness always completes. At the end it prints a summary table,
dumps each artifact to the terminal, and opens the heatmap, report, and session
folder.

### Usage

```bash
# from inside the repo dir
export HUNTER_AI_PROVIDER=anthropic
export HUNTER_AI_MODEL=claude-sonnet-4-5
export HUNTER_AI_ALLOW_REMOTE=1
export HUNTER_AI_API_KEY=<key>      # only for the cloud modes

./run_pipeline_test.sh
```

Environment knobs: `OPEN_CMD=open ./run_pipeline_test.sh` on macOS;
`HUNTER_LOCAL_MODEL=mistral ./run_pipeline_test.sh` to pick a non-default Ollama
model.

> The harness sets the AI environment for modes 2 and 3 so AI-YARA has a working
> provider. If you run the engine directly (not via the harness), remember that
> AI-YARA and cloud advisory both require `HUNTER_AI_ALLOW_REMOTE=1` for cloud.

---

## 17. Writing & Extending Primitive Profiles

A profile is a single JSON file with three top-level keys: `config`,
`attack_map`, and `primitives`.

### 17.1 `primitives`

A map of primitive name → `{score, keywords}`:

```json
"primitives": {
  "urgency": {
    "score": 3,
    "keywords": ["urgent", "immediate", "action required", "asap",
                 "final notice", "end of day", "expires"]
  },
  "authority_impersonation": {
    "score": 5,
    "keywords": ["this is the ceo", "from the director", "on behalf of"]
  }
}
```

- `score` — points added when the primitive fires.
- `keywords` — case-insensitive substrings. Any match fires the primitive once
  (a single primitive contributes its score at most once per item).

**Adding a primitive:** add a new entry, give it a score proportional to how
strong a signal it is, and list natural phrasings real lures use. Use lower-case
keywords; matching is case-insensitive.

### 17.2 `config`

Tuning knobs for scoring and matching:

```json
"config": {
  "fuzzy_threshold": 85,
  "risk_thresholds": { "LOW": 4, "MEDIUM": 8, "HIGH": 12 },
  "score_boosts":    { "has_indicator": 5, "mitre_ttp": 6 }
}
```

- `risk_thresholds` — score cutoffs for LOW/MEDIUM/HIGH (above HIGH = CRITICAL).
  Raise these to spread items across more levels; lower them to be more
  sensitive.
- `score_boosts` — bonus for finding an IoC and for mapping at least one
  technique.
- `fuzzy_threshold` — match strictness for the optional fuzzy fallback (0–100).

### 17.3 `attack_map`

Deterministic technique combo-rules:

```json
"attack_map": [
  { "id": "T1566",     "when": ["action_request", "authority"] },
  { "id": "T1567.002", "when": ["data_sensitivity", "exfil_channel"] }
]
```

- `id` — an ATT&CK technique ID. **It must exist in the ATT&CK dataset** or it
  is skipped at runtime (fail-closed). Verify new IDs against current ATT&CK.
- `when` — list of signals that must **all** be present. Entries are primitive
  names or the derived `has_indicator`.

**Tuning for precision:** require more signals in `when` to reduce false
positives (e.g. mapping T1566 on `action_request` *and* `authority` rather than
`action_request` alone). Avoid mapping a technique you cannot distinguish from
context (e.g. don't map USB-only exfiltration when you cannot tell USB from
cloud).

### 17.4 Verifying a new technique ID

Before adding an ID to `attack_map`, confirm it is current:

```bash
python3 -c "import json; c=json.load(open('mitre_cache.json')); \
ids={m['id'] for m in c['metadata']}; print('T1566' in ids)"
```

If it prints `False`, the ID is wrong or renumbered — find the current ID on
<https://attack.mitre.org> before using it.

### 17.5 Shipping a new profile

Save it under `primitives/`, then select it with `-c`:

```bash
python3 HunterEngine.py inbox.txt -c primitives/my_profile.json
```

The three bundled profiles (`default_phishing`, `bec_financial`,
`insider_exfil`) and the combined `merged_primitives.json` are good templates to
copy from.

---

## 18. Environment Variable Reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `HUNTER_AI_PROVIDER` | `none` | `anthropic`, `openai`, `openai-compatible`, or `none`. |
| `HUNTER_AI_MODEL` | — | Model string for the provider. |
| `HUNTER_AI_BASE_URL` | — | Endpoint for `openai-compatible` (e.g. Ollama at `http://localhost:11434/v1`). |
| `HUNTER_AI_API_KEY` | — | API key for cloud providers. Sent only as a request header, never logged. |
| `HUNTER_AI_ALLOW_REMOTE` | unset | Must be `1` to permit **any non-local** endpoint. Safety gate against accidental egress. |
| `HUNTER_AI_TIMEOUT` | `30` | Per-call timeout (seconds). |
| `HUNTER_AI_MAX_CALLS` | `25` | Max AI calls per run (budget guard). |
| `HUNTER_AI_MAX_INPUT_CHARS` | `4000` | Max characters of an item sent to the AI. |
| `HUNTER_AI_MAX_TOKENS` | `512` | Max tokens requested per AI response. |

CLI flags: `-c/--config`, `--no-banner`, `--no-ai`, `--ai-yara`.

---

## 19. Security Considerations

- **API keys.** Never paste a key into shared text, commit it, or hard-code it.
  Export it in your shell; the engine reads it from the environment and sends it
  only as a request header. If a key is ever exposed, **rotate it immediately**
  at your provider's console.
- **Data egress.** Cloud AI sends item text off-box. Use local providers or
  deterministic-only for sensitive data. `HUNTER_AI_ALLOW_REMOTE=1` is required
  precisely so remote egress is always a conscious choice.
- **AI-YARA output is untrusted.** Compile-checked is not validated. Review
  before deploying anything from `_ai_yara_NEEDS_REVIEW.yara`.
- **Reports are shareable by design.** No message content is included in charts,
  the summary, or the STIX bundle; cases are anonymized. IoCs (which are meant to
  be shared) appear in the STIX pattern unless `--defang` is used.
- **Defensive scope.** HunterEngine classifies and enriches suspicious text for
  defense. It does not generate lures or offensive content.

---

## 20. Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| `externally-managed-environment` on `pip install` | Activate a venv first: `python3 -m venv .venv && source .venv/bin/activate`. |
| `ModuleNotFoundError: rapidfuzz` (or similar) | The venv isn't active (prompt won't show `(.venv)`). Re-`source .venv/bin/activate`. |
| AI-YARA "requires yara-python … skipping" | `pip install yara-python`. The compile gate is mandatory. |
| AI-YARA or cloud advisory silently does nothing | Provider not fully configured. Set `HUNTER_AI_PROVIDER`, `HUNTER_AI_MODEL`, and `HUNTER_AI_ALLOW_REMOTE=1` (cloud) or a local `HUNTER_AI_BASE_URL`. |
| `attack_map references '<ID>', not present` in logs | The technique ID is unknown/renumbered. Find the current ID on attack.mitre.org and fix the profile. (This is fail-closed working.) |
| Only 2 techniques / weird cache | Stale cache. `rm mitre_cache.json` to force a rebuild. |
| Correlation chart missing from a report | Fewer than 20 cases — it is skipped on purpose. Run `--all` across more sessions. |
| `generate_report.py` "Missing dependency" | `pip install matplotlib numpy`. |
| STIX line doesn't say `stix2-validated` | The `stix2` library isn't importable in this environment; a spec-compliant fallback bundle was written instead. Install `stix2` to validate. |

---

## 21. File-by-File Reference

| File | Role |
|------|------|
| `HunterEngine.py` | The engine: parsing, scoring, IoC extraction, ATT&CK mapping, YARA generation, deterministic verdict, AI orchestration. |
| `ai_enrichment.py` | The advisory AI layer (provider abstraction, prompt, redaction, budget). Advisory-only. |
| `yara_ai.py` | AI-assisted YARA drafting with the mandatory compile gate and quarantined output. |
| `attack_viz.py` | Emits the Navigator layer and the heatmap SVG. |
| `generate_report.py` | Standalone reporting: charts, executive summary, STIX 2.1 export. Reads sessions only. |
| `run_pipeline_test.sh` | 4-mode end-to-end test harness + artifact opener. |
| `primitives/*.json` | Primitive profiles (default phishing, BEC, insider exfil, merged). |
| `mitre_cache.json` | Local cached ATT&CK dataset used for fail-closed validation, names, and tactics. |
| `requirements.txt` | Python dependencies. |
| `HunterEngineBox/` | Output: one timestamped session folder per run. |

---

*HunterEngine is a defensive triage and threat-intel tool. Use it on data you
are authorized to process. The deterministic core is auditable and offline; the
AI layer is advisory only and never changes a verdict.*
