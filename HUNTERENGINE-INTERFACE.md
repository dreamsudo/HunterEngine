# HUNTERENGINE-INTERFACE.md

Interface contract for wrapping HunterEngine as a blue/detection capability
(extracted from the actual code at the commit below, with examples pasted from
real runs). Written for the Skepsis integration; complete enough to replace
reading the repo.

---

## 1. Identity & install

- **Identity:** no `__version__`, no package metadata. Identify by git commit.
  This contract was extracted at commit `dac0117dc12ffc4657485d0aeade718cd4287ce4`
  (branch `main`, https://github.com/dreamsudo/HunterEngine.git, 2026-07-25).
- **Not pip-installable.** There is no `setup.py`/`pyproject.toml`; it is a
  source checkout + CLI. There is no package name to `pip install`.
- **Python:** engine core runs on 3.10+; the dev/report toolchain
  (`requirements-dev.txt`) requires **3.12** (pinned `numpy==2.5.1` is
  `>=3.12`). CI runs the full suite on 3.12 and a core smoke job on 3.10.
- **Runtime deps (pinned, `requirements.txt`):** `requests==2.34.2`,
  `tqdm==4.69.1`, `rapidfuzz==3.14.5`, `stix2==3.0.2`.
  **Optional (`requirements-dev.txt`):** `yara-python==4.5.4` (only for
  `--ai-yara`), `matplotlib==3.11.1` + `numpy==2.5.1` (only for
  `generate_report.py`), `pytest==9.1.1`, `pyflakes==3.4.0`.
- **Install + minimal invocation:**

```bash
git clone https://github.com/dreamsudo/HunterEngine.git
cd HunterEngine
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 HunterEngine.py test_input.txt --no-ai -c primitives/merged_primitives.json
```

- **First run requires network:** downloads the MITRE CTI archive
  (`MITRE_CTI_URL = "https://github.com/mitre/cti/archive/refs/heads/master.zip"`,
  capped at `MAX_DOWNLOAD_BYTES = 250*1024*1024` compressed /
  `MAX_UNCOMPRESSED_BYTES = 1 GiB` extracted) into `attack-stix-data/`, then
  builds `mitre_cache.json` (918 techniques + tactic table at time of writing).
  Subsequent runs are fully offline.
- **CWD-sensitive:** all paths are relative (`primitives/…`,
  `mitre_cache.json`, `attack-stix-data/`, `HunterEngineBox/`). **Run from the
  repo root.** A wrapper must set `cwd` to the checkout (or accept artifacts
  landing wherever it runs).

---

## 2. Entry points

### CLI (the supported orchestration path)

```
python3 HunterEngine.py <input_file> [-c/--config PATH] [--no-banner] [--no-ai] [--ai-yara]
```

- `-c/--config` defaults to `DEFAULT_PRIMITIVES_CONFIG_FILE = "primitives/default_phishing_primitives.json"`.
- `--no-ai` force-disables the AI advisory regardless of environment.
- `--ai-yara` opt-in AI YARA drafting (requires `yara-python` + AI provider env).
- Exit code `0` on a completed run; `sys.exit(1)` on missing input file,
  unparseable/invalid profile, or MITRE download failure.
- There is **no single-string CLI mode and no stdout JSON mode**; input is a
  file, output is a session directory (see §8).

### Import (real signatures from `HunterEngine.py`)

```python
class ThreatEnrichmentEngine:
    def __init__(self, config_path: str = DEFAULT_PRIMITIVES_CONFIG_FILE): ...
    def setup_dependencies(self):                       # loads profile + MITRE data (downloads on first run)
    def enrich_text(self, text: str) -> Dict:           # single item -> full result dict (§4)
    def process_batch(self, inputs: Iterable[str]) -> List[Dict]:
    def get_risk_level(self, score: int) -> str:        # "INFO"|"LOW"|"MEDIUM"|"HIGH"|"CRITICAL"

def load_inputs(path: str) -> Generator[str, None, None]:   # .txt/.csv/.json -> item strings
def save_results(results: List[Dict], ai_yara_rules: List[str] = None,
                 ai_yara_summary: Dict = None):             # writes the session dir
def generate_summary_report(results: List[Dict], stats: Dict, path: str,
                            ai_yara_summary: Dict = None):
```

Minimal embedded use (what `main()` does):

```python
engine = ThreatEnrichmentEngine(config_path="primitives/merged_primitives.json")
engine.setup_dependencies()          # CWD must be repo root
result = engine.enrich_text("URGENT: verify your PayPal account ...")
results = engine.process_batch(load_inputs("inbox.txt"))
save_results(results)                # optional; enrich_text alone has no side effects except miss-log
```

Caveats for import mode: the modules are top-level files (not a package), so
`sys.path` must include the repo root; `enrich_text` appends zero-tag inputs to
`missed_inputs.log` in CWD (side effect); `process_batch` silently skips empty
or non-string items and appends items that raise to `failed_inputs.log`.

### Other modules

- `ai_enrichment.AIAdvisor.from_env() -> AIAdvisor`;
  `AIAdvisor.annotate(results: List[Dict]) -> None` (mutates items in place);
  `AIAdvisor.enabled: bool`;
  `build_provider_from_env(purpose="ai") -> (LLMProvider | None, cfg_dict)`.
- `yara_ai.draft_ai_yara(results) -> Tuple[List[str], Dict]` — returns
  (`rule_texts`, `summary`) where
  `summary = {"status", "drafted", "compiled_ok", "discarded", "model"}`.
- `attack_viz.build_navigator_layer(results, session_id, name="HunterEngine") -> Dict`;
  `write_navigator_layer(results, path, session_id) -> bool`;
  `build_heatmap_svg(results, session_id) -> str`;
  `write_heatmap_svg(results, path, session_id) -> bool`.
- `generate_report.py` — CLI only:
  `python3 generate_report.py [session_dirs...] [--all] [--box DIR] [--out DIR] [--no-stix] [--defang]`.
  Internals importable: `load_results(session_dirs) -> List[Dict]`,
  `export_stix_bundle(items, out, defang_iocs=False) -> int` (object count).

---

## 3. Inputs

An input item is a **raw text string** (email body, SMS, chat, log line).
There is **no email-object model**: no header/MIME parsing, no attachments, no
URL unshortening. Per-item text is truncated to `MAX_INPUT_LEN = 50_000` chars
before analysis.

File formats accepted by `load_inputs(path)` (dispatch on filename extension):

- **`.txt`** — one item per line; lines are `.strip()`ed; blank lines skipped.
- **`.csv`** — `row[0]` of every row (⚠ a header row is analyzed as an item;
  quoted multi-line fields are supported by `csv.reader`).
- **`.json`** — a list of objects (`item["input"]` is used; other keys
  ignored), a list of strings, or a single object with `"input"`.

**Batch** = the file (one engine run = one session).
**Aggregate / cross-case mode** is a separate tool over session outputs:

```bash
python3 generate_report.py --all            # every HunterEngineBox/session_*/results.json
python3 generate_report.py <session_dir>    # one session
```

The tactic co-occurrence correlation is produced **only at ≥ 20 cases**
(`MIN_CASES_FOR_CORRELATION = 20`); below that it is skipped by design.

---

## 4. Output schemas

### 4.1 Per-item result (elements of `results.json`)

Real example (verbatim from a real session, trimmed only at the YARA string):

```json
{
  "input": "URGENT: Your PayPal account has been suspended. Click http://paypal-secure-login.evil-domain.com to verify now or your account will be permanently closed.",
  "analysis": {
    "risk_score": 25,
    "risk_level": "CRITICAL",
    "tags": ["action_request", "authority", "consequence", "has_indicator",
             "initial-access", "mitre_ttp", "reconnaissance", "stealth", "urgency"],
    "matched_primitives": {
      "urgency":        {"score": 3, "matches": ["urgent", "now"]},
      "authority":      {"score": 4, "matches": ["paypal"]},
      "consequence":    {"score": 4, "matches": ["suspended"]},
      "action_request": {"score": 3, "matches": ["login", "verify", "click"]}
    }
  },
  "indicators": {
    "urls": ["http://paypal-secure-login.evil-domain.com"]
  },
  "mitre_matches": [
    {"id": "T1566",     "name": "Phishing",                 "tactic": "initial-access",
     "via": ["action_request", "authority"],      "match_type": "combo-map"},
    {"id": "T1566.002", "name": "Spearphishing Link",       "tactic": "initial-access",
     "via": ["action_request", "has_indicator"],  "match_type": "combo-map"},
    {"id": "T1598",     "name": "Phishing for Information", "tactic": "reconnaissance",
     "via": ["action_request", "consequence"],    "match_type": "combo-map"},
    {"id": "T1684.001", "name": "Impersonation",            "tactic": "stealth",
     "via": ["authority"],                        "match_type": "combo-map"}
  ],
  "yara_rule": "\nrule threat_heuristic_URGENT_Your_PayPal_account_has_been_susp_414d7a61ff\n{ ... }"
}
```

Field notes (types as actually produced):

| Field | Type | Notes |
|---|---|---|
| `input` | str | raw text, truncated to 50 000 chars. **Not defanged, not anonymized.** |
| `analysis.risk_score` | int | sum of fired primitive scores + boosts (§5) |
| `analysis.risk_level` | str enum | `INFO` \| `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` |
| `analysis.tags` | list[str], sorted | primitive names + derived `has_indicator`/`mitre_ttp` + ATT&CK tactic shortnames (e.g. `initial-access`, `stealth`) |
| `analysis.matched_primitives` | dict | `{name: {"score": int, "matches": [matched keywords]}}` |
| `indicators` | dict | keys **only when non-empty**: `urls`, `domains`, `emails`, `ipv4` → list[str]. Domains that appear inside an extracted URL are deduplicated out of `domains`. |
| `mitre_matches` | list, sorted by `id` | two shapes — see below |
| `yara_rule` | str | full rule text, or `""` when score is 0 or no strong strings survive filtering |
| `ai_advisory` | dict, **optional** | present only when AI enabled and item is HIGH/CRITICAL (§6) |

**Two `mitre_matches` shapes** (consumers must handle both):

- combo-map (primary; when the profile has `attack_map`):
  `{"id", "name", "tactic", "via": [signals], "match_type": "combo-map"}`
- fuzzy/exact fallback (no `attack_map`, or `attack_fuzzy_fallback: true`):
  `{"id", "name", "tactic", "matched_phrase": str, "score": int, "match_type": "fuzzy"|"exact"}`

### 4.2 Severity enum

From `get_risk_level` with the default thresholds
(`risk_thresholds = {"LOW": 4, "MEDIUM": 8, "HIGH": 12}` — profile-overridable):

| Level | Condition |
|---|---|
| `INFO` | score == 0 |
| `LOW` | 1 ≤ score ≤ LOW |
| `MEDIUM` | LOW < score ≤ MEDIUM |
| `HIGH` | MEDIUM < score ≤ HIGH |
| `CRITICAL` | score > HIGH |

### 4.3 IoCs and defanging — precise behavior

- `results.json` / `_all_indicators.json` contain **live (non-defanged)** IoCs.
- Defanging exists in exactly two places:
  1. **AI prompts** (`ai_enrichment._defang`): `http→hxxp`, `://→[://]`, `.→[.]`
     — applied to indicators sent to the model, not to stored output.
  2. **STIX bundle** with the `--defang` CLI flag
     (`generate_report._defang`): `http://→hxxp://`, `https://→hxxps://`,
     `.→[.]` inside pattern values. Off by default.
- `_all_indicators.json` (per session) is a list of
  `{"input": <raw text>, "risk_level": str, "indicators": {…}}` — contains
  message content; treat as session-private.

### 4.4 YARA (`_all_yara_rules.yara`)

One rule per scored item that retains at least one "strong" string; **identical
inputs collapse to a single rule** (deduped by rule identifier at write time).
Real rule (verbatim):

```yara
rule threat_heuristic_URGENT_Your_PayPal_account_has_been_susp_414d7a61ff
{
    meta:
		risk_score = "25"
		risk_level = "CRITICAL"
		tags = "['action_request', 'authority', 'consequence', 'has_indicator', 'initial-access', 'mitre_ttp', 'reconnaissance', 'stealth', 'urgency']"
		input_text = "URGENT: Your PayPal account has been suspended. Click http://paypal-secure-login.evil-domain.com to verify now or your account will be permanently closed."
		mitre_ttps = "T1566, T1566.002, T1598, T1684.001"
    strings:
		$s1 = "http://paypal-secure-login.evil-domain.com" nocase wide ascii
		$s2 = "suspended" nocase wide ascii
    condition:
        all of them
}
```

Contract details:

- Rule name: `threat_heuristic_<input sanitized to [A-Za-z0-9_], 40 chars>_<sha1(input)[:10]>`
  — deterministic per input text.
- `meta.input_text` = first 1024 chars of the input, escaped (`\`, `"`, control
  chars) — **contains message content**.
- Strings = extracted indicators (always kept) + primitive keyword matches that
  pass a strength filter (multi-word, URL/email-shaped, IP-ish, or length ≥
  `yara_min_token_len`, default 7).
- Condition: `2 of them` when > 2 strings, else `all of them`.
- Deterministic rules are **not compile-gated by the engine at runtime**; the
  repo's test suite compiles them under `yara-python 4.5.4` (all pass at this
  commit). AI-drafted rules (separate file) **are** compile-gated (§6).

### 4.5 ATT&CK Navigator layer (`_attack_navigator.json`)

Real example (verbatim, truncated to 2 techniques):

```json
{
  "name": "HunterEngine 2026-07-25_02-29-37",
  "versions": {"navigator": "4.5", "layer": "4.5"},
  "domain": "enterprise-attack",
  "description": "Techniques mapped by HunterEngine across this session. Score = number of inputs that mapped to the technique.",
  "sorting": 3,
  "hideDisabled": false,
  "techniques": [
    {"techniqueID": "T1684.001", "score": 3, "comment": "Impersonation — matched in 3 input(s)", "enabled": true},
    {"techniqueID": "T1566",     "score": 2, "comment": "Phishing — matched in 2 input(s)",      "enabled": true}
  ],
  "gradient": {"colors": ["#ffe8e8", "#fc3d3d"], "minValue": 0, "maxValue": 3},
  "legendItems": [],
  "metadata": [
    {"name": "tool", "value": "HunterEngine"},
    {"name": "session", "value": "2026-07-25_02-29-37"},
    {"name": "total_inputs", "value": "4"}
  ]
}
```

`score` = count of inputs mapping to the technique. No ATT&CK release version
is pinned (deliberate). File written only if ≥ 1 technique mapped.

### 4.6 STIX 2.1 bundle (`report dir/findings_stix_bundle.json`)

Produced by `generate_report.py` (not by the engine). Object types:
`attack-pattern` (one per distinct technique), `indicator` (one per **mapped**
case), `relationship` (`indicates`, indicator → attack-pattern). Validated
through the `stix2` library when importable (log prints `stix2-validated`);
otherwise a hand-built spec-shaped bundle is written.

Real objects (verbatim):

```json
{
  "type": "attack-pattern", "spec_version": "2.1",
  "id": "attack-pattern--16e24333-8fcb-423f-a9c2-baba6d3a5808",
  "created": "2026-07-25T02:30:51.000Z", "modified": "2026-07-25T02:30:51.000Z",
  "name": "Data from Cloud Storage",
  "external_references": [
    {"source_name": "mitre-attack", "url": "https://attack.mitre.org/techniques/T1530", "external_id": "T1530"}
  ]
}
{
  "type": "indicator", "spec_version": "2.1",
  "id": "indicator--1d4866e4-1a04-456c-bf6b-85ee9f2ed82d",
  "created": "2026-07-25T02:30:51.000Z", "modified": "2026-07-25T02:30:51.000Z",
  "name": "CASE-001",
  "description": "HunterEngine detection (CRITICAL). Case anonymized; no message content included.",
  "indicator_types": ["malicious-activity"],
  "pattern": "[url:value = 'http://paypal-secure-login.evil-domain.com']",
  "pattern_type": "stix", "pattern_version": "2.1",
  "valid_from": "2026-07-25T02:30:51Z",
  "labels": ["CRITICAL"]
}
{
  "type": "relationship", "spec_version": "2.1",
  "id": "relationship--baa75967-eb6c-40f0-8ff5-74e35a4aeb32",
  "created": "2026-07-25T02:30:51.000Z", "modified": "2026-07-25T02:30:51.000Z",
  "relationship_type": "indicates",
  "source_ref": "indicator--1d4866e4-1a04-456c-bf6b-85ee9f2ed82d",
  "target_ref": "attack-pattern--041ed211-ab5e-4c84-b15a-26aa75acfda4"
}
```

Anonymization contract, confirmed from code and locked by tests:

- **No message content in the bundle** (the test suite asserts a sentinel raw
  input never appears in the serialized bundle). Only IoC values appear, inside
  `pattern` (escaped per the pattern grammar: `\`→`\\`, `'`→`\'`).
- `CASE-###` is assigned **sequentially over mapped cases in load order, per
  report run**. It is *not* persisted and *not* stable across runs, and there
  is **no reverse mapping from CASE-### to the source input** stored anywhere.
- A case with no extracted IoCs gets the placeholder pattern
  `[x-hunterengine:detection = 'true']`.
- STIX `id`s are `uuid4` and timestamps are generation-time — the bundle is
  **not byte-reproducible** across runs even for identical inputs.

### 4.7 Executive summary & stats

- `report dir/EXECUTIVE_SUMMARY.txt` — fixed-format plain text: overview counts
  (total / mapped / distinct techniques / distinct tactics), severity
  breakdown with percentages, top-10 techniques
  (`T1684.001   Impersonation ... 59 case(s)   [Stealth]`), tactic coverage in
  kill-chain order, and measurement notes. No message content.
- `session/_stats.json`:

```json
{
  "session_id": "2026-07-25_01-57-48",
  "total_inputs_processed": 4,
  "risk_level_counts": {"CRITICAL": 4},
  "tag_counts": {"mitre_ttp": 4, "action_request": 3, "...": 1},
  "top_10_mitre_techniques": [{"id": "T1684.001", "name": "Impersonation", "count": 3}]
}
```

### 4.8 Aggregate cross-case correlation

`06_tactic_correlation.png` — Pearson correlation over a cases × tactics
presence matrix, gated at n ≥ 20. **PNG only; the matrix is not exported as
machine-readable data** (gap for Skepsis — parse `results.json` yourself or
request an export).

---

## 5. Deterministic scoring + fail-closed ATT&CK

**Scoring formula** (in `enrich_text`):

```
risk_score = Σ (score of each primitive that fired, once each)
           + score_boosts["has_indicator"]  (default 5, if any IoC extracted)
           + score_boosts["mitre_ttp"]      (default 6, if ≥ 1 technique mapped)
```

Keyword matching is whole-word (`\b(kw1|kw2)\b`, `re.IGNORECASE`) against the
lower-cased input; each primitive contributes its score at most once.

**Determinism:** yes — byte-for-byte for the deterministic fields, holding the
profile and `mitre_cache.json` constant. Same input ⇒ identical
`analysis`/`indicators`/`mitre_matches`/`yara_rule` (all collections are
sorted; the test suite asserts `enrich_text(x) == enrich_text(x)`).
Not deterministic: session folder names (timestamps), STIX bundle ids/times,
`_stats.json.session_id`, and `ai_advisory` (model output).

**Fail-closed ATT&CK validation** (`_map_attack`): a combo rule
(`{"id": tid, "when": [signals]}`) fires only when **all** `when` signals are
present. The `tid` is then looked up in the index built from
`mitre_cache.json` metadata:

- Known ID → emitted with `name` and `tactic` **taken from the dataset**
  (never from the profile).
- Unknown/renumbered ID → **dropped**, and logged once per ID:
  `attack_map references '<ID>', which is not present in the loaded ATT&CK
  data; skipping (check the ID is current).`

`mitre_cache.json` structure: `{"keywords": {tid: [phrases]},
"metadata": [{"id", "name", "tactic"}], "tactics": [{"shortname", "name",
"taid"}]}` — the `tactics` list is in kill-chain order and is what
`generate_report.py` uses for tactic naming/ordering (a cache missing
`tactics` is auto-rebuilt).

---

## 6. AI advisory + offline

**Configuration is environment-only** (no CLI flags for provider):

| Variable | Default | Meaning |
|---|---|---|
| `HUNTER_AI_PROVIDER` | `none` | `anthropic` \| `openai` \| `openai-compatible` \| `none`/`off` |
| `HUNTER_AI_MODEL` | — | required when enabled |
| `HUNTER_AI_BASE_URL` | provider default | e.g. `http://localhost:11434/v1` |
| `HUNTER_AI_API_KEY` | — | header-only; never logged (log redaction in `_redact`) |
| `HUNTER_AI_ALLOW_REMOTE` | unset | must be `"1"` for any non-loopback endpoint |
| `HUNTER_AI_TIMEOUT` / `_MAX_CALLS` / `_MAX_INPUT_CHARS` / `_MAX_TOKENS` | 30 / 25 / 4000 / 512 | budget guards |

**Egress gate** (`_is_local_url`): only `localhost`, `127.0.0.0/8`, `::1`,
`0.0.0.0` count as local. Anything else — including `.local` mDNS names — is
refused with a warning unless `HUNTER_AI_ALLOW_REMOTE=1`. Refusal disables AI;
the run continues deterministically.

**Advisory behavior** (`AIAdvisor.annotate`): annotates only items with
`risk_level in ("HIGH", "CRITICAL")` (`ONLY_LEVELS`), highest score first,
up to `max_calls`. Adds this field (validated: whitespace-collapsed,
length-capped 600/1200/200, ≤ 6 actions):

```json
"ai_advisory": {
  "summary": "…", "injection_observed": false, "analyst_notes": "…",
  "recommended_actions": ["…"], "_generated_by": "ai",
  "_disclaimer": "AI-generated advisory. Not authoritative; verify before acting.",
  "_model": "anthropic:<model>" 
}
```

**The AI never alters the verdict** — `annotate` only sets `ai_advisory`; it
runs *after* `process_batch`, and `yara_rule` is generated inside
`enrich_text` before AI exists. Locked by test
(`test_annotate_never_touches_scores`). Any provider error or unparseable
reply skips the item (fail-open) and the run continues.

**AI-YARA** (`yara_ai.draft_ai_yara`, only with `--ai-yara`): the model may
propose only string literals + a match count (JSON); the rule scaffold is
built deterministically; strings are escaped; every candidate must pass
`yara.compile()` or it is discarded; survivors go **only** to
`_ai_yara_NEEDS_REVIEW.yara` behind a review banner, never into
`_all_yara_rules.yara`. Without `yara-python` the feature refuses to run
(`status: "skipped: yara-python not installed"`). Duplicate inputs draft once.

**Fully offline/deterministic:** run with `--no-ai` (or no provider env) after
the first-run MITRE download has happened. With AI off, output contains no
`ai_advisory` fields and the deterministic fields are byte-identical to an
AI-on run's deterministic fields.

---

## 7. Extension points (primitives)

A profile is one JSON file selected with `-c`; **no engine edits needed**.
Bundled profiles: `primitives/default_phishing_primitives.json`,
`bec_financial_primitives.json`, `insider_exfil_primitives.json`,
`merged_primitives.json`.

Schema (all real keys):

```json
{
  "config": {
    "fuzzy_threshold": 85,
    "risk_thresholds": {"LOW": 4, "MEDIUM": 8, "HIGH": 12},
    "score_boosts": {"has_indicator": 5, "mitre_ttp": 6},
    "yara_min_token_len": 7,
    "attack_fuzzy_fallback": false
  },
  "attack_map": [
    {"id": "T1566",     "when": ["action_request", "authority"]},
    {"id": "T1567.002", "when": ["exfil_channel", "data_sensitivity"]}
  ],
  "primitives": {
    "urgency":        {"score": 3, "keywords": ["urgent", "end of day", "asap"]},
    "exfil_channel":  {"score": 4, "keywords": ["personal email", "dropbox"]}
  }
}
```

- `primitives` is **required, non-empty**; each entry needs a non-empty
  `keywords` list, else `sys.exit(1)` with a clear log line.
- `risk_thresholds` must contain `LOW`/`MEDIUM`/`HIGH` (validated at load).
- `attack_map` `when` entries are primitive names or the derived signal
  `has_indicator`. Unknown technique IDs fail closed at runtime (§5).
- `config` keys are optional (defaults above). `attack_fuzzy_fallback: true`
  additionally runs description fuzzy-matching for long-form text.

To add a detection: add a primitive + optionally an `attack_map` rule, save as
a new file under `primitives/`, pass with `-c`.

---

## 8. State / logs / errors / anonymization

**Filesystem writes (all CWD-relative):**

| Path | When | Content sensitivity |
|---|---|---|
| `attack-stix-data/` | first run | public MITRE data |
| `mitre_cache.json` | first run (auto-rebuilds if stale) | public |
| `HunterEngineBox/session_<YYYY-MM-DD_HH-MM-SS>[_NN]/` | every run with ≥1 result; dir `chmod 0700`; `_NN` suffix prevents same-second collisions | `results.json`, `_summary_report.md`, `_all_indicators.json`, YARA meta **contain raw message text** |
| `missed_inputs.log` | inputs firing zero tags; mode `0600`; deleted at start of each CLI run | raw message text |
| `failed_inputs.log` | inputs that raised during enrichment; mode `0600`; deleted at start of each CLI run | raw message text |
| `report_aggregate/` (or `--out`) | `generate_report.py` | **content-free** (charts, summary, STIX) |

**Logging:** Python `logging` (basicConfig, level INFO, to stderr), format
`%(asctime)s - %(levelname)s - %(message)s`. Notable lines a wrapper can key
on: `AI advisory enabled via …`, `AI advisory complete: N call(s)`,
`attack_map references '<ID>' …`, `Wrote N AI-drafted rule(s) …`,
`Saved N MITRE techniques and M tactics to cache`.

**Failure model:** fatal setup problems (missing input file, invalid profile,
MITRE download failure) → `sys.exit(1)`. Per-item enrichment errors are
logged, the input is appended to `failed_inputs.log`, and the batch continues
(the failed item is absent from `results`). All AI failures are non-fatal.

**Anonymization guarantees (test-enforced):** report charts,
`EXECUTIVE_SUMMARY.txt`, and the STIX bundle contain **no message content**;
cases appear only as `CASE-###`. Session artifacts are the opposite — they are
the full-fidelity record and must be treated as private (dir mode `0700`,
gitignored).

---

## 9. Gaps & uncertainties

Honest limits a wrapper must design around:

1. **No versioning or packaging** — no `__version__`, no pip package, no
   changelog; pin to a git commit.
2. **No library-friendly packaging** — CWD-relative paths everywhere; a
   wrapper must run in the repo root (or chdir per call).
3. **No stdout/JSON API** — results are files in a timestamped directory; a
   wrapper must locate the newest `session_*` dir (or call `enrich_text`
   directly and serialize itself).
4. **`CASE-###` is not a stable ID** — assigned per report run in load order,
   never persisted, no mapping back to inputs. Skepsis needs its own case IDs
   keyed on e.g. `sha1(input)` (the same digest the YARA rule name uses).
5. **Correlation matrix is PNG-only** — no machine-readable export.
6. **IoCs in `results.json` are live**, not defanged; defanging is
   STIX-`--defang`-only (plus AI prompts).
7. **STIX bundles are not reproducible** (uuid4 + timestamps).
8. **Severity compression** — with bundled profiles, realistic lures almost
   always land CRITICAL (thresholds not yet calibrated on a labeled corpus);
   treat `risk_score` as the finer-grained signal.
9. **CSV ingestion analyzes the header row** and only column 0.
10. **Skipped items are invisible** — empty/non-string batch items are
    dropped with no per-item record (only `failed_inputs.log` for raisers).
11. **First run needs network** to fetch MITRE CTI; behind a proxy/air gap you
    must pre-seed `attack-stix-data/` or `mitre_cache.json`.
12. **`mitre_matches` has two shapes** (combo vs fuzzy) — consumers must
    branch on `match_type`.
13. **AI advisory quality is model-dependent** and optional; nothing in the
    verdict depends on it.

---

## 10. Pinning & concurrency recipes (verified)

Answers to the two integration questions, each verified empirically against the
engine (network blocked at the socket level during the pinning test).

### 10.1 Pinning `mitre_cache.json` to an ATT&CK version — yes, two ways

The downloader short-circuits on a bare existence check
(`if os.path.exists("attack-stix-data"): return` in `_setup_mitre_data`) —
**any** `attack-stix-data/` directory, even empty, suppresses the download.
`_get_mitre_data` then uses `mitre_cache.json` whenever it exists and has all
three keys (`keywords`/`metadata`/`tactics`), never touching the STIX files.

**Recipe A — pin the cache itself (simplest; verified zero network calls):**

```
<workdir>/
├── attack-stix-data/        # EMPTY directory — just suppresses the download
└── mitre_cache.json         # ~463 KB, built once from your pinned revision
```

**Recipe B — pin the STIX source and rebuild:** pre-seed the real aggregate
files and delete the cache. The engine reads **only three files**
(`attack-stix-data/{enterprise-attack,mobile-attack,ics-attack}/<dirname>.json`,
per `MITRE_DIRS`) — not the per-object files; a missing domain file is
warn-and-skip, so enterprise-only pinning works. To use the engine's own
downloader against a pinned revision: `MITRE_CTI_URL` (module constant,
hardcoded to `master`; no CLI/env override) can point at a tagged archive,
e.g. `https://github.com/mitre/cti/archive/refs/tags/ATT&CK-v16.1.zip` — the
extractor strips the archive's first path component and filters the three
domain dirs, so tagged archives extract identically. One-line edit or
`HunterEngine.MITRE_CTI_URL = ...` before `setup_dependencies()`.

**Provenance gap:** the cache stores **no version field**. Record the CTI
tag/sha alongside the cache you distribute (or key on the cache file's hash).

### 10.2 Output redirection & concurrency

`OUTPUT_ROOT = "HunterEngineBox"` is a module constant, CWD-relative — **no
CLI flag or env var** (the reporting tool does have `--box`/`--out`). Two
isolation strategies, both verified:

- **Per-engagement CWD (supported path):** every engine path is CWD-relative,
  so one working directory per engagement fully isolates sessions, logs, and
  cache. Combine with Recipe A per engagement dir.
- **Monkeypatch (works, unsupported):** `OUTPUT_ROOT`, `MISS_LOG`, `ERROR_LOG`
  are module globals read **at call time** — verified that reassigning them
  redirects `save_results` and the miss/error logs. Fragile across upstream
  changes.

**Complete list of shared-global writes in the direct-call path**
(`enrich_text`/`process_batch` without `save_results`), verified by directory
diffing: `missed_inputs.log` (zero-tag inputs) and `failed_inputs.log`
(raising inputs). Nothing else. Both open `O_APPEND|0600` — concurrent appends
won't corrupt but **will interleave engagements** in one file.

Additional concurrency notes:

- The **CLI** deletes both logs at startup (`main()`), so two concurrent CLI
  runs in one CWD stomp each other's logs; the direct-call path never deletes.
- A **cold start** is itself a shared write (extracting `attack-stix-data/`,
  writing `mitre_cache.json`); concurrent cold starts race benignly (same
  content) but wastefully. Recipe A eliminates cold starts.
- **Session dirs never collide** even in a shared CWD: `save_results` claims
  directories with atomic `os.makedirs` + `_NN` suffix retry.

**Net recommendation:** per-engagement CWD + vendored pinned
`mitre_cache.json` + empty `attack-stix-data/` + direct
`enrich_text`/`process_batch` calls (skip `save_results`; serialize results
yourself). Version-pinned, offline, collision-free, zero engine modifications.
