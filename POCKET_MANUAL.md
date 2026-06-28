# HunterEngine — Pocket Manual

Quick operator reference. For full detail see **MANUAL.md**.

---

## Setup (once per shell)

```bash
cd HunterEngine
source .venv/bin/activate           # REQUIRED — or pip/run will fail
```

First run downloads ATT&CK into `mitre_cache.json` (once). Stale cache? `rm mitre_cache.json`.

---

## Analyze

```bash
# deterministic only (no AI), general-purpose profile
python3 HunterEngine.py INPUT.txt --no-ai -c primitives/merged_primitives.json
```

Input = `.txt` (one item per line), `.csv`, or `.json`.

Results land in `HunterEngineBox/session_<timestamp>/`.

```bash
cat HunterEngineBox/session_*/_summary_report.md     # read the verdict
```

---

## Turn on AI advisory (optional)

**Cloud** (sends text off-box — only for authorized data):
```bash
export HUNTER_AI_PROVIDER=anthropic
export HUNTER_AI_MODEL=claude-sonnet-4-5
export HUNTER_AI_ALLOW_REMOTE=1
export HUNTER_AI_API_KEY=<key>
python3 HunterEngine.py INPUT.txt -c primitives/merged_primitives.json
```

**Local** (nothing leaves the box):
```bash
export HUNTER_AI_PROVIDER=openai-compatible
export HUNTER_AI_BASE_URL=http://localhost:11434/v1
export HUNTER_AI_MODEL=llama3.1
python3 HunterEngine.py INPUT.txt -c primitives/merged_primitives.json
```

AI **never** changes the score. `--no-ai` forces it off.

---

## AI-drafted YARA (optional)

```bash
pip install yara-python            # required, one time
python3 HunterEngine.py INPUT.txt --no-ai --ai-yara -c primitives/merged_primitives.json
```

Output → `_ai_yara_NEEDS_REVIEW.yara`. **Review before deploying.** Never auto-merged.

---

## Build the report

```bash
python3 generate_report.py --all          # across all sessions
xdg-open report_aggregate
```

Produces: 6 charts (MITRE-labelled, no message text, anonymized cases),
`EXECUTIVE_SUMMARY.txt`, and `findings_stix_bundle.json` (STIX 2.1).

| Flag | Effect |
|------|--------|
| `--all` | aggregate all sessions |
| `--defang` | neutralize IoCs in STIX (`hxxp://`, `[.]`) |
| `--no-stix` | skip STIX bundle |
| `--out DIR` | output directory |

Correlation chart only appears at **≥20 cases** (by design).

---

## Test the whole pipeline

```bash
./run_pipeline_test.sh
```

Runs all 4 modes (offline / AI-YARA / cloud / local), skips any whose prereqs
are missing, opens all artifacts.

---

## Visualize ATT&CK

- **Heatmap:** open `HunterEngineBox/session_*/_attack_heatmap.svg`
- **Navigator:** upload `_attack_navigator.json` at
  <https://mitre-attack.github.io/attack-navigator/> → *Open Existing Layer*

---

## Artifacts per session

| File | What |
|------|------|
| `results.json` | full machine-readable output (feeds the report) |
| `_summary_report.md` | human-readable verdict |
| `_all_yara_rules.yara` | deployable YARA |
| `_ai_yara_NEEDS_REVIEW.yara` | AI YARA (review first) |
| `_all_indicators.json` | extracted IoCs |
| `_stats.json` | session stats |
| `_attack_navigator.json` | Navigator layer |
| `_attack_heatmap.svg` | heatmap |

---

## Add a primitive (profile = JSON, key `primitives`)

```json
"my_signal": { "score": 4, "keywords": ["phrase one", "phrase two"] }
```

Map it to a technique (key `attack_map`) — all `when` signals must be present:

```json
{ "id": "T1566", "when": ["my_signal", "authority"] }
```

Verify a technique ID is current before using it:
```bash
python3 -c "import json;c=json.load(open('mitre_cache.json'));print('T1566' in {m['id'] for m in c['metadata']})"
```
`False` = wrong/renumbered ID; look it up on attack.mitre.org.

Tune levels in profile `config.risk_thresholds` (LOW/MEDIUM/HIGH; above HIGH = CRITICAL).

---

## Common fixes

| Problem | Fix |
|---------|-----|
| `externally-managed-environment` | activate venv first |
| `ModuleNotFoundError` | venv not active — `source .venv/bin/activate` |
| AI-YARA "requires yara-python" | `pip install yara-python` |
| AI does nothing | set `HUNTER_AI_PROVIDER` + `HUNTER_AI_MODEL` + `HUNTER_AI_ALLOW_REMOTE=1` |
| `attack_map references '<ID>', not present` | fix the ID (renumbered) — fail-closed working |
| no correlation chart | need ≥20 cases; run `--all` |

---

## Security reminders

- **Never commit or paste API keys.** Export them; rotate if exposed.
- **Cloud AI = data leaves the box.** Use local or `--no-ai` for sensitive data.
- **Review AI-YARA before deploying.**
- Reports/STIX contain **no message text**; IoCs included unless `--defang`.
