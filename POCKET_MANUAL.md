# HunterEngine — Pocket Manual

**AI-Augmented Threat Enrichment.** Paste suspicious text in, get scored findings,
IoCs, MITRE techniques, YARA rules, and an AI analyst note out.

This is the 5-minute version. For every detail, see `OPERATIONAL_MANUAL.md`.

---

## What it is, in one breath

A deterministic engine scores and tags suspicious messages and writes YARA
detection rules — **the part you can trust and explain.** An optional AI layer
then adds a plain-English "here's why it's bad and what to do" note and can draft
smarter YARA rules — **the part that makes it fast to act on.** The AI never
changes the score and never auto-deploys anything. Old methods, new intelligence.

---

## 1. Install (once)

```bash
cd HunterEngine
python3 -m venv .venv
source .venv/bin/activate        # your prompt should now show (.venv)
pip install -r requirements.txt
```

> On Kali/Debian, the venv is what avoids the `externally-managed-environment`
> pip error. If your prompt doesn't show `(.venv)`, nothing else will work.

First run downloads MITRE ATT&CK data (~70 MB), once. After that it's instant.

---

## 2. Make an input file

One suspicious message per line:

```bash
cat > sample.txt << 'EOF'
URGENT: Your PayPal account was suspended. Verify at http://paypal-secure-login.evil-domain.com
Hi team, standup at 10am tomorrow.
Hello, this is the CFO. I need an urgent wire transfer today, updated bank details attached.
EOF
```

---

## 3. Run it

```bash
python3 HunterEngine.py sample.txt --no-banner
cat HunterEngineBox/session_*/_summary_report.md
```

You get a `HunterEngineBox/session_<timestamp>/` folder with:

- `_summary_report.md` — **read this first.** Scored findings, IoCs, MITRE hits.
- `_all_yara_rules.yara` — detection rules ready to review and deploy.
- `_all_indicators.json` — every URL/IP/domain/email found.
- `results.json` / `_stats.json` — full data and run stats.

Risk levels: **INFO · LOW · MEDIUM · HIGH · CRITICAL**.

---

## 4. Turn on the AI (optional)

The AI only annotates HIGH/CRITICAL findings. It's off until you configure it.

### Option A — local model (nothing leaves your machine)

```bash
export HUNTER_AI_PROVIDER=openai-compatible
export HUNTER_AI_BASE_URL=http://localhost:11434/v1   # e.g. Ollama
export HUNTER_AI_MODEL=<your-local-model>
python3 HunterEngine.py sample.txt --no-banner
```

### Option B — cloud model (sends text to a provider — opt in on purpose)

```bash
export HUNTER_AI_PROVIDER=anthropic        # or: openai
export HUNTER_AI_MODEL=<your-model-string>
export HUNTER_AI_API_KEY=<key>             # set in shell only; never commit it
export HUNTER_AI_ALLOW_REMOTE=1            # required for any cloud endpoint
python3 HunterEngine.py sample.txt --no-banner
```

Now `_summary_report.md` includes an **AI-Assisted Analysis** block under each
HIGH/CRITICAL item: a summary, why it's malicious, and recommended actions.

> The scores will be identical with or without AI. The AI explains the verdict;
> it never changes it.

---

## 5. AI-drafted YARA rules (optional, opt-in)

Let the model draft detection rules. They are syntax-checked and quarantined for
your review — never auto-deployed.

```bash
pip install yara-python                     # the mandatory compile gate
# (keep the AI env vars from step 4)
python3 HunterEngine.py sample.txt --no-banner --ai-yara
cat HunterEngineBox/session_*/_ai_yara_NEEDS_REVIEW.yara
```

The drafted rules land in `_ai_yara_NEEDS_REVIEW.yara` behind a review banner.
Your deployable `_all_yara_rules.yara` stays untouched. **Review before you ship
any of them** — they compile, but they aren't validated for quality.

---

## 6. Switch threat profiles

Detection logic lives in JSON files in `primitives/`. No code changes.

```bash
# Business email compromise
python3 HunterEngine.py emails.csv -c primitives/bec_financial_primitives.json

# Insider / data exfiltration
python3 HunterEngine.py logs.txt -c primitives/insider_exfil_primitives.json
```

Add your own keywords by editing those JSON files. See the operational manual for
the full schema.

---

## 7. Handy flags

| Flag | Does |
|---|---|
| `--no-banner` | Quiet startup (good for scripts). |
| `--no-ai` | Force the AI layer off, whatever the environment says. |
| `--ai-yara` | Opt in to AI YARA drafting (needs `yara-python` + a provider). |
| `-c <file>` | Use a specific threat profile. |

---

## 8. If something breaks

- **`missing library 'rapidfuzz'`** → you're not in the venv. `source .venv/bin/activate`.
- **`externally-managed-environment`** → same fix: use the venv.
- **`Input file not found`** → check `ls -l <file>`; the file must be where you point.
- **AI did nothing** → set `HUNTER_AI_PROVIDER` + `HUNTER_AI_MODEL`; for cloud also `HUNTER_AI_ALLOW_REMOTE=1`.
- **No quarantine file from `--ai-yara`** → `pip install yara-python`, and make sure the run had HIGH/CRITICAL items.

---

## 9. Two rules to live by

1. **Your prompt must show `(.venv)`.** That single thing prevents most problems.
2. **Never commit or paste your API key.** Set it in the shell only; rotate it if
   it ever leaks.

That's it — you're running. For the deep dive, open `OPERATIONAL_MANUAL.md`.
