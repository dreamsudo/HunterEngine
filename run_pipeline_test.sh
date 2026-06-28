#!/usr/bin/env bash
#
# run_pipeline_test.sh - Exercise the full HunterEngine pipeline in every mode
# and open all produced artifacts for evaluation.
#
# Modes run (each into its own session folder):
#   1. OFFLINE, no AI            (pure deterministic engine)
#   2. OFFLINE, AI-YARA only     (--ai-yara, needs a local OR cloud model)
#   3. ONLINE cloud AI advisory  (full stack; needs HUNTER_AI_API_KEY)
#   4. LOCAL AI advisory         (Ollama; needs ollama serve running)
#
# Usage:
#   cd ~/Documents/hunter_engine/v3_engine/HunterEngine
#   export HUNTER_AI_API_KEY='sk-ant-...'      # only needed for cloud modes
#   ./run_pipeline_test.sh
#
# Modes whose prerequisites are missing are SKIPPED with a notice, never fail.

set -u
PROFILE="primitives/merged_primitives.json"
INPUT="test_input.txt"
ENGINE="HunterEngine.py"
OPEN_CMD="${OPEN_CMD:-xdg-open}"   # override with OPEN_CMD=open on mac

# --- sanity: are we in the repo? ---
if [[ ! -f "$ENGINE" || ! -f "$PROFILE" ]]; then
  echo "ERROR: run this from inside the HunterEngine repo dir."
  echo "  expected to find $ENGINE and $PROFILE here."
  exit 1
fi

# --- make the test input if missing ---
if [[ ! -f "$INPUT" ]]; then
  echo "[setup] creating $INPUT"
  cat > "$INPUT" << 'EOF'
URGENT: Your PayPal account has been suspended. Click http://paypal-secure-login.evil-domain.com to verify now or your account will be permanently closed.
Hi, this is the CEO. I need you to process an urgent wire transfer to a new vendor before end of day. Keep this confidential for now.
IT Security here — your mailbox is over quota and will be deactivated. Reactivate at http://mail-portal-reset.com using your login credentials.
Reminder: please upload the Q3 customer database to my personal Dropbox so I can review it from home this weekend.
EOF
fi

# Track which sessions each run produces by snapshotting the dir before/after.
BOX="HunterEngineBox"
mkdir -p "$BOX"
declare -A RESULT_SESSION
declare -A RESULT_STATUS

run_mode () {
  local label="$1"; shift
  echo ""
  echo "=================================================================="
  echo " RUN: $label"
  echo "=================================================================="
  before=$(ls -1 "$BOX" 2>/dev/null | grep '^session_' || true)
  # run, capture exit
  if python3 "$ENGINE" "$INPUT" -c "$PROFILE" "$@" > "/tmp/he_${label}.log" 2>&1; then
    RESULT_STATUS[$label]="ok"
  else
    RESULT_STATUS[$label]="FAILED (see /tmp/he_${label}.log)"
  fi
  sleep 1
  after=$(ls -1 "$BOX" 2>/dev/null | grep '^session_' || true)
  newsess=$(comm -13 <(echo "$before"|sort) <(echo "$after"|sort) | tail -1)
  RESULT_SESSION[$label]="$newsess"
  # surface key log lines
  grep -E "AI advisory enabled|AI advisory complete|remote=|attack_map references|NEEDS_REVIEW|Saved .* MITRE|ERROR" \
    "/tmp/he_${label}.log" | sed 's/^/   /' || true
}

# ---- MODE 1: offline, no AI ----
run_mode "1_offline_noai" --no-ai

# ---- MODE 2: offline deterministic + AI-YARA only ----
# AI-YARA needs a model. If a key is set we let it use cloud; else if ollama is
# up it uses that; else the feature self-skips (compile gate). Advisory stays off.
if [[ -n "${HUNTER_AI_API_KEY:-}" ]]; then
  export HUNTER_AI_PROVIDER="${HUNTER_AI_PROVIDER:-anthropic}"
  export HUNTER_AI_MODEL="${HUNTER_AI_MODEL:-claude-sonnet-4-5}"
  export HUNTER_AI_ALLOW_REMOTE=1
fi
run_mode "2_aiyara_only" --no-ai --ai-yara

# ---- MODE 3: cloud AI advisory (full stack) ----
if [[ -n "${HUNTER_AI_API_KEY:-}" ]]; then
  ( export HUNTER_AI_PROVIDER=anthropic
    export HUNTER_AI_MODEL="${HUNTER_AI_MODEL:-claude-sonnet-4-5}"
    export HUNTER_AI_ALLOW_REMOTE=1
    unset HUNTER_AI_BASE_URL
    python3 "$ENGINE" "$INPUT" -c "$PROFILE" > "/tmp/he_3_cloud_ai.log" 2>&1 )
  st=$?
  before_dummy=""  # cloud run handled inline; grab newest session
  RESULT_SESSION[3_cloud_ai]=$(ls -1d "$BOX"/session_* 2>/dev/null | tail -1 | xargs -n1 basename)
  [[ $st -eq 0 ]] && RESULT_STATUS[3_cloud_ai]="ok" || RESULT_STATUS[3_cloud_ai]="FAILED (see /tmp/he_3_cloud_ai.log)"
  echo ""
  echo "=================================================================="
  echo " RUN: 3_cloud_ai"
  echo "=================================================================="
  grep -E "AI advisory enabled|AI advisory complete|remote=|ERROR" /tmp/he_3_cloud_ai.log | sed 's/^/   /' || true
else
  echo ""
  echo "[skip] 3_cloud_ai: HUNTER_AI_API_KEY not set. To run cloud AI:"
  echo "       export HUNTER_AI_API_KEY='sk-ant-...' && re-run this script"
  RESULT_STATUS[3_cloud_ai]="skipped (no API key)"
fi

# ---- MODE 4: local AI advisory (Ollama) ----
if curl -s -o /dev/null -m 2 http://localhost:11434/api/tags 2>/dev/null; then
  ( export HUNTER_AI_PROVIDER=openai-compatible
    export HUNTER_AI_BASE_URL=http://localhost:11434/v1
    export HUNTER_AI_MODEL="${HUNTER_LOCAL_MODEL:-llama3.1}"
    unset HUNTER_AI_ALLOW_REMOTE
    python3 "$ENGINE" "$INPUT" -c "$PROFILE" > "/tmp/he_4_local_ai.log" 2>&1 )
  st=$?
  RESULT_SESSION[4_local_ai]=$(ls -1d "$BOX"/session_* 2>/dev/null | tail -1 | xargs -n1 basename)
  [[ $st -eq 0 ]] && RESULT_STATUS[4_local_ai]="ok" || RESULT_STATUS[4_local_ai]="FAILED (see /tmp/he_4_local_ai.log)"
  echo ""
  echo "=================================================================="
  echo " RUN: 4_local_ai"
  echo "=================================================================="
  grep -E "AI advisory enabled|AI advisory complete|remote=|ERROR" /tmp/he_4_local_ai.log | sed 's/^/   /' || true
else
  echo ""
  echo "[skip] 4_local_ai: no Ollama on localhost:11434. To run local AI:"
  echo "       ollama serve & ollama pull llama3.1   (then re-run)"
  RESULT_STATUS[4_local_ai]="skipped (ollama not running)"
fi

# ============================ SUMMARY ============================
echo ""
echo "=================================================================="
echo " PIPELINE TEST SUMMARY"
echo "=================================================================="
for m in 1_offline_noai 2_aiyara_only 3_cloud_ai 4_local_ai; do
  printf "  %-18s %s\n" "$m" "${RESULT_STATUS[$m]:-?}"
  [[ -n "${RESULT_SESSION[$m]:-}" ]] && printf "  %-18s   -> %s\n" "" "${RESULT_SESSION[$m]}"
done

# ============================ OPEN ARTIFACTS ============================
# Open artifacts from the richest run available (prefer cloud, else local,
# else aiyara, else offline). Also dump them to the terminal.
PICK=""
for m in 3_cloud_ai 4_local_ai 2_aiyara_only 1_offline_noai; do
  if [[ -n "${RESULT_SESSION[$m]:-}" && -d "$BOX/${RESULT_SESSION[$m]}" ]]; then PICK="${RESULT_SESSION[$m]}"; PICKLABEL="$m"; break; fi
done

if [[ -z "$PICK" ]]; then
  echo ""
  echo "No session produced - check the logs in /tmp/he_*.log"
  exit 1
fi

SESS="$BOX/$PICK"
echo ""
echo "=================================================================="
echo " ARTIFACTS from richest run: $PICKLABEL  ($PICK)"
echo "=================================================================="
echo ""
echo "----- _summary_report.md -----";    cat "$SESS/_summary_report.md" 2>/dev/null
echo ""; echo "----- _all_yara_rules.yara -----"; cat "$SESS/_all_yara_rules.yara" 2>/dev/null
[[ -f "$SESS/_ai_yara_NEEDS_REVIEW.yara" ]] && { echo ""; echo "----- _ai_yara_NEEDS_REVIEW.yara -----"; cat "$SESS/_ai_yara_NEEDS_REVIEW.yara"; }
echo ""; echo "----- _all_indicators.json -----"; cat "$SESS/_all_indicators.json" 2>/dev/null
echo ""; echo "----- _stats.json -----";         cat "$SESS/_stats.json" 2>/dev/null
echo ""; echo "----- _attack_navigator.json (data for navigator) -----"; cat "$SESS/_attack_navigator.json" 2>/dev/null

# Open the visual + the folder
echo ""
echo "[open] launching artifacts with $OPEN_CMD ..."
"$OPEN_CMD" "$SESS/_attack_heatmap.svg"  2>/dev/null &
"$OPEN_CMD" "$SESS/_summary_report.md"   2>/dev/null &
"$OPEN_CMD" "$SESS"                       2>/dev/null &

echo ""
echo "Navigator layer (interactive matrix): upload this file at"
echo "  https://mitre-attack.github.io/attack-navigator/  (Open Existing Layer)"
echo "  $SESS/_attack_navigator.json"
echo ""
echo "All session folders this run:"
for m in 1_offline_noai 2_aiyara_only 3_cloud_ai 4_local_ai; do
  [[ -n "${RESULT_SESSION[$m]:-}" ]] && echo "  $m -> $BOX/${RESULT_SESSION[$m]}"
done
