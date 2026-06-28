#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###############################################################################
#
#                      *
#                     ***
#                    *****
#                   *******
#                  *********
#                 ***********
#                *****Psypher*****
#                 *****Labs *****
#                  ***********
#                   *******
#                    *****
#                     ***
#                      *
#
#   HunterEngine.py - Heuristic Threat Enrichment Engine by PsypherLabs
#
###############################################################################
#
# Author: PsypherLabs
#
# Description:
#   - Ingests unstructured text data (emails, SMS, logs) for analysis.
#   - Enriches inputs with heuristic tags, IoCs, and MITRE ATT&CK TTPs.
#   - Calculates a risk score and generates high-fidelity YARA rules.
#   - Outputs all findings to a structured session folder with reports.
#   - Optionally attaches an AI advisory note (advisory only) to HIGH/CRITICAL
#     findings via a model-agnostic interface (see ai_enrichment.py).
#   - Intended for Blue Teams, Threat Hunters, and Security Researchers.
#
# MIT License - Copyright (c) 2025 PsypherLabs
# See LICENSE file for details.
#
###############################################################################

# --- Standard Library Imports ---
import os
import re
import sys
import csv
import json
import hashlib
import argparse
import logging
import zipfile
import io
from datetime import datetime
from collections import Counter
from typing import List, Dict, Any, Tuple, Generator, Iterable

# --- Dependency Check & Third-Party Imports ---
try:
    import requests
    from tqdm import tqdm
    from rapidfuzz import fuzz
    from stix2 import MemoryStore, Filter
except ImportError as e:
    print("\n--- Missing Dependencies ---")
    print(f"Error: A required library is missing: '{e.name}'")
    print("Please install all dependencies by running:")
    print("    pip install -r requirements.txt")
    print("Or directly:")
    print("    pip install requests tqdm rapidfuzz stix2")
    print("----------------------------\n")
    sys.exit(1)


# --- Banners and Manuals ---

def print_banner():
    """Prints the ASCII art logo in bright green."""
    # Enable ANSI escape sequence processing on Windows terminals.
    if os.name == 'nt':
        os.system('')

    bright_green = "\033[92m"
    reset_color = "\033[0m"

    banner = f"""{bright_green}
                      *
                     ***
                    *****
                   *******
                  *********
                 ***********
                *****Psypher*****
                 *****Labs *****
                  ***********
                   *******
                    *****
                     ***
                      *

        HunterEngine by PsypherLabs
  Heuristic Threat Enrichment & Hunting Engine
{reset_color}"""
    print(banner)


def print_manual_and_license():
    """Prints the license and legal disclosure."""
    manual = """
===============================================================================
 MIT LICENSE & ETHICAL USE NOTICE
===============================================================================
Copyright (c) 2025 PsypherLabs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

--- LEGAL & ETHICAL USE DISCLOSURE ---
This tool is intended for legitimate cybersecurity purposes ONLY, including
blue team analysis, threat hunting, and security research. Unauthorized use
of this tool on any system or with any data for which you do not have explicit
permission is strictly prohibited. The authors are not responsible for any
misuse or damage caused by this program. YOU ARE RESPONSIBLE FOR YOUR ACTIONS.
===============================================================================
"""
    print(manual)


# --- GLOBAL CONFIGURATION & LOGGING ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for data sources and file paths
MITRE_CTI_URL = "https://github.com/mitre/cti/archive/refs/heads/master.zip"
MITRE_DIRS = [
    "attack-stix-data/enterprise-attack",
    "attack-stix-data/mobile-attack",
    "attack-stix-data/ics-attack",
]
OUTPUT_ROOT = "HunterEngineBox"
MISS_LOG = "missed_inputs.log"
ERROR_LOG = "failed_inputs.log"
MITRE_CACHE_FILE = "mitre_cache.json"
DEFAULT_PRIMITIVES_CONFIG_FILE = "primitives/default_phishing_primitives.json"

# Safety caps
MAX_INPUT_LEN = 50_000               # per-input char cap (bounds fuzzy-match cost)
MAX_DOWNLOAD_BYTES = 250 * 1024 * 1024   # compressed download cap
MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024  # zip-bomb guard

# Matching / fidelity defaults (overridable via config)
MITRE_MIN_WORD_LEN = 5               # single-word MITRE phrases shorter than this
                                     # are too generic to be signal; skipped
DEFAULT_YARA_MIN_TOKEN_LEN = 7       # single-token YARA strings shorter than this
                                     # are dropped as weak/noisy


class ThreatEnrichmentEngine:
    """
    Encapsulates all threat enrichment logic, from data setup to analysis and
    artifact generation.
    """

    def __init__(self, config_path: str = DEFAULT_PRIMITIVES_CONFIG_FILE):
        self.config_path = config_path
        self.mitre_keywords: Dict[str, List[str]] = {}
        self.mitre_metadata: List[Dict[str, Any]] = []
        self.heuristic_classifiers: List[Dict[str, Any]] = []
        self.risk_thresholds = {"LOW": 4, "MEDIUM": 8, "HIGH": 12}
        self.fuzzy_threshold = 85
        self.score_boosts = {"has_indicator": 5, "mitre_ttp": 6}
        self.yara_min_token_len = DEFAULT_YARA_MIN_TOKEN_LEN
        self._mitre_index: Dict[str, Dict[str, Any]] = {}
        self.attack_map: List[Dict[str, Any]] = []
        self.attack_fuzzy_fallback = False
        self._attack_unknown_warned: set = set()

    def get_risk_level(self, score: int) -> str:
        if score == 0:
            return "INFO"
        if score <= self.risk_thresholds["LOW"]:
            return "LOW"
        if score <= self.risk_thresholds["MEDIUM"]:
            return "MEDIUM"
        if score <= self.risk_thresholds["HIGH"]:
            return "HIGH"
        return "CRITICAL"

    def setup_dependencies(self):
        self._load_configuration()
        self._setup_mitre_data()
        self.mitre_keywords, self.mitre_metadata = self._get_mitre_data()
        self._mitre_index = {t["id"]: t for t in self.mitre_metadata}

    def _load_configuration(self):
        if not os.path.exists(self.config_path):
            logging.error("Configuration file not found at '%s'.", self.config_path)
            logging.error("Ensure a primitives file exists or use -c to specify a path.")
            sys.exit(1)

        logging.info("Loading configuration from %s", self.config_path)
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                config_data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logging.error("Failed to parse configuration '%s': %s", self.config_path, e)
            sys.exit(1)

        if not isinstance(config_data, dict):
            logging.error("Configuration root must be a JSON object.")
            sys.exit(1)

        engine_config = config_data.get("config", {})
        self.fuzzy_threshold = engine_config.get("fuzzy_threshold", self.fuzzy_threshold)
        self.risk_thresholds = engine_config.get("risk_thresholds", self.risk_thresholds)
        self.score_boosts = engine_config.get("score_boosts", self.score_boosts)
        self.yara_min_token_len = engine_config.get("yara_min_token_len",
                                                    self.yara_min_token_len)
        self.attack_fuzzy_fallback = bool(
            engine_config.get("attack_fuzzy_fallback", False))

        # ATT&CK technique mapping rules (combo-aware). A rule fires when ALL
        # signals in its "when" list are present. Empty/missing -> fall back to
        # description fuzzy matching (legacy behaviour) for long-form text.
        self.attack_map = config_data.get("attack_map", [])
        if not isinstance(self.attack_map, list):
            logging.warning("attack_map must be a list; ignoring.")
            self.attack_map = []

        # Minimal schema validation so a malformed profile fails clearly, not deep
        # inside the hot loop.
        for key in ("LOW", "MEDIUM", "HIGH"):
            if key not in self.risk_thresholds:
                logging.error("risk_thresholds missing required key '%s'.", key)
                sys.exit(1)

        logging.info("Risk thresholds set to: %s", self.risk_thresholds)
        logging.info("Fuzzy matching threshold set to: %s", self.fuzzy_threshold)
        logging.info("Score boosts set to: %s", self.score_boosts)

        primitives = config_data.get("primitives", {})
        if not isinstance(primitives, dict) or not primitives:
            logging.error("Configuration must contain a non-empty 'primitives' object.")
            sys.exit(1)

        compiled_classifiers = []
        for name, data in primitives.items():
            if not isinstance(data, dict) or "keywords" not in data \
                    or not isinstance(data["keywords"], list) or not data["keywords"]:
                logging.error("Primitive '%s' must define a non-empty 'keywords' list.", name)
                sys.exit(1)
            pattern = r'\b(' + '|'.join(re.escape(k) for k in data["keywords"]) + r')\b'
            compiled_classifiers.append({
                "name": name,
                "score": data.get("score", 1),
                "regex": re.compile(pattern, re.IGNORECASE),
            })
        self.heuristic_classifiers = compiled_classifiers
        logging.info("Heuristic classifiers built for: %s", ', '.join(primitives.keys()))

    def _setup_mitre_data(self):
        if os.path.exists("attack-stix-data"):
            return
        logging.warning("MITRE ATT&CK data not found. Downloading... (approx. 70MB)")

        base_dir = os.path.realpath("attack-stix-data")
        allowed_roots = {"enterprise-attack", "mobile-attack", "ics-attack"}
        try:
            # Stream with a hard size cap so a hostile/MITM endpoint cannot
            # exhaust memory.
            with requests.get(MITRE_CTI_URL, stream=True, timeout=120) as response:
                response.raise_for_status()
                buf, total = io.BytesIO(), 0
                for chunk in response.iter_content(chunk_size=1 << 16):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise ValueError("MITRE download exceeded size cap; aborting.")
                    buf.write(chunk)
                buf.seek(0)

            extracted = 0
            with zipfile.ZipFile(buf) as zf:
                for member in tqdm(zf.infolist(), desc="Extracting MITRE data"):
                    parts = member.filename.split('/')[1:]
                    if not parts or parts[0] not in allowed_roots or member.is_dir():
                        continue
                    extracted += member.file_size
                    if extracted > MAX_UNCOMPRESSED_BYTES:
                        raise ValueError("MITRE archive exceeded uncompressed cap; aborting.")

                    target_path = os.path.realpath(os.path.join(base_dir, *parts))
                    # Zip-slip guard: extracted path must remain inside base_dir.
                    if os.path.commonpath([base_dir, target_path]) != base_dir:
                        logging.warning("Skipping unsafe archive path: %s", member.filename)
                        continue
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    with open(target_path, "wb") as f:
                        f.write(zf.read(member.filename))
            logging.info("MITRE ATT&CK data downloaded and extracted successfully.")
        except requests.exceptions.RequestException as e:
            logging.error("Network error downloading MITRE data: %s", e)
            sys.exit(1)
        except Exception as e:
            logging.error("Failed to download or extract MITRE data: %s", e)
            sys.exit(1)

    def _get_mitre_data(self) -> Tuple[Dict, List]:
        if os.path.exists(MITRE_CACHE_FILE):
            logging.info("Loading MITRE data from cache: %s", MITRE_CACHE_FILE)
            try:
                with open(MITRE_CACHE_FILE, "r", encoding="utf-8") as f:
                    cache = json.load(f)
                return cache["keywords"], cache["metadata"]
            except (json.JSONDecodeError, KeyError, OSError) as e:
                logging.warning("MITRE cache unreadable (%s); rebuilding.", e)

        logging.info("Building MITRE cache from STIX data...")
        store = MemoryStore()
        for folder in MITRE_DIRS:
            path = os.path.join(folder, f"{os.path.basename(folder)}.json")
            if not os.path.exists(path):
                logging.warning("STIX file not found, skipping: %s", path)
                continue
            logging.info("Processing STIX data from: %s", path)
            try:
                store.load_from_file(path)
            except Exception as e:
                logging.error("Failed to process %s: %s", path, e)

        logging.info("Extracting and caching MITRE ATT&CK techniques...")
        mitre_keywords: Dict[str, List[str]] = {}
        mitre_metadata: List[Dict[str, Any]] = []
        tech_filter = [Filter("type", "=", "attack-pattern"),
                       Filter("revoked", "=", False)]
        for obj in store.query(tech_filter):
            if obj.get("x_mitre_deprecated", False):
                continue

            tid = next(
                (ref.get("external_id") for ref in obj.get("external_references", [])
                 if ref.get("source_name", "").startswith("mitre-")), None)
            if not tid:
                continue

            phrases = {
                s.strip().lower()
                for s in re.split(r'[.?!]\s+', obj.get("description", ""))
                if 5 <= len(s.strip()) <= 150
            }
            name = obj.get("name", "").strip().lower()
            if name and len(name) > 4:
                phrases.add(name)

            if phrases:
                mitre_keywords[tid] = sorted(phrases)
                mitre_metadata.append({
                    "id": tid,
                    "name": obj.get("name", "N/A"),
                    "tactic": next((p.get("phase_name")
                                    for p in obj.get("kill_chain_phases", [])), "unknown"),
                })

        with open(MITRE_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({"keywords": mitre_keywords, "metadata": mitre_metadata}, f, indent=2)
        logging.info("Saved %d MITRE techniques to cache: %s",
                     len(mitre_keywords), MITRE_CACHE_FILE)
        return mitre_keywords, mitre_metadata

    def _extract_indicators(self, text: str) -> Dict[str, List[str]]:
        ipv4_pattern = (r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        patterns = {
            "urls": re.compile(r'https?://[^\s/$.?#].[^\s]*', re.IGNORECASE),
            "domains": re.compile(
                r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b'),
            "emails": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
            "ipv4": re.compile(ipv4_pattern),
        }
        indicators = {name: list(set(p.findall(text))) for name, p in patterns.items()}

        if indicators.get("domains") and indicators.get("urls"):
            url_domains = {
                m.group(0) for url in indicators["urls"]
                if (m := re.search(patterns["domains"], url))
            }
            indicators["domains"] = [d for d in indicators["domains"]
                                     if d not in url_domains]

        return {k: v for k, v in indicators.items() if v}

    def _map_attack(self, signals: set) -> List[Dict[str, Any]]:
        """Deterministic, combo-aware ATT&CK mapping.

        `signals` is the set of fired primitive names plus derived tags
        (e.g. 'has_indicator'). A rule's technique fires only when ALL of its
        `when` signals are present. Every emitted technique ID is validated
        against the loaded ATT&CK data (`_mitre_index`): unknown IDs (e.g. an ID
        that was renumbered) FAIL CLOSED — logged once and skipped — and the
        official name/tactic are pulled from the real data, never assumed.
        """
        fired: Dict[str, set] = {}  # technique_id -> set(triggering primitives)
        for rule in self.attack_map:
            tid = rule.get("id")
            when = rule.get("when", [])
            if not tid or not isinstance(when, list) or not when:
                continue
            if all(sig in signals for sig in when):
                fired.setdefault(tid, set()).update(when)

        results: List[Dict[str, Any]] = []
        for tid, via in sorted(fired.items()):
            tech = self._mitre_index.get(tid)
            if not tech:
                if tid not in self._attack_unknown_warned:
                    logging.warning(
                        "attack_map references '%s', which is not present in the "
                        "loaded ATT&CK data; skipping (check the ID is current).",
                        tid)
                    self._attack_unknown_warned.add(tid)
                continue
            results.append({
                "id": tid,
                "name": tech["name"],
                "tactic": tech["tactic"],
                "via": sorted(via),
                "match_type": "combo-map",
            })
        return results

    def _match_mitre(self, text_lower: str) -> List[Dict[str, Any]]:
        """Precise, auditable MITRE matching.

        Root-cause fix for substring false positives (e.g. the technique name
        "Domains" matching inside "evil-domain.com"):
          * Single-word phrases must appear as a WHOLE WORD (word-boundary regex).
            Generic one-word names like "domains"/"accounts" no longer match a
            random substring. Words shorter than MITRE_MIN_WORD_LEN are skipped
            as too generic to be signal.
          * Multi-word phrases keep fuzzy partial matching (tolerates minor
            variation) at the configured threshold.
        Every match records the phrase, score, and match type so an analyst can
        SEE why a technique was tagged rather than trusting an opaque assertion.
        """
        results: List[Dict[str, Any]] = []
        for tid, phrases in self.mitre_keywords.items():
            best = None  # (phrase, score, match_type)
            for phrase in phrases:
                if ' ' in phrase:
                    score = fuzz.partial_ratio(phrase, text_lower)
                    if score >= self.fuzzy_threshold and (best is None or score > best[1]):
                        best = (phrase, int(score), "fuzzy")
                else:
                    if len(phrase) < MITRE_MIN_WORD_LEN:
                        continue
                    if re.search(r'\b' + re.escape(phrase) + r'\b', text_lower):
                        if best is None or best[1] < 100:
                            best = (phrase, 100, "exact")
            if best:
                tech = self._mitre_index.get(tid)
                if tech:
                    results.append({
                        "id": tid,
                        "name": tech["name"],
                        "tactic": tech["tactic"],
                        "matched_phrase": best[0],
                        "score": best[1],
                        "match_type": best[2],
                    })
        results.sort(key=lambda m: m["id"])
        return results

    def _yara_string_is_strong(self, s: str) -> bool:
        """Deterministic fidelity filter: drop weak single-token strings that
        flood rules with noise (e.g. 'login', 'urgent', 'click'). Indicators are
        passed in separately and always kept."""
        if ' ' in s:                       # multi-word phrase: distinctive
            return True
        if '://' in s or '@' in s:         # url / email shaped
            return True
        if '.' in s and any(c.isdigit() for c in s):  # ip-ish
            return True
        if len(s) >= self.yara_min_token_len:         # long enough to be specific
            return True
        return False

    def _sanitize_yara_string(self, value: str) -> str:
        value = value.replace('\\', '\\\\')
        value = value.replace('"', '\\"')
        # Escape only control characters (and DEL). Printable Unicode such as an
        # em-dash is valid UTF-8 in a YARA string and stays human-readable in the
        # meta field rather than becoming an ugly \xNNNN escape.
        return ''.join(
            c if (ord(c) >= 32 and ord(c) != 127) else f'\\x{ord(c):02x}'
            for c in value)

    def _generate_yara_rule(self, result: Dict) -> str:
        if result['analysis']['risk_score'] == 0:
            return ""

        # Indicators (URLs, IPs, domains, emails) are concrete — always keep.
        # Primitive keyword matches are filtered to drop weak, noisy tokens.
        indicator_strings: List[str] = []
        for ind_list in result['indicators'].values():
            indicator_strings.extend(ind_list)
        primitive_strings: List[str] = []
        for data in result['analysis']['matched_primitives'].values():
            primitive_strings.extend(data['matches'])
        strong_primitives = [s for s in primitive_strings
                             if self._yara_string_is_strong(s)]
        high_confidence_strings = sorted(set(indicator_strings + strong_primitives))

        if not high_confidence_strings:
            logging.debug("Skipping YARA rule for '%s...' (no strong strings).",
                          result['input'][:50])
            return ""

        # Content-hash naming: unique per distinct input, and identical inputs
        # collapse to one rule instead of producing duplicate, non-compiling names.
        digest = hashlib.sha1(
            result['input'].encode('utf-8', 'ignore')).hexdigest()[:10]
        safe = re.sub(r'[^a-zA-Z0-9_]', '',
                      result['input'].replace(' ', '_'))[:40]
        rule_name = f"threat_heuristic_{safe}_{digest}"

        meta = result['analysis'].copy()
        meta["input_text"] = self._sanitize_yara_string(result["input"][:1024])
        if result['mitre_matches']:
            meta["mitre_ttps"] = ", ".join(m["id"] for m in result["mitre_matches"])
        meta_fields = [
            f'\t\t{k} = "{self._sanitize_yara_string(str(v))}"'
            for k, v in meta.items() if k != 'matched_primitives'
        ]

        string_fields = [
            f'\t\t$s{i+1} = "{self._sanitize_yara_string(s)}" nocase wide ascii'
            for i, s in enumerate(sorted(set(high_confidence_strings)))
        ]

        condition = "2 of them" if len(string_fields) > 2 else "all of them"

        return f"""
rule {rule_name}
{{
    meta:
{os.linesep.join(meta_fields)}
    strings:
{os.linesep.join(string_fields)}
    condition:
        {condition}
}}
"""

    def enrich_text(self, text: str) -> Dict:
        if len(text) > MAX_INPUT_LEN:
            text = text[:MAX_INPUT_LEN]
        text_lower = text.lower()

        matched_primitives = {}
        for classifier in self.heuristic_classifiers:
            matches = list(set(classifier["regex"].findall(text_lower)))
            if matches:
                matched_primitives[classifier["name"]] = {
                    "score": classifier["score"], "matches": matches}

        risk_score = sum(p["score"] for p in matched_primitives.values())
        tags = set(matched_primitives.keys())

        indicators = self._extract_indicators(text)
        if indicators:
            tags.add("has_indicator")
            risk_score += self.score_boosts.get("has_indicator", 5)

        # ATT&CK mapping: combo-rule map (primary). Signals = fired primitives
        # plus derived tags. Fuzzy description matching is a fallback only when
        # no map is configured, or when explicitly enabled for long-form text.
        signals = set(matched_primitives.keys())
        if indicators:
            signals.add("has_indicator")

        if self.attack_map:
            mitre_matches = self._map_attack(signals)
            if self.attack_fuzzy_fallback:
                seen = {m["id"] for m in mitre_matches}
                for m in self._match_mitre(text_lower):
                    if m["id"] not in seen:
                        mitre_matches.append(m)
                        seen.add(m["id"])
                mitre_matches.sort(key=lambda m: m["id"])
        else:
            mitre_matches = self._match_mitre(text_lower)

        if mitre_matches:
            tags.add("mitre_ttp")
            risk_score += self.score_boosts.get("mitre_ttp", 6)
            for m in mitre_matches:
                if m["tactic"] != 'unknown':
                    tags.add(m["tactic"])

        if not tags:
            with open(MISS_LOG, "a", encoding="utf-8") as f:
                f.write(text + "\n")

        result = {
            "input": text,
            "analysis": {
                "risk_score": risk_score,
                "risk_level": self.get_risk_level(risk_score),
                "tags": sorted(tags),
                "matched_primitives": matched_primitives,
            },
            "indicators": indicators,
            "mitre_matches": mitre_matches,
        }
        result["yara_rule"] = self._generate_yara_rule(result)
        return result

    def process_batch(self, inputs: Iterable[str]) -> List[Dict]:
        logging.info("Starting enrichment process...")
        results = []
        for text in tqdm(inputs, desc="Enriching"):
            try:
                if not text or not isinstance(text, str):
                    continue
                results.append(self.enrich_text(text))
            except Exception:
                # Avoid echoing raw (possibly PII-laden) input to the console.
                logging.error("Failed to process an input (len=%d); written to %s.",
                              len(text) if isinstance(text, str) else -1, ERROR_LOG)
                logging.debug("Processing error detail", exc_info=True)
                with open(ERROR_LOG, "a", encoding="utf-8") as f:
                    f.write(f"{text}\n")
        return results


def load_inputs(path: str) -> Generator[str, None, None]:
    if not os.path.exists(path):
        logging.error("Input file not found: %s", path)
        sys.exit(1)
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            if path.lower().endswith(".csv"):
                reader = csv.reader(f)
                for row in reader:
                    if row:
                        yield row[0]
            elif path.lower().endswith(".json"):
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        yield item.get("input", str(item)) \
                            if isinstance(item, dict) else str(item)
                elif isinstance(data, dict):
                    yield data.get("input", str(data))
            else:
                for line in f:
                    if stripped := line.strip():
                        yield stripped
    except Exception as e:
        logging.error("Failed to read input file %s: %s", path, e)
        sys.exit(1)


def save_results(results: List[Dict], ai_yara_rules: List[str] = None,
                 ai_yara_summary: Dict = None):
    if not results:
        logging.warning("No results were generated. Skipping output file creation.")
        return
    session_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    session_path = os.path.join(OUTPUT_ROOT, f"session_{session_id}")
    os.makedirs(session_path, exist_ok=True)
    try:
        # Findings can contain sensitive input; restrict to owner. No-op on Windows.
        os.chmod(session_path, 0o700)
    except OSError:
        pass
    logging.info("Saving results to directory: %s", session_path)

    with open(os.path.join(session_path, "results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    contextual_indicators = []
    for res in results:
        if res['indicators']:
            contextual_indicators.append({
                "input": res['input'],
                "risk_level": res['analysis']['risk_level'],
                "indicators": res['indicators'],
            })
    if contextual_indicators:
        with open(os.path.join(session_path, "_all_indicators.json"),
                  "w", encoding="utf-8") as f:
            json.dump(contextual_indicators, f, indent=2)

    all_yara_rules = [res['yara_rule'] for res in results if res['yara_rule']]
    if all_yara_rules:
        with open(os.path.join(session_path, "_all_yara_rules.yara"),
                  "w", encoding="utf-8") as f:
            f.write("\n".join(all_yara_rules))

    # AI-drafted YARA rules go to a SEPARATE, clearly-banner-ed quarantine file —
    # never mixed into the deployable ruleset above.
    if ai_yara_rules:
        from yara_ai import quarantine_header
        model_label = (ai_yara_summary or {}).get("model")
        with open(os.path.join(session_path, "_ai_yara_NEEDS_REVIEW.yara"),
                  "w", encoding="utf-8") as f:
            f.write(quarantine_header(model_label, session_id))
            f.write("\n".join(ai_yara_rules))
        logging.warning("Wrote %d AI-drafted rule(s) to _ai_yara_NEEDS_REVIEW.yara "
                        "(review required; NOT deployable as-is).",
                        len(ai_yara_rules))

    stats = {
        "session_id": session_id,
        "total_inputs_processed": len(results),
        "risk_level_counts": dict(
            Counter(r["analysis"]["risk_level"] for r in results)),
        "tag_counts": dict(
            Counter(tag for r in results
                    for tag in r['analysis']['tags']).most_common()),
        "top_10_mitre_techniques": [
            {"id": k[0], "name": k[1], "count": v}
            for k, v in Counter(
                (m["id"], m.get("name"))
                for r in results for m in r["mitre_matches"]).most_common(10)
        ],
    }
    with open(os.path.join(session_path, "_stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)

    # Standards-based ATT&CK output + visualization (no-op if nothing mapped).
    try:
        from attack_viz import write_navigator_layer, write_heatmap_svg
        if write_navigator_layer(
                results, os.path.join(session_path, "_attack_navigator.json"),
                session_id):
            logging.info("Wrote ATT&CK Navigator layer: _attack_navigator.json "
                         "(import at mitre-attack.github.io/attack-navigator).")
        if write_heatmap_svg(
                results, os.path.join(session_path, "_attack_heatmap.svg"),
                session_id):
            logging.info("Wrote ATT&CK heatmap: _attack_heatmap.svg")
    except Exception as e:
        logging.warning("ATT&CK visualization step failed (continuing): %s", e)

    generate_summary_report(results, stats,
                            os.path.join(session_path, "_summary_report.md"),
                            ai_yara_summary=ai_yara_summary)
    logging.info("All output files saved successfully.")


def generate_summary_report(results: List[Dict], stats: Dict, path: str,
                            ai_yara_summary: Dict = None):
    report_lines = [f"# Threat Enrichment Report: {stats['session_id']}", ""]

    report_lines.append("## Executive Summary")
    report_lines.append(f"- **Total Inputs Analyzed:** {stats['total_inputs_processed']}")
    report_lines.append("- **Risk Level Distribution:**")
    risk_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for level, count in sorted(stats['risk_level_counts'].items(),
                               key=lambda item: risk_order.index(item[0])):
        report_lines.append(f"  - {level}: {count}")
    report_lines.append("")

    if ai_yara_summary and ai_yara_summary.get("status") not in (None, "disabled"):
        report_lines.append("## AI-Drafted YARA (review required)")
        report_lines.append(
            f"- Status: {ai_yara_summary.get('status')} "
            f"(model: {ai_yara_summary.get('model', 'n/a')})")
        report_lines.append(
            f"- Drafted: {ai_yara_summary.get('drafted', 0)} · "
            f"passed compile gate: {ai_yara_summary.get('compiled_ok', 0)} · "
            f"discarded: {ai_yara_summary.get('discarded', 0)}")
        if ai_yara_summary.get("compiled_ok", 0):
            report_lines.append(
                "- See `_ai_yara_NEEDS_REVIEW.yara`. These are NOT validated for "
                "detection quality and must be reviewed before deployment.")
        report_lines.append("")

    report_lines.append("## High-Risk Items")
    high_risk_items = sorted(
        [r for r in results if r['analysis']['risk_level'] in ["HIGH", "CRITICAL"]],
        key=lambda x: x['analysis']['risk_score'], reverse=True)
    if not high_risk_items:
        report_lines.append("No HIGH or CRITICAL risk items found.")
    else:
        for item in high_risk_items[:20]:
            report_lines.append(f"### Input: `{item['input'][:200]}`")
            report_lines.append(
                f"- **Risk Score:** {item['analysis']['risk_score']} "
                f"({item['analysis']['risk_level']})")
            report_lines.append(f"- **Tags:** `{', '.join(item['analysis']['tags'])}`")
            if item['indicators']:
                report_lines.append("- **Indicators:**")
                for ind_type, ind_list in item['indicators'].items():
                    report_lines.append(
                        f"  - {ind_type.capitalize()}: `{', '.join(ind_list)}`")
            if item['mitre_matches']:
                report_lines.append("- **MITRE TTPs:**")
                for match in item['mitre_matches']:
                    if match.get('via'):
                        ev = f" — via {', '.join(match['via'])}"
                    elif match.get('matched_phrase'):
                        ev = (f" — matched \"{match['matched_phrase']}\" "
                              f"({match.get('match_type', '?')}, {match.get('score', '?')})")
                    else:
                        ev = ""
                    report_lines.append(f"  - {match['id']}: {match['name']}{ev}")

            adv = item.get("ai_advisory")
            if adv:
                report_lines.append(
                    f"- **AI-Assisted Analysis** _(advisory only \u2014 verify before "
                    f"acting; {adv.get('_model', 'model')})_:")
                report_lines.append(f"  - Summary: {adv['summary']}")
                if adv.get("injection_observed"):
                    report_lines.append(
                        "  - \u26a0\ufe0f Possible prompt-injection / social-engineering "
                        "text detected in the input.")
                if adv.get("analyst_notes"):
                    report_lines.append(f"  - Notes: {adv['analyst_notes']}")
                for act in adv.get("recommended_actions", []):
                    report_lines.append(f"  - Action: {act}")
            report_lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    logging.info("Human-readable summary report saved to: %s", path)


def main():
    """Orchestrates setup, data loading, processing, optional AI enrichment, and saving."""
    manual_epilog = """
===============================================================================
 QUICK START MANUAL
===============================================================================
1. Install dependencies:
   pip install -r requirements.txt

2. Run the engine against an input file:
   python3 HunterEngine.py /path/to/your/input.txt

3. Use a custom configuration for different threat models:
   python3 HunterEngine.py emails.csv -c primitives/bec_financial_primitives.json

4. (Optional) Enable the AI advisory layer (advisory only, off by default):
   export HUNTER_AI_PROVIDER=anthropic
   export HUNTER_AI_MODEL=<your-model-string>
   export HUNTER_AI_API_KEY=<key>
   export HUNTER_AI_ALLOW_REMOTE=1     # required for any non-local endpoint
   python3 HunterEngine.py emails.csv

5. Find all generated reports, IoCs, and YARA rules in:
   ./HunterEngineBox/session_<timestamp>/
===============================================================================
"""
    parser = argparse.ArgumentParser(
        description="HunterEngine by PsypherLabs - A Heuristic Threat Enrichment Engine.",
        epilog=manual_epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("input", help="Path to the input file (.txt, .csv, .json).")
    parser.add_argument(
        "-c", "--config",
        default=DEFAULT_PRIMITIVES_CONFIG_FILE,
        help=f"Path to a custom configuration JSON file "
             f"(default: {DEFAULT_PRIMITIVES_CONFIG_FILE}).")
    parser.add_argument('--no-banner', action='store_true',
                        help='Suppress the startup banner and manual.')
    parser.add_argument('--no-ai', action='store_true',
                        help='Force-disable the optional AI advisory layer.')
    parser.add_argument('--ai-yara', action='store_true',
                        help='Opt-in: AI-draft YARA rules (compile-gated, written '
                             'to a separate _ai_yara_NEEDS_REVIEW.yara; never '
                             'merged into the deployable ruleset). Requires '
                             'yara-python and an AI provider in the environment.')
    args = parser.parse_args()

    if not args.no_banner:
        print_banner()
        print_manual_and_license()

    for log_file in [MISS_LOG, ERROR_LOG]:
        if os.path.exists(log_file):
            os.remove(log_file)

    engine = ThreatEnrichmentEngine(config_path=args.config)
    engine.setup_dependencies()

    inputs = load_inputs(args.input)
    results = engine.process_batch(inputs)

    # Optional, advisory-only AI enrichment. Disabled unless explicitly configured.
    if not args.no_ai:
        try:
            from ai_enrichment import AIAdvisor
            advisor = AIAdvisor.from_env()
            if advisor.enabled:
                logging.info("Running optional AI advisory layer (advisory only)...")
                advisor.annotate(results)
        except Exception as e:
            logging.warning("AI advisory layer unavailable (continuing): %s", e)

    # Opt-in AI-YARA drafting. Compile-gated; quarantine-only; never auto-deployed.
    ai_yara_rules, ai_yara_summary = None, None
    if args.ai_yara:
        try:
            from yara_ai import draft_ai_yara
            logging.info("Running optional AI-YARA drafting (compile-gated, "
                         "review-required)...")
            ai_yara_rules, ai_yara_summary = draft_ai_yara(results)
        except Exception as e:
            logging.warning("AI-YARA drafting unavailable (continuing): %s", e)

    save_results(results, ai_yara_rules=ai_yara_rules,
                 ai_yara_summary=ai_yara_summary)


if __name__ == "__main__":
    main()
