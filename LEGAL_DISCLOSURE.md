# Legal & Ethical Use Disclosure

## Legal Disclaimer
This tool is provided "AS IS" without any warranty of any kind. The authors and
contributors are not responsible for any misuse or damage caused by this program.
The use of this software is at your own risk. You are solely responsible for your
actions and for complying with all applicable laws in your jurisdiction.

## Ethical Use Policy
`HunterEngine` is a tool created for legitimate cybersecurity purposes. Its
intended use cases include:

- **Blue Teams:** Analyzing suspicious emails, messages, and logs to triage
  threats and build detections.
- **Threat Hunters:** Generating high-fidelity YARA rules to proactively hunt for
  threats in an environment.
- **Security Researchers:** Studying the language and indicators used in malicious
  campaigns.
- **Educational Purposes:** Training security professionals in threat analysis and
  detection engineering.

**Unauthorized and unethical use of this tool is strictly prohibited.** Do not use
this tool on any system or with any data for which you do not have explicit,
written permission. Misuse of this tool for malicious purposes may lead to legal
consequences.

## Data Handling Note
Inputs to this tool (suspected phishing/BEC/insider text) frequently contain
personal data. Treat the `HunterEngineBox/` output directory and the
`missed_inputs.log` / `failed_inputs.log` files as sensitive. The optional AI
advisory layer is **disabled by default** and will not transmit input to any
non-local endpoint unless `HUNTER_AI_ALLOW_REMOTE=1` is explicitly set. Enabling
remote/cloud AI sends input text to a third-party provider; confirm this is
authorized for your data before doing so.
