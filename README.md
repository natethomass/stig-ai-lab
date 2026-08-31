# STIG AI Hardening Lab

An AI-powered DISA STIG compliance and hardening tool for RHEL 10, built with **CrewAI** multi-agent architecture and a **local Ollama LLM** — fully offline, no cloud APIs required.

> **Resume Project** — Demonstrates: Linux hardening, DISA STIGs, OpenSCAP, AI agents, Ansible automation, Python

---

## What It Does

```
┌─────────────────────────────────────────────────────────┐
│                     STIG AI Lab Flow                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. Scanner Agent  → Runs OpenSCAP STIG scan on RHEL 10 │
│         ↓                                               │
│  2. Analyst Agent  → Explains findings in plain English │
│         ↓                                               │
│  3. ⚠️  USER APPROVAL GATE — review each finding        │
│         ↓                                               │
│  4. Remediation Agent → Generates Ansible playbook      │
│         ↓                                               │
│  5. Apply fix → Ansible runs the playbook               │
│         ↓                                               │
│  6. Compliance Agent → Validates fix, updates score     │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Target OS | RHEL 10 (free Developer Subscription) |
| AI Framework | CrewAI (multi-agent) |
| Local LLM | Ollama + LLaMA 3.1 / Mistral |
| Compliance Scanner | OpenSCAP + SCAP Security Guide |
| STIG Source | DISA STIG for RHEL 10 (via scap-security-guide) |
| Automation | Ansible |
| Language | Python 3.11+ |

---

## Architecture

```
stig-ai-lab/
├── agent.py                 # Main orchestrator & human-in-loop
├── agents/
│   ├── scanner_agent.py     # Runs & parses OpenSCAP scans
│   ├── analyst_agent.py     # Explains findings, assesses risk
│   ├── remediation_agent.py # Generates Ansible tasks
│   └── compliance_agent.py  # Validates fixes, tracks score
├── tools/
│   ├── scanner.py           # OpenSCAP wrapper & XCCDF parser
│   └── remediator.py        # Ansible playbook runner
├── playbooks/               # Generated Ansible playbooks (auto-created)
├── reports/                 # Scan results & compliance history
├── config/
├── scripts/
├── setup.sh                 # One-shot setup script
├── requirements.txt
└── .env.example
```

---

## The Four Agents

### 🔍 Scanner Agent
Runs `oscap xccdf eval` with the DISA STIG profile, parses the XCCDF results XML, and categorizes all failures as CAT I (High), CAT II (Medium), or CAT III (Low).

### 🧠 Analyst Agent
For each failed control, produces a plain-English explanation: what the control means, why it matters, what an attacker could do if it's left unfixed, and any known side effects of remediation.

### 🔧 Remediation Agent
Generates idempotent Ansible tasks using proper modules (`lineinfile`, `sysctl`, `service`, `file`, etc.) targeting RHEL 10. All tasks are written to disk as reviewable playbooks before execution.

### ✅ Compliance Agent
Tracks compliance score across scan iterations, identifies regressions, and generates executive-level summary reports. Maintains a history file so you can show score improvement over time.

---

## Prerequisites

- RHEL 10 VM (VirtualBox/VMware — minimum 2 vCPUs, 4GB RAM)
- Free [Red Hat Developer Subscription](https://developers.redhat.com/register)
- Internet access for initial setup (Ollama model download)
- Python 3.11+

---

## Quick Start

```bash
# 1. Clone and enter the project
git clone <your-repo> stig-ai-lab
cd stig-ai-lab

# 2. Run setup (installs all dependencies, pulls LLM model)
sudo bash setup.sh

# 3. Activate the virtual environment
source .venv/bin/activate

# 4. First — try a dry run (no changes made)
sudo python agent.py --dry-run

# 5. Full interactive hardening session
sudo python agent.py
```

---

## Usage

```bash
# Scan only — no remediation
sudo python agent.py --scan-only

# Full interactive mode (recommended)
sudo python agent.py

# Dry run — see proposed changes without applying
sudo python agent.py --dry-run

# Use a different AI model
sudo python agent.py --model mistral

# Resume from an existing scan result (saves time)
sudo python agent.py --results reports/scan_results_20240101_120000.xml
```

---

## Sample Terminal Output

```
╔══════════════════════════════════════════════╗
║       STIG AI Hardening Lab                  ║
║  Model: llama3.1  Profile: stig  Dry: False  ║
╚══════════════════════════════════════════════╝

[PHASE 1: Scanning]
Running OpenSCAP scan with profile: xccdf_org.ssgproject.content_profile_stig
✓ Scan complete

Compliance Score: 43.2%   Pass: 156 | Fail: 205

┌─ Failed STIG Controls (205 findings) ────────┐
│ #  Rule ID              Severity  Title       │
│ 1  V-257902             CAT I     SSH...      │
│ 2  V-257924             CAT I     Root...     │
│ ...                                           │
└──────────────────────────────────────────────┘

[PHASE 2: AI Triage Analysis]
AI Report: Top 5 critical findings...
  1. V-257902 — SSH protocol version...
  2. V-257924 — Root login must be disabled...

[PHASE 3: Interactive Remediation]

══════════════════════════════════════════
Finding 1/205  [CAT I]  V-257924
SSH root login must be disabled
──────────────────────────────────────────
╭─ AI Analysis ──────────────────────────╮
│ This control prevents attackers from   │
│ directly logging in as root via SSH... │
╰────────────────────────────────────────╯
╭─ Proposed Ansible Task ────────────────╮
│ - name: "V-257924 | Disable SSH root"  │
│   lineinfile:                          │
│     path: /etc/ssh/sshd_config         │
│     regexp: '^PermitRootLogin'         │
│     line: 'PermitRootLogin no'         │
│   become: true                         │
│   notify: restart sshd                 │
╰────────────────────────────────────────╯

Action [apply/skip/quit]:
```

---

## Configuration

Copy `.env.example` to `.env` and customize:

```bash
OLLAMA_MODEL=llama3.1         # or mistral, codellama, etc.
STIG_PROFILE=stig             # stig, cis, ospp, pci-dss
MIN_SEVERITY=CAT_II           # CAT_I, CAT_II, CAT_III, ALL
DRY_RUN=false
REQUIRE_APPROVAL=true
```

---

## Model Recommendations

| Model | Size | Notes |
|---|---|---|
| `llama3.1` | 8B | Best balance — recommended |
| `mistral` | 7B | Fast, good reasoning |
| `llama3.1:70b` | 70B | Best quality, needs 40GB+ VRAM |
| `codellama` | 13B | Good for Ansible generation |

---

## Resume Talking Points

- Built a multi-agent AI system using **CrewAI** with specialized agents for scanning, analysis, remediation, and compliance validation
- Integrated **DISA STIG** compliance scanning via **OpenSCAP** on RHEL 10
- Implemented **human-in-the-loop** approval gates ensuring no changes are applied without explicit user consent
- Used **local LLMs via Ollama** — fully air-gapped, no data leaves the system (relevant for government/DoD environments)
- Generated idempotent **Ansible playbooks** for all remediations with full audit trail
- Demonstrated measurable **compliance score improvement** from baseline to hardened state

---

## Recording / Streaming Theme

The [`obs/`](obs/) directory holds an OBS overlay pack for recording videos about this
project — starting-soon and break cards with countdowns, a topic bar that tracks the run,
lower thirds, a webcam frame, an outro with a before → after compliance score, and a
thumbnail template. Plain HTML with no CDNs or web fonts, so it runs on the same
air-gapped box as the lab.

It ships two brand layers: the **TechFitDad** channel identity (default) and the project's
own green, loaded with `?brand=stig`. Open `obs/index.html` to preview every scene and copy
its OBS Browser source URL. Setup notes are in [`obs/README.md`](obs/README.md).

---

## License

MIT — use freely for learning and portfolio purposes.
