# Typosquatting Package Name Checker

**A real, no-mock-data supply-chain security scanner for dependency manifests — CLI + Web App.**
Real-parses `package.json` (npm) and `requirements.txt` (pip) files in a real project directory, then compares every REAL declared dependency name against a real, bundled, static list of popular npm/PyPI package names using a real Levenshtein edit-distance implementation and pattern checks — flagging typosquatted, homoglyph, and ambiguous-lookalike dependency names.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ DISCLAIMER (READ BEFORE USE)

This software is provided **strictly for educational, defensive-security, and supply-chain-hygiene purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Run this tool **only** against project directories and manifest files that you own or for which you have explicit, documented authorization to assess.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including missed detections, false positives, or downstream consequences of dependency decisions made using this tool's output — arising from the use, misuse, or inability to use this software.
- **Static bundled reference list — not a live registry feed.** The "popular package" list this tool compares against (`app/security_engine/__init__.py`) is a **fixed, offline snapshot** bundled at development time. This tool makes **no network calls** at scan time; it never queries npm, PyPI, or any live registry. The list is illustrative and not exhaustive or continuously updated — a package's absence from the list is not evidence it is safe, and the list may go stale as ecosystems evolve.
- **Not a certified audit.** This tool is **not a substitute** for a professional security review, a certified supply-chain audit, or a dedicated dependency-scanning service with live registry data (e.g. npm audit, pip-audit, Socket, Snyk). Findings are heuristic pattern matches and may include false positives and false negatives.
- **No guaranteed detection.** Absence of findings does **not** mean a project's dependencies are safe from typosquatting. This tool checks a specific, limited set of naming-pattern heuristics only, against a limited bundled name list.
- **Read-only by design.** The Security Engine only reads manifest file contents from disk — it never modifies `package.json`, `requirements.txt`, installs packages, or changes any file. Verify this yourself by reading `app/security_engine/__init__.py` before running it on anything important.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to scan a given project, **do not run this tool against it.**

---

## Who should use this project

- Developers and DevSecOps engineers who want a quick, scriptable pre-install check for suspicious dependency names in `package.json` / `requirements.txt`.
- Security students and self-learners studying software-supply-chain attack patterns (typosquatting, homoglyph substitution, dependency confusion).
- Teams that want a lightweight CI gate that flags obviously-mistyped dependency declarations before `npm install` / `pip install` ever runs.
- Anyone reviewing a new or unfamiliar codebase's dependency list for red flags.

## Why use this project

- **Real data only** — every result comes from real-parsed manifest file contents in the scanned project and a real Levenshtein edit-distance computation against a bundled name list. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Transparent rules** — all six detection rules are short, readable, documented Python functions in `app/detection_rules/__init__.py`. Nothing is a black box.
- **Two interfaces, one engine** — the CLI (for terminals/CI) and the web app (for dashboards/teams) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a scanner** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external API calls at scan time (the popular-package list is a static file, not a live feed).

---

## Architecture

```
typosquatting-package-name-checker/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Core engine: real manifest parsing + real Levenshtein distance + bundled popular-package list
│   ├── detection_rules/      # 6 documented detection rules (single-edit typo, separator swap, padding, homoglyph, ambiguity, no-manifest)
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user scan configuration
│   ├── database/             # SQLAlchemy models (SQLite)
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                 # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules
├── tests/                     # pytest suite — real temp manifests + synthetic rule-level tests
├── docs/                      # Additional documentation
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default path, depth, exclusions, alert threshold)

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| TPN-001 | Single-Edit-Distance Typosquat | High | Declared name is a real Levenshtein edit distance of exactly 1 from a popular package name (e.g. `flasks` vs `flask`) |
| TPN-002 | Separator-Substitution Typosquat | Medium | Declared name matches a popular name once hyphens/underscores/dots are stripped (e.g. `python_dateutil` vs `python-dateutil`) |
| TPN-003 | Suffix/Prefix Padding Typosquat | Medium | Declared name contains a popular name padded with extra characters (e.g. `reactjs2`, `django-official`) |
| TPN-004 | Homoglyph Digit-Substitution Typosquat | Low | Declared name normalizes (0→o, 1→l/i, 5→s, 3→e) to a popular package name (e.g. `n0de-fetch` vs `node-fetch`) |
| TPN-005 | Ambiguous Multi-Package Resemblance | Medium | Declared name is within edit distance 2 of **two or more** different popular packages — unclear intent, review manually |
| TPN-006 | No Dependency Manifest Found | Informational | No `package.json` or `requirements.txt` was found under the scanned directory — no names could be evaluated |

---

## Setup & Run

### Requirements
- Python 3.9+
- Works on any OS Python runs on (pure filesystem/text parsing, no OS-specific permission semantics)

### Install

```bash
git clone <this-repository-url>
cd typosquatting-package-name-checker
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
TPN_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                  # port to listen on
FLASK_DEBUG=1              # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/tpn.db`.

### Run the CLI

```bash
python3 cli/main.py scan /path/to/your/project --depth 4
python3 cli/main.py scan /path/to/your/project --json
python3 cli/main.py scan /path/to/your/project --csv findings.csv
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings are detected (useful as a CI gate) and `0` if the target is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

All 31 tests use either synthetic context dicts (for isolated rule-level checks) or real temporary directories with real `package.json`/`requirements.txt` files on disk (plus real Levenshtein-distance unit tests against known pairs) — nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Typosquatting Package Name Checker check?**
It real-parses `package.json` and `requirements.txt` manifests found in a real project directory, then compares each declared dependency name against a bundled static list of popular npm/PyPI package names using real Levenshtein edit distance, separator-substitution, suffix/prefix padding, and digit-homoglyph checks.

**Who should use it?**
Developers, DevSecOps engineers, and security students who want to catch typosquatted or look-alike dependency names in a project they own or are authorized to assess, before those dependencies are installed.

**Is it a replacement for a professional security audit or a live vulnerability scanner?**
No. It is an educational and productivity aid only, using a static bundled name list with no live registry queries — see the Disclaimer section above.

**Does it modify my files or install anything?**
No. It only reads manifest file contents from disk. It never writes to, deletes, or installs any package, and never calls out to npm/PyPI at scan time.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
