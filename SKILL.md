---
name: selectinfo-scan
description: Run and explain the domain and IP scanning workflows in this repository. Use when working with `scan.py`, `main.py`, or the SelectInfo scan pipeline; choosing presets and flags; interpreting reverse-IP, port-scan, web-fingerprint, and directory-scan results; or guiding setup when required tools are missing or broken.
---

# SelectInfo Scan

Use this skill when working in this repository so the existing CLI, setup flow, reports, and scan-stage boundaries stay consistent.

## Scope

This repository focuses on CLI-driven scanning plus JSON / XLSX outputs. Prefer extending the existing pipeline instead of adding parallel entrypoints or one-off scripts.

This skill should help the agent do three things well:

- guide the human operator toward the right scan path
- guide the human operator through tool installation and verification when needed
- explain normal empty results versus actual runtime or dependency failures

Current scan stages are:

- subdomain discovery for domain targets
- direct-IP seed workflow for IP targets
- reverse-IP enrichment for IP targets
- port scan
- web fingerprint
- directory scan
- JSON result persistence
- XLSX summary reports

## Repo Map

- `scan.py`: non-interactive entrypoint
- `main.py`: interactive entrypoint
- `requirements.txt`: unified Python dependency entrypoint
- `scripts/install_linux.sh`: one-shot Linux bootstrap script
- `core/subdomain_scanner.py`: target-type branching and subdomain scan coordination
- `core/reverse_ip_scanner.py`: PTR + TLS-certificate reverse-IP enrichment
- `core/scan_workflow.py`: port scan, reverse-IP, web fingerprint, directory scan helpers
- `core/batch_scan.py`: batch execution and summary aggregation
- `core/human_reports.py`: XLSX report generation
- `tools/self_check.py`: canonical local tool install and usability verification
- `tools/setup_manager.py`: local tool path configuration helpers
- `tests/test_scan_entrypoint.py`: CLI and scan flow coverage
- `tests/test_main_entrypoint.py`: interactive/background command coverage
- `tests/test_reverse_ip_scanner.py`: reverse-IP behavior coverage
- `tests/test_human_reports.py`: report coverage
- `tests/test_tool_wrappers.py`: wrapper behavior and regression coverage

## Tool Installation Guidance

This skill should actively guide the agent through tool setup, not just tell the user to install tools vaguely.

Before recommending scan commands that depend on external tools, follow this order:

1. Install Python dependencies:

       python -m pip install -r requirements.txt

2. Verify local tool availability:

       python tools/self_check.py

3. If the environment is Linux and this is first-time deployment, prefer:

       bash scripts/install_linux.sh

4. If a tool is installed but not detected, guide the user to update `config/local_settings.json` or use the interactive setup path in `main.py`

The agent should treat tool setup as part of the normal workflow in this repository, not as a separate topic.

### Required vs Optional Tools

- `nmap`: required for port scan and most service follow-up
- `subfinder`: used for domain subdomain discovery
- `oneforall`: used for fuller domain subdomain discovery
- `dirsearch`: optional, only needed for directory scan

If `dirsearch` is unavailable, continue to recommend workflows without `--directory-scan` instead of blocking the whole task.

### Installation Decision Rules

- If the user says the project cannot run, tool missing, scan has no output, or help me install, check installation first before changing scan parameters.
- If `python tools/self_check.py` reports `MISSING` or `BROKEN`, explain the smallest next fix for that specific tool.
- If the user only wants a quick domain or IP scan and the required tools are already usable, do not derail into full environment setup.

### Per-Tool Guidance

For `nmap`:

- Windows: ensure `nmap.exe` is in `PATH`, or configure its path locally
- Linux: install with the system package manager, typically `sudo apt install nmap`
- On Linux, if `-sS` is used without `root` or `CAP_NET_RAW/CAP_NET_ADMIN`, explain that `-sT` is the safer fallback

For `subfinder`:

- Default expected path is `tools/subfinder/subfinder.exe` on Windows or `tools/subfinder/subfinder` on Linux/macOS
- If the binary exists but is not executable on Linux, recommend:

       chmod +x tools/subfinder/subfinder

- If execution still fails, mention the possibility of a `noexec` mount

For `oneforall`:

- Default expected path is `tools/oneforall/oneforall.py`
- Python dependencies come from the repo root `requirements.txt`
- If self-check reports a sqlite issue, explain that the environment needs a working `sqlite3`, and that the project may fall back to `pysqlite3-binary` when available

For `dirsearch`:

- Treat it as optional
- Default expected path is `tools/dirsearch/dirsearch.py`
- If missing, guide the user to configure the path manually rather than implying the entire project is broken

### How the Agent Should Respond

When the environment is not ready, prefer concrete setup guidance like:

- "先执行 `python -m pip install -r requirements.txt`"
- "再执行 `python tools/self_check.py` 看是哪一个工具不可用"
- "如果是 Linux 首次部署，优先跑 `bash scripts/install_linux.sh`"
- "如果只是 `dirsearch` 缺失，可以先不加 `--directory-scan`"

Avoid vague advice like "check your environment" or "install dependencies" without naming the exact next command.

## Mode Selection

Use `scan.py` by default:

    python scan.py example.com --preset standard --port-scan --web-fingerprint
    python scan.py 1.1.1.1 --port-scan --web-fingerprint
    python scan.py 1.1.1.1 --port-scan --no-reverse-ip
    python scan.py --targets-file targets.txt --preset quick --background

Use `main.py` only when the user explicitly wants interactive prompts:

    python main.py

Choose modes this way:

- Use `scan.py` when the user already knows the target and wants a reproducible command.
- Use `main.py` when the user says they want to be guided step by step, is unsure which stages to enable, or wants an interactive walk-through.
- If the user sounds uncertain, recommend one concrete command first instead of listing every possible flag.

## Interaction Guidance

Guide the user toward the smallest command that answers their real question.

Preferred interaction pattern:

1. Identify whether the user wants to:
   - run a new scan
   - understand the workflow
   - debug an empty or suspicious result
   - compare domain and IP behavior
   - install or repair the environment
2. If the request is underspecified, ask at most one or two high-signal questions.
3. Prefer practical clarifications such as:
   - domain or IP?
   - quick inventory or deeper follow-up?
   - single target or batch?
   - are you blocked on setup, or already able to run scans?
4. After clarifying, give one recommended command first.
5. Explain optional flags only after the main command is clear.

Default communication behavior:

- Prefer Chinese unless the user explicitly asks for another language.
- Keep explanations aligned to the pipeline order.
- When the user says “带我一步一步来”, actively steer them through choices instead of only describing flags.
- When the user seems unsure, explicitly suggest `python main.py` as the guided path.

## Operator Recipes

Map fuzzy user intents into concrete scan plans.

If the user wants a quick first look at a domain:

    python scan.py example.com --preset quick

If the user wants to know what services are exposed:

    python scan.py example.com --preset standard --port-scan --web-fingerprint

If the user wants to dig web paths:

    python scan.py example.com --preset standard --port-scan --web-fingerprint --directory-scan

If the user gives an IP and wants the fullest built-in path:

    python scan.py 1.1.1.1 --port-scan --web-fingerprint

If the user wants to reduce reverse-IP noise for an IP:

    python scan.py 1.1.1.1 --port-scan --no-reverse-ip

If the user wants guided operation:

    python main.py

## Best-Effect Guidance

To get the best results, steer the user to make these decisions explicitly:

- domain or IP target
- whether they want only discovery, or also service and path follow-up
- whether they want a quick pass (`quick`) or fuller coverage (`standard` / `deep`)
- whether they are debugging one target or running a batch

Use these heuristics:

- Start with `quick` when the user is exploring or validating the environment.
- Use `standard` for most normal scan tasks.
- Use `deep` only when the user explicitly wants more coverage and accepts slower runs.
- Add `--directory-scan` only when web targets matter; do not enable it by default for every request.
- For IP input, mention that reverse-IP is enabled by default so the user understands where extra domain candidates came from.

## Domain Workflow

When the target is a domain:

1. Normalize the target as a domain.
2. Select subdomain tools from the preset unless the user explicitly passes `--tools`.
3. Run subdomain enumeration.
4. Run wildcard detection unless `--skip-wildcard` is set.
5. Run DNS validation unless `--skip-validation` is set.
6. If enabled, continue with port scan, web fingerprint, and directory scan.

Important notes:

- `--serial` only changes whether subdomain tools run in parallel.
- Do not add `--skip-wildcard` or `--skip-validation` casually; treat them as expert or debug flags.

## IP Workflow

When the target is an IP:

1. Do not run `subfinder` or `oneforall`.
2. Seed the scan result directly with the IP target.
3. Reverse-IP is enabled by default unless the user passes `--no-reverse-ip`.
4. If enabled, run reverse-IP enrichment after the initial result and after port scan input is available.
5. Continue with port scan, web fingerprint, and directory scan when requested.

Current reverse-IP scope is intentionally narrow:

- PTR records
- TLS certificate hostnames on configured TLS ports
- validation of whether candidate hostnames currently resolve back to the target IP

Do not describe this as passive DNS, historical reverse-IP, or a third-party asset database unless that feature is actually added.

## Stage Meanings

- Port scan:
  - operates on discovered IPs
  - answers which ports are open
- Web fingerprint:
  - operates on `IP:port` candidates from the port scan
  - identifies web services and maps them back to discovered domains or URLs
- Directory scan:
  - operates on web target URLs, not raw ports
  - if one IP maps to multiple domains already present in the target list, it scans each URL separately

## Empty Result Guidance

Treat these as normal no-signal outcomes unless logs show an execution error:

- reverse-IP returns zero candidates because there is no PTR and no usable certificate hostname
- port scan returns no open ports
- web fingerprint finds no web services on scanned ports
- directory scan finds no interesting paths

Treat these as likely runtime or dependency issues:

- tool unavailable
- timeout
- non-zero return code
- malformed output

When the user asks “是不是有问题”, answer in two layers:

1. say whether the result is logically consistent with the current stage behavior
2. give the next smallest verification step to confirm it

Examples:

- Reverse-IP returned nothing for an IP:
  - explain that this can be normal when there is no PTR record and no usable TLS certificate hostname
  - suggest verifying with:

        python scan.py 1.1.1.1 --port-scan --web-fingerprint

- Port scan returned no open ports:
  - explain that the scan may still have run correctly but found no open ports under the chosen arguments
  - suggest checking whether `nmap` itself is healthy with:

        python tools/self_check.py

- Directory scan was skipped:
  - explain whether `dirsearch` is unavailable or whether no web targets were identified upstream
  - if the user wants directory scan, suggest fixing `dirsearch` first or rerunning with a target known to host web services

## Installation Troubleshooting

When the user is blocked on setup, prefer the smallest concrete next step instead of a long checklist.

Recommended order:

1. Install Python dependencies:

       python -m pip install -r requirements.txt

2. Run tool verification:

       python tools/self_check.py

3. If Linux first-time deployment:

       bash scripts/install_linux.sh

4. Only then move on to path overrides or scan-parameter changes

Use these heuristics:

- If `nmap` is missing, solve that before debugging `--port-scan` behavior.
- If `subfinder` or `oneforall` is missing, domain scans may still partially work depending on available tools, but the user should be told coverage is reduced.
- If only `dirsearch` is missing, do not frame the whole install as broken.
- If `config/local_settings.json` contains stale paths from another machine, suggest deleting it or updating only the incorrect tool path entries.

## Recommended Response Patterns

Use short, direct guidance that produces action.

Preferred pattern when setup is not ready:

1. Name the blocker clearly.
2. Give exactly one recommended next command.
3. Explain what that command will confirm or fix.
4. Only then mention the second step.

Good examples:

- First run `python -m pip install -r requirements.txt` to install the repo and bundled tool dependencies.
- Then run `python tools/self_check.py` so we can see which tool is unavailable.
- If this is first-time Linux deployment, prefer `bash scripts/install_linux.sh` because it installs system packages, Python dependencies, and runs self-check.
- If only `dirsearch` is missing, continue without `--directory-scan` for now.

Avoid:

- vague advice like `check your environment`
- suggesting many equivalent commands at once without a recommendation
- treating an empty result as a bug before verifying tool health

## Command Recommendation Templates

Prefer one concrete command first, then optional follow-ups.

For first-time environment setup:

    python -m pip install -r requirements.txt
    python tools/self_check.py

For first-time Linux deployment:

    bash scripts/install_linux.sh

For a quick domain smoke test after setup:

    python scan.py example.com --preset quick

For a normal domain scan with service follow-up:

    python scan.py example.com --preset standard --port-scan --web-fingerprint

For a normal IP scan:

    python scan.py 1.1.1.1 --port-scan --web-fingerprint

For guided local setup and scanning:

    python main.py

## Maintenance Notes

When modifying this repository, preserve these operational assumptions:

- `requirements.txt` remains the single Python dependency entrypoint
- `tools/self_check.py` remains the canonical tool verification command
- `scripts/install_linux.sh` remains the preferred first-time Linux bootstrap path
- `runtime/` stores runtime state only and should not become a tracked source directory
- `config/local_settings.json` is host-local and should not be treated as a shared project config

If future changes alter install paths, tool names, or setup flow, update this skill together with the README and any relevant tests.
