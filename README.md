# ctf-brain — CTF Reverse-Engineering Agent

> Repository: [`ctf-reverse-engineering-agent`](https://github.com/<your-username>/ctf-reverse-engineering-agent)
> · project name: **ctf-brain**

**An autonomous agent that solves CTF reverse-engineering challenges.** It is built and
tuned specifically for RE puzzles (unpacking, decompiling, debugging, emulating, defeating
obfuscation) of the kind found in [FLARE-On](https://flare-on.com/). A single strong LLM
(the **Brain**) makes every decision and writes every script; a set of deterministic,
zero-cost tools (the **Muscle**) execute those decisions on real analysis VMs and return
raw output — they never interpret or conclude.

It has been tested and used in practice on:

- **FLARE-On 12** — solved challenges **1–8**
- **FLARE-On 13** — solved challenges **1–9**

> Research / education project. Operate it only on files you own or on published,
> authorized CTF puzzles, inside a private, network-isolated lab. Challenge binaries are
> **not** included in this repo.

---

## Table of contents

1. [How it works](#how-it-works)
2. [The two variants](#the-two-variants)
3. [The Muscle toolset](#the-muscle-toolset)
4. [The recall knowledge base](#the-recall-knowledge-base)
5. [Repository layout](#repository-layout)
6. [Getting started from zero](#getting-started-from-zero)
   - [Prerequisites](#1-prerequisites)
   - [Clone the repo](#2-clone-the-repo)
   - [Python dependencies](#3-python-dependencies)
   - [The analysis VMs (the Muscle)](#4-the-analysis-vms-the-muscle)
   - [AI models](#5-ai-models)
   - [The `.env` file (API keys & VM addresses)](#6-the-env-file-api-keys--vm-addresses)
   - [Flag detection per CTF](#7-flag-detection-per-ctf)
7. [Running it](#running-it)
8. [Design principles](#design-principles)
9. [License & scope](#license--scope)

---

## How it works

```
                 think → act → observe  (loop over a compressed Ledger)
   ┌──────────┐   decides everything,   ┌───────────────────────────────┐
   │  BRAIN   │   writes every script   │            MUSCLE             │
   │ (1 LLM)  │ ──────────────────────► │  ~29 deterministic tools, $0   │
   │          │ ◄────────────────────── │  run commands, return RAW out  │
   └──────────┘   raw tool output       └───────────────────────────────┘
                                              │ SSH (key auth)
                                   ┌──────────┴───────────┐
                                   ▼                      ▼
                           Kali Linux VM           Windows VM
                        (radare2, Ghidra,        (Frida, UI automation,
                         gdb, Xvfb, …)            x64 emulation, …)
```

- **Brain** — one strong model decides the next action, authors any command/script, reads
  the output, and updates its state. It reasons over a compressed **Ledger** of `KNOWN`
  (measured facts) / `ASSUMED` (unverified) / `RULED-OUT` (with evidence).
- **Muscle** — a dumb, deterministic executor. Each tool runs a command or a VM action and
  returns a raw, structured slice of output. **It never draws conclusions** — that is the
  Brain's job. This keeps the expensive model focused on reasoning and the cheap,
  reproducible work in code.
- **Guardrails** (all in code, $0): a hard per-challenge step budget; a *stall* detector
  (two consecutive steps with no new `KNOWN` ⇒ escalate to the stronger model, then **stop
  rather than guess**); a tool-error budget; and anti-loop nudges that stop the Brain
  re-reading the same bytes instead of writing the solver.
- **Two tiers, one seam** — a default model does the bulk of the work; on repeated stalls
  the run escalates to a stronger *top* model, then de-escalates on progress. Dispatch is
  by model-name prefix (`claude-*` → Anthropic, `gpt-*`/`o*` → OpenAI). **The Claude path
  is what has been tested in practice; the OpenAI path is implemented but not yet exercised
  end-to-end** (see `variant2_brain_muscle/smoke_openai.py` for a standalone check).

---

## The two variants

A deliberate cost-vs-capability trade-off:

| | **variant2** — 1 Brain + 1 Muscle | **variant1** — multi-node pipeline |
|---|---|---|
| Idea | one strong **API** model decides everything | fixed LangGraph of cheap/**local** models per role (triage → planner → coder → executor → evaluator) |
| Token cost | higher (a capable model does every step) | **lower** — cheap/local models, few or no API tokens |
| Hardware | light locally (reasoning is in the cloud) | **needs a strong machine** so the local model (the "muscle") is actually capable |
| Status | **active & proven** — FLARE-On 12 (1–8), FLARE-On 13 (1–9) | the original idea; **not yet well-refined**, kept for A/B comparison |

**`variant2_brain_muscle/` is the active design.** `variant1_multinode/` came first — it
trades API tokens for local compute, so it is cheaper to run but only as good as the local
model your hardware can host, and it has not yet been polished to the same level.

### variant1 workflow (multi-node pipeline)

variant1 is a fixed [LangGraph](https://github.com/langchain-ai/langgraph) state machine
where each role is a **separate node running a cheap/local model** (default
`qwen2.5-coder:7b` via ollama):

```
  ┌────────┐   ┌─────────┐   ┌───────┐   ┌──────────┐   ┌───────────┐
  │ triage │──►│ planner │──►│ coder │──►│ executor │──►│ evaluator │
  └────────┘   └─────────┘   └───────┘   └──────────┘   └─────┬─────┘
                    ▲             ▲            ▲              │
                    │             │  retry the code          │
                    │             └──────────────────────────┤
                    │        try another strategy            │
                    └────────────────────────────────────────┘
                         (loops until solved or budget spent)
```

- **triage** — survey the file (type, strings) on the Kali VM.
- **planner** — pick a strategy from a fixed menu; on a malformed reply it re-asks once,
  more strictly.
- **coder** — write the solver / command for the chosen strategy.
- **executor** — run it on the VM and capture the output.
- **evaluator** — scan for the flag, then route back to **coder** (fix the code) or
  **planner** (try another strategy) until the flag is found or the step budget is spent.

Each stage is one cheap model call, so a run costs far fewer tokens than variant2's single
strong model — but every stage is only as capable as the local model, which is why it
needs strong hardware and is less robust on hard challenges. Contrast this with variant2's
single [think → act → observe loop](#how-it-works), where one strong model plays every
role over a shared Ledger. Entry point: `variant1_multinode/graph_skeleton.py`
(see [Running it](#running-it)).

---

## The Muscle toolset

variant2 gives the Brain ~29 deterministic tools. All are $0 (no model calls), return raw
output, and never interpret.

**Recon / read**
- `triage` — first-look survey of an input (file type, sections, entropy, imports, strings).
- `peek` / `read_file` — read bytes / paged text of an artifact or a produced file.
- `run_cmd` — run one shell command on a VM (real timeout, exit code, new-file detection).
- `run_script` — run a whole Python/bash script the Brain wrote, on a VM.

**Solve**
- `author_and_run` — the Brain writes a solver; it runs and is forced to print every value.
- `check_flag` — scan text (or the last output) for the flag pattern.
- `extract` / `extract_images` — unpack archives / WIM, pull images out of PE resources.

**Vision**
- `view_image` — let the Brain actually see an image.
- `pdf_pages` — render PDF pages to images.

**Binary reverse-engineering**
- `pe_overview` — Ghidra full auto-analysis once; lists every function + imports.
- `decompile` — Ghidra decompiled C for one function (by name or address).
- `ghidra_script` — the Brain writes a custom Ghidra Java pass and it runs headless.
- `r2` — radare2, with the shell-out traps removed (functions, xrefs, disasm, strings).
- `recall` — search distilled RE technique notes from past CTFs (see next section).

**Windows dynamic / GUI** (over a second SSH session to the Windows VM)
- `win_frida` — scriptable debugger: the Brain writes Frida JS that runs inside the live
  process (breakpoints, read/patch memory, hook functions, drive a GUI).
- `win_windows`, `win_screenshot`, `win_gui_run` — inspect/see/run GUI programs.
- `win_ui_tree`, `win_ui_click`, `win_ui_type`, `win_key`, `win_ui_seq` — drive a GUI via
  UI Automation (list controls, click, type, key, click sequences).

**Linux dynamic / GUI**
- `linux_gdb` — scriptable gdb-python debugger; runs the target with ASLR off (fixed PIE
  base) under Xvfb so GUI / GTK / webkit binaries actually start.
- `linux_gui_run` — run a Linux GUI program under Xvfb and screenshot it.

**Long-running jobs**
- `job_start` / `job_poll` — start a long analysis in the background and poll it, so a slow
  job doesn't block the loop.

---

## The recall knowledge base

`recall` is the agent's **memory of how this *kind* of challenge is usually cracked** — a
corpus of short "situation → technique" notes distilled from many reverse-engineers' CTF
writeups (not challenge-specific solutions). It ships with ~155 notes under
`variant2_brain_muscle/knowledge/notes/`, tagged by situation (e.g. `qt-gui`,
`debug-disassembly`, `malware-c2`, `pcap-network`, `vm-obfuscation`, `firmware-uefi`). When
the Brain is stuck or a target feels familiar, it queries `recall("qt crackme per-keystroke
accumulator")` and gets back the few most relevant notes — it still decides and acts itself.

**Adding your own notes.** `scripts/ingest_writeups.py` turns a folder of writeup Markdown
into `recall` notes, chunked by heading, into `knowledge/writeups/` (git-ignored to keep
the repo lean). Run it where the writeup repos are cloned:

```bash
git clone --depth 1 https://github.com/pawlos/allthingsreversed.io /tmp/wr/allthingsreversed.io
cd variant2_brain_muscle && python3 scripts/ingest_writeups.py
```

> If you benchmark on a specific challenge, **exclude or distill** writeups of that same
> challenge to avoid contamination — the script's header explains which sources to treat as
> notes vs. as a regression test corpus.

---

## Repository layout

```
ctf-brain/
├── variant2_brain_muscle/       # ACTIVE agent
│   ├── agent/
│   │   ├── run.py               # entry point: python3 -m agent.run <file>
│   │   ├── orchestrator.py      # the think→act→observe loop, budget & escalation
│   │   ├── reasoner.py          # model dispatch, token accounting, Ledger
│   │   ├── tools.py             # the Muscle: every tool + flag detection (FLAG_RES)
│   │   ├── remote.py            # SSH/SFTP to the Kali & Windows VMs
│   │   └── config.py            # models, budgets, prompt facts, knobs
│   ├── prompts.py               # system prompt (lab/CTF context)
│   ├── ctf_playbook.py          # RE discipline the Brain reads
│   ├── knowledge/notes/         # distilled technique notes for `recall`
│   ├── scripts/ingest_writeups.py
│   └── technique_archive.md
├── variant1_multinode/          # legacy multi-role LangGraph prototype (local models)
│   └── graph_skeleton.py        # run: python3 graph_skeleton.py <file>
├── docker-x86/                  # x86 helper container
├── requirements.txt             # host (orchestrator) dependencies
├── requirements-vm.txt          # analysis-VM Python toolbox (install on Kali venv)
└── .env.example                 # copy to .env and fill in (never commit .env)
```

Not committed (see `.gitignore`): `.env`, `.ssh_keys/`, `challenges/`, VM `samples/`, run
logs, `knowledge/writeups/`, and other scratch.

---

## Getting started from zero

This section assumes you have never seen the repo before.

### 1. Prerequisites

- A **host machine** to run the orchestrator (macOS or Linux) with **Python 3.10+** and
  `git`. This machine does not need to be powerful for variant2 — the heavy reasoning is a
  cloud API call.
- **Two analysis VMs** the host can reach over SSH (a typical local setup uses a hypervisor
  on the same host, e.g. addresses like `192.168.64.5` / `192.168.64.10`):
  - a **Kali Linux VM** (Linux RE tooling), and
  - a **Windows VM** (for Windows binaries and GUI/Frida work).
  You can start with only Kali if you don't need Windows challenges.
- For **variant2**: an API key from Anthropic (and/or OpenAI).
- For **variant1** (or a local fallback): a machine strong enough to run a local LLM.

### 2. Clone the repo

```bash
git clone https://github.com/<your-username>/ctf-reverse-engineering-agent.git ctf-brain
cd ctf-brain
```

Cloning into a folder named `ctf-brain` keeps every path in this README (`ctf-brain/…`,
`/path/to/ctf-brain/requirements-vm.txt`) valid as written.

### 3. Python dependencies

Install on the **host** into a virtualenv:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

What they are for: `anthropic`, `openai` (Brain via API) · `paramiko` (SSH/SFTP to the VMs)
· `python-dotenv` (`.env` loading) · `py7zr` (7-zip archives) · `pillow`, `pymupdf` (image /
PDF handling for `view_image`, `pdf_pages`) · `ollama` (local-model client, variant1 /
fallback) · `langgraph` (variant1 only).

### 4. The analysis VMs (the Muscle)

The tools run **on the VMs**, not on the host, so the RE toolchain must be installed on
each VM. The agent probes what's available at startup and degrades gracefully if something
is missing — but the more you install, the more the Brain can do. You can start with only
Kali; the Windows VM is optional and only needed for Windows targets.

#### Kali VM — Linux targets

**System tools** (apt):

```bash
sudo apt update
sudo apt install -y \
    radare2 gdb binwalk binutils file p7zip-full \
    xvfb xdotool imagemagick \
    openjdk-21-jre-headless
```

- `radare2`, `gdb`, `binwalk`, `binutils` (`objdump`), `file`, `p7zip-full` (`7z`) —
  static RE, unpacking, archives.
- `xvfb` + `xdotool` + `imagemagick` — run and screenshot Linux GUIs, and back `linux_gdb`
  (GUI/webkit binaries start under a virtual display).
- `openjdk-21-jre-headless` — required to run Ghidra.

**Ghidra (headless)** — download a release, unzip, and put `analyzeHeadless` on the `PATH`
(the agent calls the bare command name):

```bash
# https://github.com/NationalSecurityAgency/ghidra/releases  (unzip anywhere)
echo 'export PATH="$HOME/ghidra/ghidra_11.4.2_PUBLIC/support:$PATH"' >> ~/.zshrc
source ~/.zshrc
analyzeHeadless        # should print usage, not "command not found"
```

**Python analysis venv** — the Brain's solver scripts import a large RE toolbox (capstone,
unicorn, angr, z3, pefile, lief, pwntools, pycryptodome, uncompyle6, scapy, capa, floss, …).
Create the venv at the path the agent expects and install [`requirements-vm.txt`](requirements-vm.txt):

```bash
python3 -m venv ~/ctf-venv
~/ctf-venv/bin/pip install -r /path/to/ctf-brain/requirements-vm.txt
```

The default interpreter is `~/ctf-venv/bin/python3`; if you put the venv elsewhere, set
`KALI_PYTHON` in `.env`.

#### Windows VM — Windows targets (optional)

Needed only for Windows binaries / GUI challenges (the `win_*` tools). Install Python and
Frida; UI automation (`win_ui_*`) uses built-in PowerShell, so nothing else is required:

```powershell
pip install frida frida-tools
```

The agent invokes Python at
`C:\Users\<you>\AppData\Local\Programs\Python\Python3xx\python.exe` by default — set
`WIN_PYTHON_EXE` in `.env` to match your actual install path.

#### SSH access (the repo ships NO keys)

The repository contains **no credentials of any kind.** You generate your own key, keep the
**private** half in `.ssh_keys/` (which is git-ignored and is never committed or printed),
and install the **public** half on each VM:

```bash
ssh-keygen -t ed25519 -f .ssh_keys/ctf_orchestrator_ed25519 -N ""
ssh-copy-id -i .ssh_keys/ctf_orchestrator_ed25519.pub <user>@<kali-ip>
ssh-copy-id -i .ssh_keys/ctf_orchestrator_ed25519.pub <user>@<win-ip>   # only if using Windows
```

### 5. AI models

**variant2 (recommended) — cloud API, no local model needed.** Put an API key in `.env`
(next step) and set the model ids. Dispatch is by name prefix: a `claude-*` id routes to
Anthropic, a `gpt-*`/`o*` id routes to OpenAI. **Only the Claude path has been tested in
practice**; the OpenAI path is implemented but not yet run end-to-end (verify it in
isolation with `python3 smoke_openai.py` from `variant2_brain_muscle/`). You choose two
tiers:

```dotenv
BRAIN_MODEL=claude-sonnet-...        # default tier — does most steps
BRAIN_TOP_MODEL=claude-opus-...      # escalation tier — harder steps / stalls
```

**variant1 (or a local fallback) — a local model via [ollama](https://ollama.com).** Install
ollama on a strong machine, pull a code model, and run the server:

```bash
# on the machine that will host the model:
ollama pull qwen2.5-coder:7b          # the model variant1 uses by default
ollama serve                          # exposes http://<that-host>:11434
```

Point the agent at it with `OLLAMA_HOST=http://<that-host>:11434` when you run variant1.
(To change variant1's model, edit `MODEL` in `variant1_multinode/graph_skeleton.py`.) If
`BRAIN_MODEL` is unset, variant2 refuses to silently fall back to a local model unless you
opt in with `ALLOW_LOCAL_BRAIN=1`.

### 6. The `.env` file (API keys & VM addresses)

Copy the template and fill it in. `.env` lives at the **repo root** (next to
`variant2_brain_muscle/`) and is git-ignored — **never commit it.**

```bash
cp .env.example .env
$EDITOR .env
```

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Brain via Claude API (`claude-*` models) |
| `OPENAI_API_KEY` | Brain via OpenAI API (`gpt-*` models) — optional |
| `BRAIN_MODEL` | default-tier model id |
| `BRAIN_TOP_MODEL` | escalation-tier model id |
| `KALI_HOST`, `KALI_USER` | Kali VM address and SSH user |
| `WIN_HOST`, `WIN_USER` | Windows VM address and SSH user |
| `KALI_PYTHON` | *(optional)* Kali venv interpreter — default `~/ctf-venv/bin/python3` |
| `WIN_PYTHON_EXE` | *(optional)* Windows `python.exe` full path |

Get an Anthropic key at <https://console.anthropic.com/> (an OpenAI key at
<https://platform.openai.com/>). Keep keys out of the code and out of git — the API key is
read only from `.env` at runtime.

### 7. Flag detection per CTF

The agent decides "solved" when a tool's output matches a **flag pattern**. Patterns live in
one place — the `FLAG_RES` list in `variant2_brain_muscle/agent/tools.py`:

```python
# FLARE-On flags are always <text>@flare-on.com
FLAG_RES = [
    re.compile(r"[A-Za-z0-9_.\-+]{4,}@flare-on\.com"),
]
```

**To target a different CTF, edit this list.** Examples:

```python
FLAG_RES = [
    re.compile(r"[A-Za-z0-9_.\-+]{4,}@flare-on\.com"),   # FLARE-On
    re.compile(r"flag\{[^}]{1,200}\}"),                  # generic flag{...}
    re.compile(r"CTF\{[^}]{1,200}\}"),                   # e.g. picoCTF-style
    re.compile(r"HTB\{[^}]{1,200}\}"),                   # Hack The Box
]
```

`_find_flag` returns the **first non-placeholder** match, so a decoy like `flag@flare-on.com`
or `flag{...}` template earlier in the output won't mask the real flag later. Obvious
placeholders (`flag`, `example`, `xxxx`, `____`, …) are rejected automatically via the
`_FLAG_PLACEHOLDERS` set — extend it if your CTF has its own template strings. Keep patterns
**specific** (a delimiter or domain), not a bare `\{.*\}`, so binary noise isn't mistaken for
a flag.

---

## Running it

**variant2** (from its folder):

```bash
cd variant2_brain_muscle
source ../.venv/bin/activate
python3 -m agent.run ../challenges/09_neonoutrun
```

- Input is a **file or a directory** (a directory's files are all ingested).
- Raise the step budget for a run: `MAX_STEPS=40 python3 -m agent.run <path>`
- Resume a previous run: `python3 -m agent.run <path> --resume [state.json]`
- On finish it prints the flag (or `not found`) and a full token-usage breakdown.

**variant1** (cheaper, local model):

```bash
cd variant1_multinode
OLLAMA_HOST=http://<model-host>:11434 python3 graph_skeleton.py <path-to-file>
```

### Useful environment knobs (variant2)

| Variable | Default | Effect |
|---|---|---|
| `MAX_STEPS` | `20` | hard per-challenge step cap |
| `MAX_RUN_TOKENS` | `0` (off) | optional token budget |
| `SEED_RECALL` | — | pre-seed `recall` notes from the input's shape |
| `PIN_SMALL_FILES_MAX_CHARS` | `4000` | pin small input files into context to stop re-reads |
| `INSPECT_NUDGE_AFTER` | `5` | nudge toward writing a solver after N read-only steps |
| `ALLOW_LOCAL_BRAIN` | — | accept a local ollama Brain when `BRAIN_MODEL` is unset |

(See `agent/config.py` for the full list.)

---

## Design principles

- **Measure, don't assume.** A conclusion is only `KNOWN` once a tool measured it;
  everything else is `ASSUMED` until verified.
- **Emptiness is a measurement.** Two cheap static looks at the same question coming back
  empty means the answer is built at runtime or the call is obfuscated — switch to dynamic
  analysis instead of repeating the search with a bigger regex.
- **Stop rather than guess.** At the top tier with no progress, the run stops for a human
  instead of emitting a plausible-looking wrong flag.
- **Change one thing at a time**, and verify each fix on a real run before the next.

---

## License & scope

For security research and education. Use it only against binaries you are authorized to
analyze (your own, or published CTF challenges intended to be solved). Challenge binaries
are **not** included in this repository.
