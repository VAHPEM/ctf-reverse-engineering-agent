# -*- coding: utf-8 -*-
"""Central config = every model/policy decision from the design sessions, in one
place. Change the Brain here; the loop code never hardcodes a model.

ONE-NODE by default: logic (decide/interpret) and coder (write scripts) point to
the SAME model. The split is a seam — flip CODER_MODEL to another vendor later,
only if measurement shows a real win.
"""
import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".env"))

# --- Brain model, two tiers (both must be capable; never a weak model deciding) ---
# Measured failure 2026-09-22: with .env missing/unreadable this silently fell back
# to a local 7B ollama model and the whole run LOOKED normal while being decided by a
# model that cannot do the job. Fail loudly instead; opt in explicitly for local dev.
_LOCAL_DEV_MODEL = "qwen2.5-coder:7b"
DEFAULT_MODEL = os.environ.get("BRAIN_MODEL", "")
if not DEFAULT_MODEL:
    if os.environ.get("ALLOW_LOCAL_BRAIN") == "1":
        DEFAULT_MODEL = _LOCAL_DEV_MODEL
    else:
        raise RuntimeError(
            "BRAIN_MODEL is not set - .env was not found or not loaded, so the Brain "
            "would silently fall back to a local 7B ollama model. Fix .env (it lives "
            "at the repo root, next to variant2_brain_muscle/), or set "
            "ALLOW_LOCAL_BRAIN=1 to accept the local model on purpose.")
TOP_MODEL     = os.environ.get("BRAIN_TOP_MODEL", DEFAULT_MODEL)    # escalation tier

# role -> {tier: model}. Same model for both roles today (1 node); the seam stays.
LOGIC_MODEL = {"default": DEFAULT_MODEL, "top": TOP_MODEL}
CODER_MODEL = {"default": DEFAULT_MODEL, "top": TOP_MODEL}

NUM_CTX = 16384

# --- Loop / budget policy ---
MAX_STEPS = int(os.environ.get("MAX_STEPS", 20))  # hard per-challenge step cap (budget guard); override per-run: MAX_STEPS=40 python3 -m agent.run <file>
STALL_THRESHOLD = 2            # 2 same-wall stalls (no new KNOWN) -> escalate, then stop
TOOL_ERROR_BUDGET = 3         # consecutive OPERATIONAL tool errors (frida syntax, file
                              # not found, wrong host, driver timeout, SSH/SFTP drop)
                              # allowed before acting. Separate from STALL_THRESHOLD:
                              # a tool that failed to do its job is NOT the Brain going
                              # in circles. Within budget: re-ask so the Brain fixes the
                              # call, no tier escalation, no stop. At budget: escalate
                              # default->top ONCE to repair the call; if already at top
                              # and errors persist past budget, stop (the tool is really
                              # broken, not the reasoning).
DEESCALATE_AFTER = 5           # consecutive PROGRESSED steps at top tier -> back to
                               # default. Escalation was one-way: once two stalls put
                               # the Brain on Opus it stayed there for the rest of the
                               # run, paying top-tier prices for steps the default tier
                               # had just shown it could do. Two fresh stalls re-escalate.
# Endgame push. MEASURED (ch7-run1, ch8-run13): both runs burned the whole 50-step
# budget WITHOUT a flag; the run state shows a streak of 8 consecutive read-only steps
# (read_file/peek/run_cmd/r2) that each surfaced a slightly different byte range, so
# absorb() scored them "novel", dead_end never incremented, and the stall detector never
# fired - the Brain kept RE-READING instead of writing the solver that closes the bai
# (2 author_and_run in 50 steps). NOT a stall (each step is technically new bytes) so
# escalation is the wrong lever; instead, after this many consecutive read-only steps
# that produced no new artifact, inject a one-shot nudge telling the Brain it likely has
# enough to write a solver or go dynamic. Does not escalate, does not count as a stall.
# 0 disables.
INSPECT_NUDGE_AFTER = int(os.environ.get("INSPECT_NUDGE_AFTER", 5))
# Run-start memory seed: how many technique notes matching the input's shape to put in
# the cached run context (tools.seed_recall). 0 disables.
SEED_RECALL = int(os.environ.get("SEED_RECALL", 8))
# Handoff notes given as INPUT (a *.md inside an _analysis/ folder, e.g. FINDINGS.md
# written by a previous run or a human) are pinned WHOLE into the cached run context
# when at most this many chars. MEASURED ch8 run 15: 13 of 60 steps re-read FINDINGS.md
# because each read aged out of the observation window. 0 disables.
PIN_DOCS_MAX_CHARS = int(os.environ.get("PIN_DOCS_MAX_CHARS", 16000))
# Pin small TEXT input files (source/config the Brain would otherwise peek/read over and
# over: popup.js, manifest.json, README, small .go/.py/.js ...) whole into the cached
# context, same mechanism as PRIOR NOTES. MEASURED ch8 crux: popup.js read 6x, popup.html
# 5x, manifest 3x in one 60-step run. Per-file char cap (0 disables); a hard count/total
# cap in the orchestrator keeps the big binary and 17KB Go glue out.
PIN_SMALL_FILES_MAX_CHARS = int(os.environ.get("PIN_SMALL_FILES_MAX_CHARS", 4000))
# Pin the TOP tier for the rest of the run at this escalation number. Escalating needs
# the default tier, so escalation #N always follows N-1 de-escalations:
#   1 = pin at once (tried 2026-09-25, rejected: opus cost + a pinned run stops at the
#       first top-tier double stall)
#   2 = pin after ONE de-escalation - the measured fix for the opus<->sonnet flip-flop
#       (~30 steps wasted on ch8/ch7, see pre-flareon13 notes). DEFAULT.
#   3 = pin after TWO de-escalations (allows one more flip-flop)
PIN_TOP_AFTER_ESCALATIONS = int(os.environ.get("PIN_TOP_AFTER_ESCALATIONS", 2))
# Same dynamic target retried: after this many win_frida calls whose scripts reference
# the same address, nudge toward offline emulation. MEASURED ch8 run 15: ~10 of 17
# win_frida steps went at the same two addresses. 0 disables.
DYN_REPEAT_NUDGE = int(os.environ.get("DYN_REPEAT_NUDGE", 3))

# --- Transient-API resilience (measured gap 2026-09-22: a single 529/network blip
#     killed the whole run, ledger and all, because nothing retried and nothing was
#     ever written to disk) ---
API_RETRIES = 4                # attempts per Brain call before giving up
API_BACKOFF = 4.0              # seconds; doubles each attempt (4, 8, 16, 32)
STATE_DUMP = os.environ.get("STATE_DUMP", "_run_state.json")  # ledger snapshot per step

# Hard spend ceiling for one run, in total billed tokens (input + output + cache).
# 0 disables it. The step cap alone does not bound cost: one author_and_run on a big
# binary sends far more than one peek, so 40 steps can mean very different bills. This
# stops CLEANLY at the ledger (which is dumped), instead of being noticed on an invoice.
MAX_RUN_TOKENS = int(os.environ.get("MAX_RUN_TOKENS", 0))

# Prompt-cache TTL for the cached system prefix. Empty (default) = Anthropic's standard
# 5-minute ephemeral cache, UNCHANGED. Set CACHE_TTL=1h to keep the ~5.9k-token cached
# prefix warm across SLOW steps (a >5min gap - an install up to 600s, a long job - would
# otherwise expire the 5-min cache and re-pay the write). Opt-in: only "5m"/"1h" are
# valid Anthropic values; a wrong value would make the API reject every call, so it is
# off by default and you turn it on per-run once you've confirmed your stack accepts it.
CACHE_TTL = os.environ.get("CACHE_TTL", "").strip()

# recall (tier-2 memory) contamination guard. When you BENCHMARK the agent on a
# challenge whose writeup is in the corpus, retrieving that writeup is cheating. Set
# RECALL_EXCLUDE to comma-separated substrings (matched against each note's `source`)
# to hide them, e.g. RECALL_EXCLUDE=flare-on,ch8 . Default empty (real unseen targets
# have no writeup here, so nothing is hidden).
RECALL_EXCLUDE = [x.strip().lower() for x in os.environ.get("RECALL_EXCLUDE", "").split(",") if x.strip()]

# Given to the Brain as a task fact (seeded into the ledger). It is the flag FORMAT
# only - no hint about where/how the flag is hidden.
FLAG_FORMAT_HINT = (
    "task: the flag has the form <text>@flare-on.com (FLARE-On). Only a string of that "
    "exact form counts as a solved flag; an echo of your own search pattern, random "
    "bytes, or a 'flag{...}' placeholder is NOT a flag."
)

# --- Progress accounting (A) + Brain notebook (B) ---
INFO_MIN_CHARS = 20     # a step is progress only if it shows >= this many chars of never-seen lines
# How much of a tool's output the Brain ACTUALLY SEES. Measured on the ch6 run
# 2026-09-23: read_file was asked for 12000 bytes, returned 12000, and observe()
# then cut it to 3500 - so ~8500 bytes per page were silently dropped while the
# Brain advanced its offset by the full 12000. It skipped two thirds of every file
# it paged, never knew, and kept re-reading to find what it had "already read".
# The newest observation is the one the next decision turns on, so it gets a real
# paging window; older ones stay small (they are context, not the subject).
OBS_CAP_NEWEST = 12000
OBS_CAP_OLDER = (1400, 700)
PAGE_MAX = 11000        # read_file/peek clamp `length` to this, so an offset never lies

# How long a line stays "already seen" for progress accounting. The Brain only ever
# holds 3 observations, so anything read earlier is gone from its context - yet
# ch6 run 3 scored steps 30/31/33 as stalls for re-reading exactly such evicted
# material, and that is what killed the run. Novelty is about what the Brain can still
# see, not about everything that ever crossed the wire.
# It must not be LONGER than the observation window, or the accounting punishes the
# Brain for re-reading what its own prompt already threw away: render_state shows the
# newest observation in full, the next two trimmed to 1400/700, and nothing older
# (keep=3). MEASURED ch8 run 1: with 8, material that left the context at step n+1 was
# still scored "already seen" at step n+7. 4 = the 3-observation window plus one step.
MEMORY_SPAN = 4

KNOWN_CAP = 70          # prompt-size guard on measured facts; seeded/pinned facts
                        # (task + environment + method) are NEVER trimmed
ASSUMED_CAP = 16        # keep the newest N Brain notes in the ledger (prompt-size guard)
RULED_OUT_CAP = 15      # keep the newest N ruled-out entries
# The ledger is the UNCACHED half of every step's prompt - it is re-sent, in full, on
# every single Brain call. MEASURED ch8 run 1 step 44: one failed ghidra_script put a
# 1800-character Java stack trace into RULED_OUT, and every later step paid for it
# again. A ruled-out line has one job: say what did not work. A measured fact can be
# longer, but not unbounded.
FACT_MAX_CHARS = 400        # cap on ONE KNOWN line
RULED_OUT_MAX_CHARS = 220   # cap on ONE RULED OUT line (single-lined)
NOTE_MAX_CHARS = 450    # was 240. ch6 run 3, the Brain's own note at step 28:
                        # "details of get_next/encrypt/_generate_primes_from_hash got
                        # trimmed from context". ASSUMED is the only place a finding
                        # survives past the 3-observation window, so it IS the working
                        # memory - and it was starved.

# General RE method hint (not tied to any one challenge). Learned from comparing run 6
# (ch4 UnholyDragon) against the official writeup: the Brain spent most of its budget on
# static Ghidra decompile of code that turned out to be VB6/twinBASIC runtime init (not
# the real logic), and never once tried just running the (fixed) binary on the Windows
# VM - which the official solution shows immediately reveals the compiler/runtime via a
# runtime error dialog ("twinBASIC Internal Error"), far cheaper than static analysis.
METHOD_HINT = (
    "method: work CHEAP-TO-EXPENSIVE, and MEASURE A FAILURE BEFORE RETRYING IT. Two "
    "halves, and the second matters as much as the first.\n"
    "  ORDER: (1) the cheap survey is already done for you - triage shows file type, "
    "sections with entropy, imports, first bytes and, for an executable, a radare2 "
    "survey; read it before doing anything. (2) TARGETED static reading: use imports, "
    "strings and cross-references to find the FEW functions that matter, then read "
    "those with the r2 TOOL (not run_cmd): r2(cmd=\"afl\") functions, "
    "r2(cmd=\"axt @ <addr>\") who-references-this, r2(cmd=\"pdf @ <addr>\") "
    "disassemble one function, r2(cmd=\"pdc @ <addr>\") quick pseudo-C, "
    "r2(cmd=\"px 64 @ <VIRTUAL addr>\") bytes at a virtual address, "
    "r2(cmd=\"izz~<word>\") strings. r2 turns colour off, runs `aaa` only when the "
    "command needs functions/xrefs (on one binary `aa` found 2 functions where `aaa` "
    "found 292), caches the analysis and scans output for the flag. For the hard "
    "functions, pe_overview()/decompile() (Ghidra, minutes each). (3) DYNAMIC when "
    "static cannot pin something down - a value computed at runtime, a key built at "
    "runtime, a buffer that exists only after unpacking, which branch is really taken: "
    "win_frida (Windows scriptable debugger), linux_gdb (Linux ELF scriptable "
    "debugger - ASLR off so a PIE's base is a fixed 0x555555554000, runs under Xvfb so "
    "a GUI/webkit app starts) or emulation.\n"
    "  KNOW WHEN TO LEAVE STATIC: when TWO cheap static looks at the SAME question come "
    "back empty - no such string; an xref that returns nothing; a decompile that is "
    "unreadable junk; r2 `aaa` finding far fewer functions than Ghidra so its xrefs are "
    "unreliable - that emptiness IS A MEASUREMENT, and what it measures is that the "
    "answer is built at RUNTIME or the call is indirect/obfuscated. Do NOT repeat the "
    "static look with a new regex or a bigger timeout (the single most common way this "
    "agent burns its budget): switch anchor (a different API the handler must call) or "
    "go dynamic. High .data entropy, or strings that don't appear in the file at all, "
    "are the same signal measured earlier. MEMORY FIRST: `recall(<situation in "
    "keywords>)` pulls the most relevant technique notes from past CTF experience ($0, "
    "instant, no VM). Call it EARLY - right after triage/the first decompile shows the "
    "target's shape (framework, language, packer, obfuscation, crypto, protocol), and "
    "BEFORE committing to a dynamic line of attack - not only once you are stuck; notes "
    "matching the input files are already under PAST EXPERIENCE. Reason with them, "
    "don't copy.\n"
    "  KNOW WHEN TO STOP OBSERVING AND SOLVE: dynamic analysis (hooks, drives, "
    "screenshots) exists to CONFIRM the check algorithm, not to leak every value "
    "forever. Once you can STATE the check - e.g. each input element is transformed "
    "then compared to a target, or accumulated into one value compared at the end - "
    "STOP hooking and re-reading and WRITE ONE author_and_run solver that recovers the "
    "answer. An OBFUSCATED primitive (an MBA / control-flow-flattened hash, a decoder) "
    "is NOT hand-translated from pseudocode: EMULATE the function as a black-box oracle "
    "(unicorn / flare-emu - feed it inputs, read outputs) or lift it, then INVERT it or "
    "constraint-solve (z3, or a direct search / subset-sum / meet-in-the-middle). "
    "Re-decompiling or re-disassembling something you already saved, or re-hooking the "
    "SAME address you already hooked, is NOT progress - if you already have the "
    "algorithm, the only next step that counts is the solver.\n"
    "  When you DO run a Windows GUI program use win_gui_run, NOT run_cmd/run_script: an "
    "SSH command lands in Windows SESSION 0 which has no interactive desktop, so a GUI "
    "started there paints where nobody can see and a MODAL dialog blocks the process "
    "until your timeout kills it ('produced no output'); win_gui_run runs it in session "
    "1 and hands back the window titles, the dialog text and a picture."
)

# General RE method hint (not tied to any one challenge). Learned from ch5 (ntfsm)
# runs 7/8/9: Brain repeatedly tried to find a program's real entry point by
# grepping a large Ghidra function list for "main" - in MSVC-compiled C/C++
# binaries there is almost never a function literally named "main" (confirmed by
# direct measurement on ntfsm.exe: decompiling invoke_main showed it calls exactly
# one non-library function, which was the program's real main - at the exact
# address the official writeup names). Grepping a 6000+-function list is also
# fragile (wrong path, SIGPIPE from an unseen pipe, or a pattern like "FUN_" that
# matches nearly every line since Ghidra names unlabeled functions that way).
FIND_MAIN_HINT = (
    "method: to find a C/C++ program's real entry point in an MSVC-compiled binary "
    "(the common case for Windows .exe challenges), don't grep a large function list "
    "for a function literally named \"main\" - MSVC binaries almost never have one. "
    "Instead locate invoke_main (a tiny CRT wrapper function Ghidra usually "
    "recognizes as a library function) and decompile() it directly - it calls "
    "exactly one non-library function, which is the program's actual main. This is "
    "far cheaper and more reliable than searching a large function-list file."
)

# Filled in at run start by tools.probe_environment() - a single $0 SSH round-trip that
# MEASURES the analysis VM instead of asserting things about it (the previous static
# version of this claimed "`pip install X` works", which is false here, and never
# mentioned the venv at all - so the Brain had no way to know that angr/capstone/xdis
# were already installed, or that anything it pip-installed would be invisible).
ENV_FACTS_FALLBACK = (
    "environment: could not probe the analysis VM at run start (it may be down). "
    "Assume nothing about what is installed - verify with run_cmd before relying on "
    "any tool or library."
)

MAX_OUTPUT_TOKENS = 12288  # cap Brain output for decide() (controller: JSON action).
# 8192 -> 12288 (2026-09-24): endgame decides hit 8192 (ch8/ch7 runs), truncating ->
# strict retry at 16000 = ~24k tokens for ONE action. 12288 lets the long reply finish
# in ONE generation (billed by tokens generated, so short actions still cost the same).
# Raised 4096 -> 8192 after ch6 run 5 (2026-09-23) DIED on it: in the endgame the
# controller packs measured analysis into the `note` field, the reply ran past 4096
# and was CUT OFF mid-JSON -> extract_json failed -> "no valid action" -> STOP, with
# the whole crypto scheme already reverse-engineered. Billed by tokens actually
# generated, so a short action still costs the same; only a genuinely long reply
# (exactly the one we must not truncate) costs more.
CONTROLLER_RETRY_MAX_TOKENS = 16000  # the strict retry after a truncated/invalid
# controller reply runs with THIS much room, so a reply that was cut off can actually
# finish the second time instead of hitting the same wall (the old strict retry kept
# 4096 and just re-truncated -> two strikes -> dead run).

# author_script() writes a full solver (e.g. FSM-extraction + BFS over a large jump
# table); measured 2026-09-22 (ch5 ntfsm, MAX_STEPS=40 run): a real solver script was
# cut off mid-statement at 4096 tokens ("SyntaxError: '(' was never closed"), and
# likely also explains repeated "produced NO output" runs where print() calls near
# the end of the script never got written. Anthropic bills by tokens actually
# generated, not by this cap, so raising it costs nothing unless truly needed.
CODER_MAX_OUTPUT_TOKENS = 24576  # 8192 -> 16384 -> 24576. Each raise was a MEASURED
# ceiling hit that cost a wasted author_and_run: ch5 ntfsm (2026-09-22) hit 8192 x3 on
# a jump-table extractor; ch6 run 6 (2026-09-23) hit 16384 on an end-to-end web3
# solver (step 43, cut off -> not run -> a whole step lost re-splitting). Anthropic
# bills by tokens actually generated, not this cap, so headroom is free unless used;
# a script that needs MORE than this is genuinely too big for one call and the muscle
# already tells the Brain to split it (author_and_run blocks a truncated script).


# What the analysis VM can do beyond python. The ENVIRONMENT FACTS entry gives the
# absolute paths (PATH has neither the venv's bin nor ~/tools); this says what each
# thing is FOR, which a path alone does not.
TOOLCHAIN_HINT = (
    "toolchain: beyond writing python solvers, the Kali box carries specialist tools "
    "- see ENVIRONMENT FACTS for their exact absolute paths, and run them with "
    "run_cmd (give installs and heavy analysis a big `timeout`):\n"
    "  * floss - FLARE's own obfuscated-string solver: recovers strings that plain "
    "`strings` cannot see because the binary builds or decrypts them at runtime "
    "(stack strings, tight-loop decoders). On a FLARE-On sample this is often the "
    "single highest-yield first command; `--only static` is the fast mode.\n"
    "  * capa - identifies a binary's CAPABILITIES (encrypts data, persists, injects, "
    "self-modifies...) by matching rules against disassembly. Cheap way to find out "
    "what a sample DOES before deciding what to decompile. It needs both -r rules and "
    "-s signatures.\n"
    "  * Ghidra via pe_overview/decompile (already wired as tools), radare2/rabin2, "
    "objdump, readelf, nm, binwalk, upx (`-d` to unpack), 7z, exiftool, tshark for "
    "pcap, yara, qemu-x86_64 for foreign-arch ELF, gdb, bulk_extractor.\n"
    "  * jadx - Java/Android: decompiles .jar/.apk/.dex to readable Java.\n"
    "  * pyinstxtractor.py - unpacks a PyInstaller-built executable (Windows .exe OR "
    "Linux ELF) into its .pyc files; run it with the solver interpreter. Then "
    "then DECOMPILE those .pyc with `~/tools/pycdc/pycdc <f.pyc> > src.py` (readable "
    "source, 3.9-3.12) and only fall back to `<venv>/bin/pydisasm <f.pyc> > out.txt` "
    "for the parts pycdc could not lift.\n"
    "  * python libs worth remembering: lief (parse AND rewrite PE/ELF - the clean way "
    "to repair a mangled header), pefile, angr + z3 (symbolic execution when a check "
    "is a constraint problem), unicorn (emulate a decoder routine instead of "
    "reimplementing it), capstone, scapy (pcap), yara, dnfile + dncil (.NET metadata "
    "and CIL - FLARE-On ships .NET often), oletools (Office macros), PIL + numpy "
    "(pixel/stego work), zxingcpp (QR/barcode), pymupdf (PDF), aplib + lznt1 + lz4 + zstandard (the compression formats packers actually use).\n"
    "Prefer an existing specialist tool over reimplementing it in a solver: it is one "
    "step instead of several, and its output is evidence rather than your own code's "
    "opinion."
)


# Learned from ch6 run 4 (2026-09-23): after decompiling the challenge the Brain spent
# TEN consecutive steps grepping the source and the bytecode for "flag", "flare-on",
# "secret", a long hex constant, a big integer - all of which returned nothing, because
# the flag was computed at runtime from data files shipped alongside the code. Each
# miss is cheap; the pattern of misses is what costs a run.
LITERAL_SEARCH_HINT = (
    "method: searching for the flag as a literal string or constant is worth ONE or "
    "TWO cheap attempts, no more. If `grep -i flag/flare-on/secret` and a scan for "
    "long hex/decimal constants both come back empty, that is a MEASUREMENT, and what "
    "it measures is that the flag is COMPUTED AT RUNTIME - so stop searching for it "
    "and start reconstructing the computation. Concretely, at that point: enumerate "
    "the NON-code files shipped with the challenge (a bundle, an archive, a resource "
    "section, the directory the binary was extracted into - filter out the library "
    "noise by size and extension), because a runtime-computed flag needs inputs and "
    "those inputs travel with it; and re-read the code for where it LOADS data rather "
    "than where it stores strings. Repeating a literal search with a slightly "
    "different regex after two empty results is the single most common way this agent "
    "burns a step budget."
)


# --- What the CONTROLLER is told on every step -------------------------------------
# Until 2026-09-22 these were seeded into the LEDGER, i.e. re-sent inside the dynamic
# user message on every single step (~5100 chars, never cacheable), while the
# controller's system prompt was ONE sentence - so the whole 27KB of SYSTEM_PROMPT +
# ANALYSIS_DISCIPLINE + METHOD_PLAYBOOK only ever reached the script-writer, and the
# controller (the thing that actually chooses actions) never saw the method rules at
# all. Moving them into a STABLE system prefix fixes both: the controller finally gets
# the discipline, and the prefix becomes an Anthropic cache prefix instead of fresh
# input tokens every step. Anything that varies per run (the measured ENVIRONMENT
# FACTS) must stay in the ledger, or it would break that cache.


# Merged 2026-09-23 (tier-1 rebuild) from AVOID_HUGE_DECOMPILE_HINT + DECOMPILE_ADDR_HINT
# + GHIDRA_SCRIPT_HINT + SPLIT_LARGE_SOLVER_HINT. Every measured fact preserved; the
# verbose originals are archived in technique_archive.md.
CODE_AT_SCALE_HINT = (
    "tool note - reading COMPILED CODE and handling BIG output:\n"
    "  * decompile() resolves a NAME or an ADDRESS to the function CONTAINING it, so a "
    "mid-function address returns that whole function. It fails 'function not found' "
    "only where Ghidra never made a function (jump-table case bodies, data regions) - "
    "that is about the binary, not your formatting, so re-asking 0x/FUN_/no-0x variants "
    "will not help; for code there, author_and_run with capstone (VA->file offset via "
    "the PE section headers, read the bytes, disassemble).\n"
    "  * A function that is one HUGE switch / jump table (hundreds+ cases): do NOT "
    "decompile() the whole thing - it times out or returns a wall of near-identical "
    "case blocks. Script it: read the table/case structure directly (capstone, or the "
    "raw bytes) and extract the small repeated per-case pattern as data.\n"
    "  * A WHOLE-BINARY question (how many functions look generated, which reference a "
    "constant, patch junk and re-decompile) is a ghidra_script, not dozens of "
    "decompile() calls; its bulk output MUST go to the getScriptArgs()[0] file - the "
    "Ghidra console drops lines under load.\n"
    "  * A solver that BOTH bulk-extracts a large table AND computes from it can exceed "
    "the coder output ceiling and get cut off mid-script (truncated -> syntax error, or "
    "silent no output). Split into TWO author_and_run calls: first extract to a file "
    "(JSON) with a print() confirming size/shape; then a second, smaller script loads it "
    "and computes."
)

# Merged 2026-09-23 (tier-1 rebuild) from DEBUGGER_HINT + GUI_ACT_HINT + SEEING_HINT +
# LONG_JOB_HINT into a compact capability MAP - each tool's own catalog entry carries the
# mechanics, this says WHEN to reach for it. Verbose originals in technique_archive.md.
CAPABILITIES_HINT = (
    "capability map (the tool's catalog entry has the mechanics; this is WHEN):\n"
    "  * SEE on Windows: win_windows FIRST - window titles plus the readable text inside "
    "a window (UI Automation), the whole answer for an error box or prompt at a few "
    "dozen tokens. Only if the meaning is truly VISUAL use win_screenshot / view_image "
    "(~1500-1900 tokens each, and an attached image is visible for ONE turn only - write "
    "what you saw into that turn's note). Pictures inside files: extract_images (PE "
    ".rsrc) or pdf_pages first, then view_image on the one that matters. Kali is "
    "headless - a Linux GUI needs linux_gui_run (Xvfb).\n"
    "  * DEBUG at runtime (Windows): win_frida runs a JS snippet inside the live process "
    "- 'what is this value at runtime' in one step. Reach for it when static reading "
    "stalls: a key built at runtime, a buffer that exists only after unpacking, an "
    "anti-debug branch to force. Hooks die when the call returns, so trigger the hooked "
    "code INSIDE the same call.\n"
    "  * DEBUG at runtime (Linux ELF): linux_gdb runs a gdb-python snippet against the "
    "target with ASLR off (PIE base fixed at 0x555555554000, so at(rva) maps an "
    "r2/Ghidra offset straight to a live address) and under Xvfb (so a GTK/webkit GUI "
    "actually starts). Same rule as win_frida: your hooks live only for that one call, "
    "so set the hook then run()/cont() so it fires inside the call. Reach for it the "
    "moment a Linux target's answer is built at runtime (a decrypted buffer, an "
    "overridden function, a value only live at one PC) instead of grinding static.\n"
    "  * DRIVE the Windows GUI: win_ui_tree lists live controls (read it, believe "
    "whichever layer is non-empty - UIA for Qt, W32 for WinForms), then win_ui_click / "
    "win_ui_type / win_ui_seq (a whole keypad in one step) / win_key (a keystroke to the "
    "foreground window, e.g. {ENTER} or {ESC} to dismiss a dialog). Start it with "
    "win_gui_run(kill=false) first.\n"
    "  * LONG work (thousands of files, a keyspace sweep, a long emulation) -> job_start, "
    "not a bigger timeout; check with job_poll(name, grep=...). A running job is not a "
    "stall - do something else that step."
)

# Trimmed 2026-09-23 (tier-1 rebuild): install MECHANICS kept here; the deep Python-
# bytecode / .pyc recovery block (xdis/pycdc/pydisasm) moved to technique_archive.md - it
# is only relevant on a PyInstaller/pyc challenge, i.e. tier-2 retrieval material.
INSTALL_ALLOWED_HINT = (
    "capability: you ARE allowed to install tools on the analysis VM when the task needs "
    "them (a python library, a disassembler, a specific interpreter). Measured facts "
    "about this Kali box:\n"
    "  * CHECK the ENVIRONMENT FACTS entry FIRST - it lists what the solver interpreter "
    "can already import; installing something already there is a wasted step.\n"
    "  * A bare `pip install X` FAILS (PEP-668 externally-managed). Install into the "
    "SOLVER's own interpreter: the `pip` next to it (path in ENVIRONMENT FACTS), e.g. "
    "`<venv>/bin/pip install capstone`. That venv ignores --user / --break-system-"
    "packages / apt python3-x, so those 'work' then fail with ImportError.\n"
    "  * `sudo` needs a password and there is no TTY - user-space installs only. The "
    "shell is NON-LOGIN (PATH lacks ~/.local/bin) so call user-installed binaries by "
    "FULL PATH. Installs are SLOW - pass a large timeout (180-600).\n"
    "  * apt has python 3.13/3.14/3.15 but NOT 3.12. For a pinned CPython: "
    "`curl -LsSf https://astral.sh/uv/install.sh | sh` then "
    "`~/.local/bin/uv python install <version>`, then pass "
    "`python=<abs path to that interpreter>` to author_and_run/run_script (without it "
    "the solver still runs under the default venv and the mismatch stands).\n"
    "  * Run installs through run_cmd/run_script (not hidden in a solver) and verify "
    "(import it, or -V) before relying on it. For version-locked .pyc / marshalled "
    "bytecode see the archived note. What stays refused is only security tampering "
    "(AV/firewall/services/registry/ACLs) and destructive disk/account commands."
)


MULTIFILE_HINT = (
    "the input is often a BUNDLE, not one file (a binary PLUS a pcap, a memory dump, a "
    "disk/firmware image, encrypted samples, a README). The ledger's `input artifacts` "
    "line lists EVERY input with its `file` type - read it and survey ALL of them "
    "(triage each) before deciding what matters; do not fixate on the first file. Think "
    "about how they RELATE: a binary usually explains a pcap/dump, a decryptor pairs "
    "with encrypted samples, firmware pairs with a disk image, a README/known-plaintext "
    "gives the crib. If an input is itself an archive/image, unpack it with extract. "
    "When an .exe ships with .dll files: they are all uploaded into the SAME samples/ "
    "dir (so the .exe finds them at launch) - but the real check is often inside a DLL, "
    "not the .exe (a thin launcher). Read the .exe's IMPORT table (pe_overview/r2) to see "
    "which DLL it loads, then analyze THAT DLL's exports."
)


STATIC_FACTS = [
    FLAG_FORMAT_HINT,
    METHOD_HINT,
    LITERAL_SEARCH_HINT,
    FIND_MAIN_HINT,
    CODE_AT_SCALE_HINT,
    CAPABILITIES_HINT,
    INSTALL_ALLOWED_HINT,
    TOOLCHAIN_HINT,
    MULTIFILE_HINT,
]

STATIC_FACTS_TEXT = (
    "=== STANDING TASK FACTS AND METHOD NOTES (they apply on EVERY step) ===\n"
    + "\n\n".join("- " + f for f in STATIC_FACTS)
)
