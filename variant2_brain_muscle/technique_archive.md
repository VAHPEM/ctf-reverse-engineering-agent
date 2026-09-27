# CTF-brain technique archive — TIER-2 SEED (2026-09-23)
#
# This file is NOT imported and NOT sent to the Brain every step. It is the holding
# place for knowledge that is real and hard-won but too SPECIFIC / rarely-relevant to
# justify a slot in the always-on prompt (tier 1 = config.STATIC_FACTS + the playbook).
#
# The plan: build a `recall(query)` muscle tool that indexes these notes and returns the
# 2-3 relevant ones ON DEMAND when the situation matches — so the Brain can carry a large
# memory without bloating the every-step prompt. Until that tool exists, nothing here
# reaches the Brain; it is preserved verbatim so no measured lesson is lost.
#
# ============================================================================
# PART A — hints moved out of config.STATIC_FACTS during the 2026-09-23 tier-1 rebuild
#          (verbatim originals; their general parts were merged into the tier-1
#           CODE_AT_SCALE_HINT / CAPABILITIES_HINT / INSTALL_ALLOWED_HINT).
# ============================================================================

STRATEGY_HINT = (
    "task: if a binary mutates ITSELF one step at a time (e.g. it writes out a new "
    "copy with an incremented number each time you run it), do not assume running it "
    "further will reveal the flag - the intended direction is often the REVERSE of "
    "the observed one, and reversing usually requires understanding the generation "
    "algorithm (read the code / decompile), not running the program more."
)


AVOID_HUGE_DECOMPILE_HINT = (
    "method: if analysis shows one function contains a very large switch statement or "
    "jump table (hundreds+ cases), avoid calling decompile() on that whole function - "
    "full pseudocode generation for something that size can time out, or even if it "
    "succeeds, produce a wall of thousands of near-duplicate case blocks that's too "
    "large to read productively. Prefer author_and_run: write a small script that "
    "reads the jump table / case structure directly (a disassembly library, or "
    "parsing the raw bytes) and extracts the small repeated per-case pattern as "
    "structured data - that's usually far cheaper and more useful than prose C."
)


DECOMPILE_ADDR_HINT = (
    "tool note: decompile() resolves a name, or an address, to the function that "
    "CONTAINS that address - so an address pointing into the middle of a known "
    "function works fine and returns that whole function. It fails with \"function "
    "not found\" only when Ghidra's analysis never created a function covering that "
    "address at all - typical for jump-table case bodies, a shared continuation block "
    "next to a jump table, or data-ish regions. That failure is about the binary's "
    "analysis, not your formatting, so re-asking with 0x/no-0x/FUN_ variants of the "
    "same address will not help. For code at such an address, use author_and_run with "
    "a disassembly library (capstone): convert VA -> file offset via the PE section "
    "headers, read the bytes, disassemble from there."
)


GHIDRA_SCRIPT_HINT = (
    "method: when a question is about the WHOLE binary rather than one function - how "
    "many functions look machine-generated, which ones reference this constant, what "
    "does the call graph around here look like, patch these junk blocks and decompile "
    "again - write a ghidra_script instead of calling decompile dozens of times. Bulk "
    "output MUST go to the getScriptArgs()[0] file: Ghidra's console silently drops "
    "lines under load."
)


SPLIT_LARGE_SOLVER_HINT = (
    "method: when a task needs both (a) bulk-extracting a large amount of structured "
    "data (every entry of a large table/array, or every case of a huge switch) and "
    "(b) then computing something FROM that data (e.g. a graph search), don't try to "
    "do both in ONE author_and_run script - a script that big can exceed the output "
    "token budget and get cut off mid-generation (a truncated script fails with a "
    "syntax error like an unterminated string, or silently produces no output if the "
    "print() calls near the end never got written). Split it into two separate "
    "author_and_run calls instead: first, extract the raw data and save it to a file "
    "(JSON/pickle) with an explicit print() confirming size/shape; then, in a second, "
    "separate call, write a smaller script that loads that saved file and does the "
    "analysis/search. Each script stays small enough to generate reliably."
)


SEEING_HINT = (
    "method: when you need to SEE something, go cheap-to-expensive. (1) win_windows "
    "first on Windows: it returns window titles, classes and - through UI Automation "
    "- the readable text inside a chosen window, which is usually the entire answer "
    "for an error box, a prompt or a status message, at a few dozen tokens. (2) Only "
    "if the meaning is genuinely VISUAL (a drawn image, a rendered puzzle, a custom "
    "widget, a picture hidden in resources or a PDF) use win_screenshot / view_image, "
    "which cost ~1500-1900 tokens per look. (3) An attached image is SINGLE-SHOT: it "
    "is visible on your very next turn only, then discarded - so write what you saw "
    "into that turn's `note`, or you will have paid for it twice. (4) For pictures "
    "inside files, extract first and look second: extract_images for a PE's .rsrc, "
    "pdf_pages for a PDF (renders pages AND pulls embedded images AND gives you the "
    "page text for free), then view_image on the one that matters. (5) Kali is "
    "headless - a Linux GUI binary there needs linux_gui_run (Xvfb), not run_cmd."
)


DEBUGGER_HINT = (
    "method: you HAVE a debugger on Windows - win_frida. It runs a JavaScript snippet "
    "you write inside the live process, so 'what is this value at runtime' is one step "
    "instead of a reimplementation. Reach for it when static reading stalls: a check "
    "whose inputs you cannot reconstruct, a decryption whose key is built at runtime, a "
    "buffer that only exists after unpacking, an anti-debug branch you want to force. "
    "Interceptor.attach(addr, {onEnter, onLeave}) is the breakpoint; hex(ptr, n) dumps "
    "memory; at('prog.exe', off) converts a Ghidra offset to a live address; "
    "Interceptor.replace patches a function outright. Measured working on x86-64 PEs on "
    "this ARM64 VM. It is Frida 17: Module.getGlobalExportByName, NOT findExportByName."
)


GUI_ACT_HINT = (
    "method: you can also ACT on the Windows GUI, not just look at it. win_ui_tree "
    "lists the live controls, win_ui_click presses one, win_ui_type fills one in, and "
    "win_ui_seq presses a whole SEQUENCE of them in one step. win_ui_tree reports two "
    "layers and WHICH ONE SEES ANYTHING DEPENDS ON THE TOOLKIT - both cases are "
    "measured on this VM, so read the tree and believe it rather than picking a layer "
    "in advance. (1) A Win32/WinForms dialog: UI Automation shows nothing usable "
    "(generic Panes, empty pattern list) while the W32 lines carry the real controls - "
    "address those by `hwnd`. (2) A Qt application: the reverse - Win32 child "
    "enumeration returns ZERO controls (Qt paints its widgets inside one single HWND) "
    "while UIA exposes every widget with its type, name and current value - address "
    "those by `target` (AutomationId or Name) and read their `val=`. When neither "
    "layer shows a control, win_ui_click takes raw x/y from the rect win_ui_tree "
    "printed. WM_SETTEXT fills a box without telling the program anything changed, so "
    "after typing you normally still click the button. Start the program with "
    "win_gui_run(kill=false) first, or there is no window to talk to."
)


LONG_JOB_HINT = (
    "method: work that cannot finish inside one tool call goes to job_start, not to a "
    "bigger timeout - thousands of files, a keyspace sweep, a long emulation. It "
    "returns immediately; you keep working and check with job_poll(name). Use "
    "job_poll(grep=...) to pull the interesting lines out of a huge log instead of "
    "paging it. A job that is still RUNNING is not a stall - do something else that "
    "step."
)


INSTALL_ALLOWED_HINT = (
    "capability: you ARE allowed to install tools on the analysis VM when the task "
    "needs them - a python library, a disassembler, or a specific interpreter "
    "version. Measured facts about THIS Kali box (re-measured 2026-09-22), so you "
    "don't waste steps:\n"
    "  * CHECK FIRST whether you need to install anything at all - the ENVIRONMENT "
    "FACTS entry in this ledger lists what is ALREADY importable by the solver "
    "interpreter. Installing something that is already there costs a step and "
    "counts as a stall.\n"
    "  * A BARE `pip install X` FAILS here: the system python is PEP-668 "
    "externally-managed (`error: externally-managed-environment`). Ignore any "
    "instinct that `pip install X` just works.\n"
    "  * To add a library the SOLVER can import, you must install into the solver's "
    "OWN interpreter: use the `pip` next to it (the ENVIRONMENT FACTS entry gives "
    "the exact path), e.g. `<venv>/bin/pip install capstone`. That venv has "
    "include-system-site-packages=false and ENABLE_USER_SITE=false, so "
    "`pip install --user`, `--break-system-packages` and `apt install python3-x` "
    "all land somewhere the solver CANNOT see - they will look like they worked and "
    "then fail with ImportError.\n"
    "  * `sudo` REQUIRES A PASSWORD and there is no TTY on this connection, so any "
    "sudo/apt line just fails. User-space installs only.\n"
    "  * The shell is NON-LOGIN: PATH does not include ~/.local/bin. Always invoke "
    "user-installed binaries by FULL PATH (`~/.local/bin/uv`, not `uv`).\n"
    "  * Installs are SLOW: pass a large `timeout` (e.g. 180-600) or the VM kills "
    "the command mid-download and you learn nothing.\n"
    "  * apt carries python3.13/3.14/3.15 but NOT 3.12. For a pinned CPython: "
    "`curl -LsSf https://astral.sh/uv/install.sh | sh` then "
    "`~/.local/bin/uv python install <version>`; then run your solver under it by "
    "passing `python=<absolute path to that interpreter>` to author_and_run / "
    "run_script - without that argument your solver still runs under the default "
    "venv interpreter and the version mismatch is unchanged.\n"
    "  * Run installs through run_cmd/run_script, not hidden inside a solver, and "
    "verify the result (import it, or -V) before relying on it.\n"
    "  * Marshalled Python bytecode and .pyc are VERSION-LOCKED. Measured on the "
    "real ch2 payload, 2026-09-22, under Python 3.14: `marshal.loads()` RETURNS a "
    "code object (so it looks like it worked) but `dis.dis()` on it then dies with "
    "`tuple index out of range` - the stdlib has only the CURRENT version's opcode "
    "table. Before installing another CPython, use xdis, which carries a separate "
    "opcode table per version: `from xdis.unmarshal import load_code` + "
    "`xdis.magics.magic2int(xdis.magics.magics['3.12.0'])` unmarshalled that same "
    "3.12 payload correctly under 3.14 and gave real co_names/co_consts. Note the "
    "division of labour: xdis READS and DISASSEMBLES foreign-version code objects, "
    "but uncompyle6/decompyle3 only DECOMPILE back to source for Python <= 3.8 - for "
    "3.9+ you read the disassembly and the constants, you do not get source back.\n"
    "  * For a .pyc FILE, try a DECOMPILER FIRST - reading source beats reading "
    "bytecode by an order of magnitude. `~/tools/pycdc/pycdc <file.pyc> > src.py` "
    "(Decompyle++) handles 3.9-3.12, which uncompyle6/decompyle3 cannot. Measured "
    "2026-09-23 on a real 3.12 .pyc: 394 lines of readable Python with every class "
    "and method named, versus 154361 characters of bytecode for the same file. Check "
    "stderr - it emits a warning per construct it could not lift, and falls back to "
    "bytecode comments inline; that is still far more readable than raw disassembly. "
    "Only when pycdc fails on the part you need, go to bytecode.\n"
    "  * For BYTECODE, do not hand-drive the xdis library at all: it ships a CLI, "
    "`<venv>/bin/pydisasm <file.pyc>`, that disassembles any version under whatever "
    "interpreter you are running. Measured 2026-09-23 on a real 3.12 .pyc under "
    "Python 3.14: one command, 4130 lines of clean disassembly, no API guessing. "
    "Redirect it to a file and page that file - guessing xdis module APIs "
    "(xdis.main, xdis.bytecode.Bytecode, ...) has burned whole steps.\n"
    "What stays refused is only security tampering (antivirus, firewall, services, "
    "registry, ACLs) and destructive disk/account commands."
)



# ============================================================================
# PART B — METHOD_PLAYBOOK sections moved out during the 2026-09-23 tier-1 rebuild
#          (off-domain for FLARE-On binary RE: blockchain/EVM, malware-C2 traffic
#           crypto, network/pcap). Verbatim; general RE notes stayed in the playbook.
# ============================================================================

[EVM / web3 / Solidity]
- A Python binary may just be a shell calling an EVM smart contract (via
  web3.py) — recognize it by standard Solidity deploy bytecode. For a pure
  function, deploy locally (web3.py + eth-tester, no real node) and call it to
  measure behavior, cheaper than translating EVM opcodes by hand.
- ethervm.io: statically disassembles EVM bytecode, useful alongside the
  deploy-locally-and-measure approach when you need more structure.
- A Python binary linked to web3/Solidity: use ganache (local testnet) to run
  the original binary end-to-end, not just the contract via eth-tester — take
  the RPC URL + private key ganache prints and put them in the program's
  config/GUI.


[malware C2 / traffic crypto]
- Fixed lookup table (256-perm) + index-dependent transform + final XOR
  constant: a common pattern in malware C2 traffic. Rebuild the reverse table
  from the binary, write a Python decoder, test on a few known samples before
  trusting it.
- AES key rotating by the hour = SHA256(host_id) XOR SHA256(password + current
  UTC hour): the password may be changed mid-stream by a specific C2 command —
  you must follow the whole traffic to catch the exact change point; using one
  fixed key for the entire PCAP will decode wrong from that point on.


--- Network / traffic ---
- The first file revealed in traffic is not necessarily the answer — the real
  answer may appear later (e.g. a zip password alongside a password.txt to try).
  Always follow the whole traffic chain to the end.
- A strange domain in traffic isn't automatically a fake placeholder — run
  nslookup first. A domain may be really registered yet still not be the server
  that generated the sample traffic (the original used an internal IP via a
  hosts override) — two possibilities to check separately.
- tshark -r <pcap> --export-objects http,<dir>: dump all HTTP bodies to
  separate files instead of reading frames one by one in the Wireshark GUI.


