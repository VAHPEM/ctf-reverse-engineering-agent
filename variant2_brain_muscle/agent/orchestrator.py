# -*- coding: utf-8 -*-
"""Orchestrator = the core loop. Observe ledger -> Brain decides one action ->
Muscle acts -> record -> repeat. Progress is measured as KNOWN-fact accretion.
Two failure kinds are counted SEPARATELY: an ANALYSIS stall (the tool worked but
showed nothing new -> 2 escalate default->top, a stall even at top stops) and an
OPERATIONAL tool error (the tool could not do its job: wrong path/host, bad Frida JS,
a timeout, an SSH drop -> its own budget, re-ask to FIX the call, escalate once only
when the budget is spent). Never guesses.
"""
import os
import json
import time
import re
import inspect
import traceback
from .workspace import Workspace
from . import tools, reasoner, config, metrics


def _dump_state(ws, step, reason=None):
    """Persist the ledger after every step. Paired with run.py's --resume, this lets a killed run continue; until
    2026-09-22 a crashed or killed run left NOTHING behind - every measured fact of a
    40-step run was lost with the process. Best-effort: never let this break a run."""
    if not config.STATE_DUMP:
        return
    try:
        with open(config.STATE_DUMP, "w", encoding="utf-8") as f:
            json.dump({
                "step": step,
                "tier": getattr(ws, "tier", "?"),
                "flag": ws.flag,
                "stopped_because": reason,
                "artifacts": list(ws.artifacts.keys()),
                "env_facts": getattr(ws, "env_facts", ""),
                "known": ws.ledger.known,
                "assumed": ws.ledger.assumed,
                "ruled_out": ws.ledger.ruled_out,
                "history": [{"tool": t, "args": a, "summary": r} for t, a, r in ws.history],
                "seen_lines": ws.seen_lines,
                "seen_sigs": {repr(list(k)): v for k, v in ws.seen_sigs.items()},
                "tokens": reasoner.USAGE,
            }, f, ensure_ascii=False, indent=1)
    except Exception:  # noqa: BLE001
        pass


def _short(args):
    s = json.dumps(args, ensure_ascii=False)
    return s if len(s) <= 60 else s[:57] + "..."


# Tools whose FAILURE output is often the evidence itself: an ImportError naming the
# missing module, a traceback naming the real routine, "No such file" proving a path
# wrong. See `informative_fail` below.
INFORMATIVE_FAIL_TOOLS = {"run_cmd", "run_script", "author_and_run"}

# Identical args, legitimately different answer (see `repeated` below).
TIME_VARYING_TOOLS = {
    "job_poll", "win_screenshot", "win_windows", "win_ui_tree", "win_ui_seq",
    "win_ui_click", "win_ui_type", "win_frida", "win_gui_run", "linux_gui_run",
}

# Pure "look at bytes/text already on disk" tools. A long streak of ONLY these, with no
# new artifact produced, is the measured re-read loop (ch7/ch8): technically-novel byte
# ranges that never advance toward closing the challenge. decompile/pe_overview are left
# OUT on purpose - producing pseudocode for the first time is real RE progress, not a
# loop. author_and_run / win_frida / extract* / job_start / GUI drive are the productive
# and dynamic steps that RESET the streak.
READ_ONLY_TOOLS = {"peek", "read_file", "triage", "run_cmd", "r2"}

READONLY_CMDS = {
    "cat", "head", "tail", "xxd", "strings", "file", "wc", "od", "hexdump",
    "hexyl", "fold", "nl", "less", "more", "grep", "ls", "stat", "readelf",
    "nm", "objdump", "sed", "awk", "cut",
}


def _inspection_sig(name, args):
    """A signature for pure read-only *inspection* steps, so re-looking at data
    we already saw does NOT count as progress. Returns None for producing steps
    (author_and_run / extract / decoding commands) which are judged normally."""
    if name in ("peek", "read_file"):
        tgt = args.get("artifact") or args.get("path") or "*"
        # EXACT range, not a 2000-char bucket. Measured 2026-09-22 in a scripted
        # loop test: peek(0,300) followed by peek(300,900) both fell in bucket 0,
        # so the second - which surfaced 871 characters the Brain had never seen -
        # was scored "re-read data already seen", counted as a stall and triggered
        # an escalation. Any page shorter than 2000 chars hit this. Partial overlap
        # is already handled, exactly and deterministically, by ws.absorb(): a real
        # re-read scores 0 novel characters on its own.
        return (name, str(tgt),
                int(args.get("offset", 0) or 0), int(args.get("length", 0) or 0))
    if name == "triage":
        return ("triage", str(args.get("artifact") or "*"), 0)
    if name == "run_cmd":
        cmd = (args.get("command") or "").strip()
        head = cmd.split()[0] if cmd else ""
        if head in READONLY_CMDS and "|" not in cmd and ">" not in cmd:
            return ("run_cmd", cmd[:40], 0)
    return None



_REQUIRED_ARGS = {}


def _missing_required(name, args):
    """Args the tool's fn REQUIRES (no default) that the controller left out or blank.
    A controller that emits e.g. author_and_run({}) as a placeholder must be treated as
    a MALFORMED ACTION (re-ask, stop after 2), NOT as an analysis stall - the old path
    let it raise TypeError inside dispatch, which counted as a dead end and could
    escalate to the expensive top tier over a mere controller glitch."""
    if name not in _REQUIRED_ARGS:
        sig = inspect.signature(tools.TOOLS[name]["fn"])
        _REQUIRED_ARGS[name] = [
            pn for pn, pp in sig.parameters.items()
            if pn != "ws" and pp.default is inspect._empty
            and pp.kind in (pp.POSITIONAL_OR_KEYWORD, pp.KEYWORD_ONLY)
        ]
    miss = []
    for pn in _REQUIRED_ARGS[name]:
        v = args.get(pn)
        if pn not in args or v is None or (isinstance(v, str) and not v.strip()):
            miss.append(pn)
    return miss

def _acquire_action(ws, state, catalog, step, img, parts=None):
    """Get ONE well-formed action (tool in TOOLS, required args present), or None.

    Every malformed reply - a non-object, an empty object, an unknown tool, non-object
    args, or a tool called with a required arg left empty - is a CONTROLLER GLITCH, not
    an analysis failure. MEASURED ch8 run 3: sonnet-5 emitted `run_cmd({})` (the command
    it wanted was described in `why`/`note`, but `args` was empty) on 4 of 16 steps, and
    two in a row ended a run that was otherwise progressing. Two fixes here:
      * re-ask IN THE SAME STEP with a POINTED correction that names the exact problem
        ("you left args.command empty"), instead of re-sending the identical prompt and
        getting the identical glitch;
      * escalate the tier on a persistent glitch (the top model rarely makes it) rather
        than counting toward a hard stop.
    Returns (action_or_None, escalate_bool). action=None with escalate=True means "could
    not get a clean action at this tier - the caller should raise the tier and retry".
    """
    correction = ""
    for attempt in range(3):
        try:
            if attempt == 0:
                action = reasoner.decide(state, catalog, tier=ws.tier, image=img,
                                         parts=parts)
            else:
                # strict + a specific correction; minimal state on the last try (the 12KB
                # of observations is the likeliest reason the model wandered off format)
                st = ws.render_state(minimal=(attempt >= 2))
                action = reasoner.decide(st, catalog, strict=True, tier=ws.tier,
                                         correction=correction)
        except Exception as e:  # noqa: BLE001 - the Brain call already retried internally
            print(f"   !! Brain call failed: {e.__class__.__name__}: {e}")
            traceback.print_exc()
            _dump_state(ws, step, f"brain call failed: {e}")
            raise

        raw = " ".join((getattr(reasoner, "LAST_RAW", "") or "").split())
        if not isinstance(action, dict) or not action:
            correction = ("Your last reply was not one JSON object" +
                          (f" (it began: {raw[:80]!r})" if raw else "") +
                          ". Reply with exactly one {\"tool\":...,\"args\":{...}} object.")
        elif action.get("stop"):
            return action, False              # a real stop request - honour it upstream
        elif action.get("tool") not in tools.TOOLS:
            correction = (f"'{action.get('tool')}' is not a tool. Choose one from the "
                          "AVAILABLE TOOLS list and fill its args.")
        elif not isinstance(action.get("args") or {}, dict):
            correction = (f"For {action.get('tool')}, `args` must be a JSON object like "
                          '{"command": "..."}, not ' + type(action.get("args")).__name__ + ".")
        else:
            missing = _missing_required(action["tool"], action.get("args") or {})
            if not missing:
                return action, False          # clean
            nm = action["tool"]
            correction = (f"You chose {nm} but left required arg(s) {missing} EMPTY. The "
                          f"actual value goes in args.{missing[0]} (e.g. the real command "
                          "string / function name), NOT in `why` or `note`. Re-send "
                          f"{nm} with {missing} filled in.")
        if attempt < 2:
            print(f"   !! malformed action - re-asking in-step ({attempt + 1}/2): "
                  f"{correction[:80]}")
    # Three tries at this tier all malformed. Record what the model actually SAID, so
    # a giving-up run is diagnosable instead of a mystery (ch8 run 4 ended here with no
    # trace of opus's replies).
    raw = " ".join((getattr(reasoner, "LAST_RAW", "") or "").split())
    print(f"   !! gave up forming an action at tier={ws.tier}. Last raw reply head: "
          + (raw[:300] if raw else "(empty)"))
    ws.ledger.rule_out("controller could not emit a well-formed action for 3 tries "
                       f"(last problem: {correction[:100]}; raw head: {raw[:120]})")
    return None, True


def solve(files, max_steps=None, resume=None):
    max_steps = max_steps or config.MAX_STEPS
    ws = Workspace(files)
    ws.tier = "default"                     # current Brain tier
    if resume:
        # Pick up where a crashed/killed/budget-exhausted run stopped instead of
        # paying for the same first N steps again. The dump is written after every
        # step, so the worst case is losing the single step in flight.
        try:
            with open(resume, encoding="utf-8") as f:
                nk, nh = ws.restore(json.load(f))
            print(f"   [resume] {resume}: {nk} KNOWN facts, {nh} past actions restored")
        except FileNotFoundError:
            print(f"   [resume] {resume} does not exist - starting fresh")
        except Exception as e:  # noqa: BLE001 - a bad dump must not block a run
            print(f"   [resume] could not read {resume} ({e.__class__.__name__}: {e})"
                  " - starting fresh")
    ws.ledger.know("input artifacts: " + ", ".join(ws.artifacts.keys()), pin=True)
    # The standing task/method facts now live in the controller's (cached) system
    # prompt - see config.STATIC_FACTS_TEXT. Only what is MEASURED per run goes here.
    print("   [probe] measuring the analysis VM ...")
    # The measured environment and the tool catalog are CONSTANT for the whole run but
    # used on every step. Keeping them in the ledger / user message meant re-sending
    # ~3200 uncached tokens per step (measured: catalog 2775 + env facts 458), i.e. 39%
    # of everything sent each step, ~129k tokens over a 40-step run - for text that
    # never changes. They now go into a SECOND cached system block, so the Brain still
    # reads them on every step while paying for them once.
    ws.env_facts = tools.probe_environment()
    reasoner.set_run_context(ws.env_facts, tools.catalog())

    # Survey EVERY input up front (multi-file bundles are the norm: binary + pcap +
    # memory dump + disk/firmware image + README). Uploads each to the VM and records
    # its `file` type + size so the Brain sees the whole landscape from step 1 rather
    # than only the first artifact's name - it used to triage just the primary file and
    # miss the pcap/dump. Pinned so the input inventory never evicts from the ledger.
    if len(ws.artifacts) > 1:
        print(f"   [survey] typing + uploading {len(ws.artifacts)} input artifacts ...")
    _survey = tools.survey_inputs(ws)
    for _f in _survey:
        ws.ledger.know(_f, pin=True)

    # PRIOR NOTES. A handoff doc among the inputs (_analysis/*.md) is read on nearly
    # every step otherwise (13/60 in ch8 run 15). Pin it whole in the cached context.
    ws.pinned_docs = set()
    if config.PIN_DOCS_MAX_CHARS:
        for _a in list(ws.artifacts.values()):
            _nm = _a.name.replace("\\", "/")
            if not (_nm.lower().endswith(".md") and "_analysis/" in _nm):
                continue
            try:
                with open(_a.local_path, encoding="utf-8", errors="replace") as _fh:
                    _txt = _fh.read()
            except OSError:
                continue
            if 0 < len(_txt) <= config.PIN_DOCS_MAX_CHARS:
                reasoner.add_run_block(
                    f"PRIOR NOTES: {_a.name} (pinned whole - do NOT peek/read_file it; "
                    "its claims marked unverified still need a measurement)", _txt)
                ws.pinned_docs.add(_a.name)
                print(f"   [memory] pinned {_a.name} ({len(_txt)} chars) into context")

    # SMALL INPUT FILES. Tiny source/config files age out of the observation window and
    # then get peek/read_file'd repeatedly (MEASURED ch8 crux: popup.js 6x, popup.html 5x,
    # manifest.json 3x in 60 steps). Pin the small TEXT ones whole - the SAME mechanism as
    # PRIOR NOTES, so peek/read_file serve them from context instead of re-reading. A
    # whitelist by extension plus a per-file / count / total cap keeps the big binary and
    # the 17KB Go glue (wasm_exec.js) out.
    if config.PIN_SMALL_FILES_MAX_CHARS:
        _PIN_EXT = {".js", ".json", ".html", ".htm", ".txt", ".css", ".xml", ".ini",
                    ".cfg", ".conf", ".yaml", ".yml", ".toml", ".csv", ".md", ".py",
                    ".go", ".rs", ".c", ".h", ".ts", ".java", ".sh", ".bat", ".ps1"}
        _cnt, _budget = 0, 24000
        for _a in list(ws.artifacts.values()):
            if _cnt >= 16 or _budget <= 0:
                break
            if _a.name in ws.pinned_docs:
                continue
            _ext = os.path.splitext(_a.name.replace("\\", "/"))[1].lower()
            if _ext not in _PIN_EXT:
                continue
            try:
                with open(_a.local_path, encoding="utf-8") as _fh:
                    _txt = _fh.read()
            except (OSError, UnicodeDecodeError):
                continue        # binary or unreadable -> never pin
            if not (0 < len(_txt) <= config.PIN_SMALL_FILES_MAX_CHARS) or len(_txt) > _budget:
                continue
            reasoner.add_run_block(
                f"INPUT FILE: {_a.name} (pinned whole - do NOT peek/read_file it; its "
                "full content is right here)", _txt)
            ws.pinned_docs.add(_a.name)
            _cnt += 1
            _budget -= len(_txt)
            print(f"   [pin] input file {_a.name} ({len(_txt)} chars) into context")

    # MEMORY SEED. recall() used to be consulted only AFTER a stall (0-2 calls per run,
    # always with why="Stalled..."), i.e. after the steps its notes would have saved.
    # Pull the notes matching the input's SHAPE (Qt / .NET / pcap / Go / python ...)
    # once, now, into the cached run context. Nothing distinctive -> nothing seeded.
    if config.SEED_RECALL:
        try:
            _q, _notes = tools.seed_recall(ws, _survey, k=config.SEED_RECALL)
            if _notes:
                reasoner.add_run_notes(_notes)
                print(f"   [memory] seeded {len(_notes.splitlines())} technique notes "
                      f"for shape: {_q}")
            else:
                print(f"   [memory] no distinctive input shape ({_q or 'none'}) - no "
                      "notes seeded; the Brain should recall() after triage")
        except Exception as e:  # noqa: BLE001 - memory is a bonus, never block a run
            print(f"   [memory] seed skipped ({e.__class__.__name__}: {e})")

    dead_end = 0             # consecutive ANALYSIS stalls (tool worked, no new info)
    tool_err = 0             # consecutive OPERATIONAL tool errors (own budget - #1)
    good_streak = 0          # consecutive progressed steps (drives de-escalation)
    ws.escalations = 0       # times the run has escalated default->top
    ws.pinned_top = False    # after the 2nd escalation, keep Opus for the endgame
    last_action = None
    last_was_info_fail = False   # at most ONE informative failure is forgiven in a row
    inspect_streak = 0           # consecutive read-only steps with no new artifact
    dyn_targets = {}             # address literal -> number of win_frida calls using it

    for step in range(1, max_steps + 1):
        ws.step = step
        parts = ws.render_state_parts()      # (cacheable head pieces, tail)
        state = "".join(parts[0]) + parts[1]
        catalog = tools.catalog()
        if config.MAX_RUN_TOKENS:
            # Would THIS step's Brain call fit? (checking `spent >= MAX` after the fact
            # let the last call overshoot by a whole reply)
            est = reasoner.estimate_call(
                len(state), len(reasoner.CONTROLLER_SYSTEM) + len(reasoner.RUN_CONTEXT),
                config.MAX_OUTPUT_TOKENS)
            fits, left = reasoner.budget_room(est)
            if not fits:
                return _stop(ws, f"token budget: {max(left, 0):,} of "
                                 f"{config.MAX_RUN_TOKENS:,} left, the next Brain call "
                                 f"may bill up to ~{est:,} - stopping BEFORE it; resume "
                                 "with --resume once you decide to spend more")
        print(f"\n==== STEP {step}/{max_steps}  [tier={ws.tier}] ====")
        metrics.begin_step(step, state, ws.tier)      # measurement only (step 0)

        img, ws.last_image = ws.last_image, None    # one-shot: use it once, then forget it
        if img:
            print("   [image] attaching one extracted image to this decide() call")
        try:
            action, want_escalate = _acquire_action(ws, state, catalog, step, img,
                                                    parts=parts)
            metrics.brain_done()
        except Exception as e:  # noqa: BLE001 - a Brain-call failure is unrecoverable
            return _stop(ws, f"Brain call failed after retries ({e.__class__.__name__}: "
                             f"{str(e)[:200]}) - ledger saved to {config.STATE_DUMP}")
        if action is None:
            # Malformed at this tier despite in-step re-asks. A controller glitch is
            # exactly what the top tier handles best, so escalate rather than end a
            # progressing run; only stop if even the top tier cannot form an action.
            if want_escalate and _handle_stall(ws, config.STALL_THRESHOLD):
                _dump_state(ws, step)
                continue
            return _stop(ws, "controller could not produce a well-formed action, even "
                             "at the top tier")
        if action.get("stop"):          # a null/empty "stop" is not a stop
            return _stop(ws, str(action.get("stop")))
        name = action.get("tool")
        args = action.get("args") or {}
        print(f">> DECIDE: {name}({_short(args)})  why: {str(action.get('why',''))[:80]}")
        note = action.get("note")
        if isinstance(note, str) and note.strip():
            note = " ".join(note.split())[:config.NOTE_MAX_CHARS]
            if ws.ledger.assume_note(f"[s{step}] {note}"):
                print(f"   note: {note[:120]}")
        # tool validity + required args are guaranteed by _acquire_action above.
        art_before = len(ws.artifacts)
        sig = _inspection_sig(name, args)
        # "redundant" means: you looked at EXACTLY this (same file, same byte range)
        # before. It is redundant however long ago - the bytes are on disk and were
        # already recorded, so re-reading the same range is never new information.
        # MEASURED ch8 run 12: FINDINGS.md was re-read whole at s2 then AGAIN at
        # s16/s24/s31; each had aged out of the observation window, so absorb() scored
        # its bytes "novel" again and every re-read counted as progress - a loop the
        # stall detector never saw. A genuine need for aged-out data is served by the
        # note the Brain was told to write, not by re-reading the same range.
        last_seen = ws.seen_sigs.get(sig) if sig is not None else None
        redundant = last_seen is not None
        allowed = set(tools.TOOLS[name]["args"].keys())
        kwargs = {k: v for k, v in args.items() if k in allowed}
        _t_tool = time.time()
        try:
            res = tools.TOOLS[name]["fn"](ws, **kwargs)
        except Exception as e:  # noqa: BLE001 - a tool crash is a FAILED STEP, not a
            # dead run. Before 2026-09-22 only TypeError was caught, so an SSH drop,
            # an SFTP error or a struct.error inside a tool killed the whole run and
            # threw away every measured fact.
            metrics.tool_done(name, time.time() - _t_tool, False)
            kind = "bad args for" if isinstance(e, TypeError) else "crash in"
            detail = f"{e.__class__.__name__}: {e}"
            print(f"   !! {kind} {name}: {detail}")
            if not isinstance(e, TypeError):
                traceback.print_exc()
            ws.ledger.rule_out(f"{kind} {name}: {detail[:200]}")
            ws.history.append((name, _short(args), f"FAILED ({detail[:80]})"))
            # A crash inside a tool (SSH/SFTP drop, struct.error, bad args) is an
            # OPERATIONAL error, not the Brain going in circles - so it draws on the
            # tool-error budget, NOT the analysis-stall counter (#1). It never escalates
            # or stops within budget; the Brain just gets the error back and fixes the call.
            tool_err += 1
            good_streak = 0
            _dump_state(ws, step)
            print(f"   [tool-error {tool_err}/{config.TOOL_ERROR_BUDGET}] {kind} {name} "
                  "(operational, not an analysis stall)")
            if tool_err >= config.TOOL_ERROR_BUDGET:
                if not _handle_tool_errors(ws, tool_err):
                    return _stop(ws, f"repeated tool errors even at TOP tier (last: "
                                     f"{name} - {detail[:120]})")
                tool_err = 0
            continue

        metrics.tool_done(name, time.time() - _t_tool, res.ok,
                          len(res.detail or "") + len(getattr(res, "info", None) or ""))
        # Stamp the inspection signature only now that the tool actually ANSWERED.
        # Stamping it before dispatch meant a crashed call (SSH drop, SFTP error) still
        # recorded "you looked at this", so the retry - the first call that really
        # returned data - was scored "re-read data already seen" and counted a stall.
        if sig is not None:
            ws.seen_sigs[sig] = step
        ws.history.append((name, _short(args), res.summary))
        if res.detail:
            ws.observe(f"{name} {_short(args)}", res.detail)
        if getattr(res, "image", None):
            ws.last_image = res.image
        print(f"   -> {res.summary}")
        if res.detail:
            print("   detail:", res.detail[:200].replace("\n", " ")[:200])

        if res.flag and _flag_is_echoed_input(res.flag, name, args):
            # FALSE flag = the Brain's OWN input echoed back in the tool output, not a
            # value the challenge produced. MEASURED ch8 crux (2026-09-27): a run_script
            # that tried guesses like "flareon2024@flare-on.com" had that guess echoed on
            # an ERROR line, _find_flag matched it, and the run declared [SOLVED] on a
            # non-flag. A real flag comes from the challenge's computation, so it does NOT
            # appear in the command/script/args we just sent. check_flag is exempt (there
            # the Brain deliberately submits a candidate to confirm the format).
            print(f"   [flag-guard] '{res.flag}' appears in THIS step's own input - "
                  "echoed, NOT a real flag; continuing")
            ws.ledger.rule_out(f"{name}: '{res.flag}' was echoed input, not a real flag")
            res.flag = None
        if res.flag:
            ws.flag = res.flag
            print(f"\n[SOLVED] flag = {ws.flag}")
            _dump_state(ws, step, "solved")
            return ws

        new_art = len(ws.artifacts) - art_before
        act_sig = (name, json.dumps(args, ensure_ascii=False, sort_keys=True))
        # Some tools answer about a world that MOVED between two identical calls: the
        # background job finished, the button was clicked, the window changed. For
        # those, "same args as last time" says nothing about whether the answer is new
        # - and CAPABILITIES_HINT tells the Brain job_poll is how to watch a long job. Novelty
        # accounting (absorb) already judges them correctly.
        repeated = act_sig == last_action and name not in TIME_VARYING_TOOLS
        last_action = act_sig

        # A - NEW INFORMATION, not new records (run-2 lesson): every run_cmd used to add a
        # unique "`cmd` -> out" KNOWN fact, so even empty / failed / duplicate results
        # counted as progress and the stall detector (hence Opus escalation) never fired.
        # Progress = a new artifact, or output with >= INFO_MIN_CHARS of lines the Brain has
        # never been shown, from a step that succeeded and is not a plain repeat/re-read.
        seen_text = res.info if res.info is not None else (res.detail or " ".join(res.known))
        # Only score what the Brain will actually be shown. Before 2026-09-23 this
        # counted the FULL tool output, so a page that got truncated on the way into
        # the prompt still earned progress credit for text nobody ever read - and
        # worse, marked those lines "seen", so re-reading them later scored zero.
        novel = ws.absorb((seen_text or "")[:config.OBS_CAP_NEWEST])
        has_info = novel >= config.INFO_MIN_CHARS
        progressed = res.ok and not repeated and (new_art > 0 or (has_info and not redundant))
        # A failed step that still showed the Brain NEW evidence is neither progress nor
        # a dead end. Until 2026-09-23 every non-zero exit counted as a stall and was
        # written to RULED OUT as "did not help" - even when the traceback was exactly
        # what the next step needed - so two such steps escalated to the top tier on
        # evidence that was useful. Bounded: only ONE in a row is forgiven, so a solver
        # that fails differently every time still reaches the stall threshold.
        informative_fail = (not res.ok and name in INFORMATIVE_FAIL_TOOLS
                            and has_info and not repeated and not redundant
                            and not last_was_info_fail)
        last_was_info_fail = informative_fail
        print(f"   [acct] novel_chars={novel} progressed={progressed}"
              + ("  (failed, but showed new evidence - not counted as a stall)"
                 if informative_fail else ""))
        # A measured fact stays a measured fact even when the step earned no
        # progress credit. Until 2026-09-22 these two were fused, so a SUCCESSFUL
        # step whose output merely overlapped something seen before had its facts
        # DELETED from the ledger and replaced by a RULED_OUT line - the agent
        # actively forgot things it had just measured. Scoring (stall/escalation)
        # still uses `progressed`; recording no longer does. KNOWN_CAP + pinning
        # keep the prompt from growing without bound.
        if res.ok:
            for f in res.known:
                ws.ledger.know(f)
        if progressed:
            dead_end = 0
            tool_err = 0
            good_streak += 1
            ws.strategic_nudge = ""      # moving again -> drop the "stuck" banner
            # Escalation used to be a ONE-WAY door: two stalls put the Brain on the top
            # (Opus) tier and it stayed there for every remaining step, even after the
            # block cleared - the most expensive part of a run, spent on steps the
            # default tier had just proven it could handle. Drop back once the run is
            # demonstrably moving again; a new pair of stalls escalates again, so the
            # safety net is unchanged.
            if (ws.tier == "top" and good_streak >= config.DEESCALATE_AFTER
                    and not getattr(ws, "pinned_top", False)):
                ws.tier = "default"
                good_streak = 0
                print(f"   .. {config.DEESCALATE_AFTER} steps of real progress -> "
                      "back to DEFAULT tier")
        elif informative_fail:
            good_streak = 0
            tool_err = 0
            ws.ledger.know(f"[s{step}] {name} FAILED but showed new evidence: "
                           f"{' '.join((res.detail or res.summary).split())[:200]}")
        elif getattr(res, "waiting", False):
            # Legitimately waiting on a background job: not progress, but NOT a stall
            # either. dead_end and good_streak both stand still.
            print("   [waiting] background work still running - not counted as a stall")
        elif not res.ok:
            # OPERATIONAL tool error: the tool RAN but could not do its job (frida
            # syntax/API error, file-not-found, wrong host, a timeout, "unrecognized
            # archive"). #1: its own budget - re-ask so the Brain repairs the call; it
            # does NOT escalate the tier or stop the run within budget, unlike a stall.
            good_streak = 0
            tool_err += 1
            ws.ledger.rule_out(f"{name} did not help (tool error): {res.summary}")
            print(f"   [tool-error {tool_err}/{config.TOOL_ERROR_BUDGET}] {name}: "
                  f"{res.summary[:80]}")
            if tool_err >= config.TOOL_ERROR_BUDGET:
                if not _handle_tool_errors(ws, tool_err):
                    return _stop(ws, f"repeated tool errors even at TOP tier (last: "
                                     f"{name} - {res.summary[:120]})")
                tool_err = 0
        else:
            # ANALYSIS stall: the tool SUCCEEDED but the step yielded nothing new
            # (repeated the same call, re-read seen bytes, no new information). THIS is
            # the "Brain going in circles" signal that escalates and, at top, stops.
            good_streak = 0
            dead_end += 1
            why = ("repeated the same call" if repeated else
                   "re-read data already seen" if redundant else "no new information")
            ws.ledger.rule_out(f"{name}: {why} - {res.summary}")
            print(f"   [stall {dead_end}/{config.STALL_THRESHOLD}]")
            if dead_end >= config.STALL_THRESHOLD:
                if not _handle_stall(ws, dead_end):
                    return _stop(ws, "stalled even at TOP tier (2 dead ends)")
                dead_end = 0

        # ENDGAME PUSH (measured re-read loop, ch7/ch8). Count consecutive read-only
        # steps that produced no new artifact; a productive/dynamic step or a new
        # artifact resets it. When it crosses the threshold, inject a one-shot nudge -
        # NOT a stall, NOT an escalation - steering the Brain from reading to closing.
        # Set AFTER the progress block above, which clears strategic_nudge on progress
        # (a read step usually counts as progressed), so the nudge would be wiped if set
        # earlier.
        # SAME DYNAMIC TARGET RETRIED. Count, per address literal, how many win_frida
        # calls referenced it. Once one address has been tried DYN_REPEAT_NUDGE times,
        # nudge toward offline emulation (once per address). Pure bookkeeping on the
        # Brain's own scripts; no judgement about what the script does.
        if config.DYN_REPEAT_NUDGE and name == "win_frida":
            _addrs = set(_hex_targets(str(args.get("script") or "")))
            _hot = []
            for _ad in _addrs:
                dyn_targets[_ad] = dyn_targets.get(_ad, 0) + 1
                if dyn_targets[_ad] == config.DYN_REPEAT_NUDGE:
                    _hot.append(_ad)
            if _hot:
                ws.strategic_nudge = (
                    f"MEASURED: address(es) {', '.join(sorted(_hot))} have now been "
                    f"targeted in {config.DYN_REPEAT_NUDGE} win_frida calls. Repeating the "
                    "same runtime approach on the same spot is the most expensive loop "
                    "this agent has. If those calls did not give you the value you "
                    "needed, stop retrying there: EMULATE the relevant function OFFLINE "
                    "(author_and_run with Unicorn + pefile, calling it as a black box on "
                    "chosen inputs) or solve from the static logic. Retry the runtime "
                    "approach only with a genuinely different anchor and a stated reason."
                )
                print(f"   [dyn-repeat] {', '.join(sorted(_hot))} targeted "
                      f"{config.DYN_REPEAT_NUDGE}x -> nudging toward offline emulation")

        if config.INSPECT_NUDGE_AFTER:
            if name in READ_ONLY_TOOLS and new_art == 0:
                inspect_streak += 1
            else:
                inspect_streak = 0
            if inspect_streak >= config.INSPECT_NUDGE_AFTER:
                ws.strategic_nudge = (
                    f"MEASURED: {inspect_streak} steps in a row were pure READING "
                    "(peek/read_file/run_cmd/r2) with no new artifact and no solver. "
                    "Reading is not closing the challenge. If your ledger already names "
                    "the check/decode routine and its constants, STOP reading now and "
                    "write the solver with author_and_run (it hands your evidence to a "
                    "script that PRINTS the answer). If a value is only knowable at "
                    "runtime, go DYNAMIC (win_frida) to read it. Re-read a byte range "
                    "only if you can name the exact fact you still lack and why a solver "
                    "cannot compute it."
                )
                print(f"   [endgame-push] {inspect_streak} read-only steps -> nudging "
                      "toward author_and_run / dynamic (not a stall)")
                inspect_streak = 0
        _dump_state(ws, step)

    return _stop(ws, f"budget exhausted ({max_steps} steps) without a flag")


_HEX_RX = re.compile(r"0x([0-9a-fA-F]{4,16})\b")


def _hex_targets(script):
    """Address-looking hex literals in a script (>= 0x1000), normalised to lower-case
    offsets. An absolute VA 0x14002a5d0 and a module offset 0x2a5d0 name the same spot,
    so an image base (0x140000000) is subtracted when present."""
    out = []
    for h in _HEX_RX.findall(script or ""):
        v = int(h, 16)
        if 0x140000000 <= v < 0x150000000:
            v -= 0x140000000
        elif 0x400000 <= v < 0x1000000:
            v -= 0x400000
        if v >= 0x1000 and v < 0x10000000:
            out.append(hex(v))
    return out


def _flag_is_echoed_input(flag, name, args):
    """True when `flag` is merely the Brain's own input for THIS step, echoed back in the
    tool output - not a value the challenge computed. The check: the flag string appears
    verbatim in the serialized args (the command / script / text we just sent). check_flag
    is exempt: submitting a candidate to confirm its format is its whole purpose."""
    if name == "check_flag":
        return False
    try:
        blob = json.dumps(args, ensure_ascii=False)
    except Exception:  # noqa: BLE001
        blob = str(args)
    return flag in blob


def _handle_tool_errors(ws, n):
    """The TOOL-ERROR budget is spent (#1). Operational errors do not escalate WITHIN
    budget; only here, when it is exhausted, do we act - and the user's chosen policy is
    "escalate once, then stop":
      * at the default tier -> flip to TOP so the stronger model can repair the broken
        call (fix the path/host, the Frida API name, raise a timeout, extract/sync the
        file). Returns True (keep going, budget reset by the caller).
      * already at TOP and errors STILL persist past budget -> return False so the caller
        stops: a call failing this persistently even for Opus is a genuinely broken tool
        or target, not a reasoning gap to spend more on.
    Deliberately does NOT touch ws.escalations / pinned_top: those drive the analysis
    endgame (pin Opus after 2 real stalls), and a mere tool glitch should not pull that
    lever. It only moves the tier so the next call is repaired by the better model."""
    ws.strategic_nudge = (
        "MEASURED: the last few steps FAILED at the TOOL level, not the analysis level - "
        "a file not found, a wrong host (PE work needs host='windows'), a Frida syntax/"
        "API error, an archive not extracted, or a driver timeout. RE-READ the exact "
        "error text and FIX THE CALL: correct the path/host, fix the JS/Frida-17 API "
        "name, raise `timeout`, or extract/sync so the file is actually present. Do NOT "
        "abandon or rethink your analytical plan over a tool glitch."
    )
    if ws.tier == "default":
        ws.tier = "top"
        print(f"   !! tool-error budget ({n}) spent -> escalate Brain to TOP tier to "
              "REPAIR the call (analysis plan unchanged)")
        return True
    return False


def _handle_stall(ws, dead_end):
    """On the stall threshold: escalate default->top once. Return False if already
    at top tier (caller should stop)."""
    if dead_end < config.STALL_THRESHOLD:
        return True
    ws.strategic_nudge = (
        "MEASURED: the current line of attack has STALLED (repeated low-yield steps). Do NOT repeat the same kind of search with a new regex or a bigger timeout - that is the classic budget sink. CHANGE KIND of approach: go DYNAMIC (win_frida to read a runtime value / emulation), decompile the EXACT handler you care about, or recall(<this situation in keywords>) for how this kind of target is usually cracked - then act on what comes back."
    )
    if ws.tier == "default":
        ws.tier = "top"
        ws.escalations = getattr(ws, "escalations", 0) + 1
        print(f"   !! {config.STALL_THRESHOLD} stalls -> escalate Brain to TOP tier "
              f"(escalation #{ws.escalations})")
        # A run that made the cheap tier stall to escalation TWICE is a genuinely hard
        # challenge; the flip-flop (escalate -> 3 quick reads de-escalate -> stall ->
        # escalate) measured on ch8/ch7 kept handing the ENDGAME back to the weaker
        # model. Pin Opus for the rest of the run: it owns the endgame, and if IT also
        # stalls twice the run STOPS cleanly (design rule: stuck at top -> stop).
        if (ws.escalations >= config.PIN_TOP_AFTER_ESCALATIONS
                and not getattr(ws, "pinned_top", False)):
            ws.pinned_top = True
            print(f"   !! escalation #{ws.escalations} -> PINNED to TOP tier for the "
                  "rest of the run")
        return True
    return False


def _stop(ws, reason):
    _dump_state(ws, None, reason)
    print(f"\n[STOP - needs a human] {reason}")
    print("\nFinal ledger:\n" + ws.ledger.render())
    return ws
