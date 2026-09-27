# -*- coding: utf-8 -*-
"""STEP-0 MEASUREMENT (2026-09-27). Changes NO agent behavior: it only watches.

Answers two questions with numbers instead of guesses before any optimisation:
  1. TOKENS - how big is the per-step (UNCACHED) user message, which section makes it
     big (KNOWN / observations / ...), and how much of it would be REUSABLE as a cache
     prefix if ARTIFACTS+KNOWN were moved to the front with a cache breakpoint after.
  2. SPEED  - of each step's wall-clock, how much is the Brain call vs the Muscle tool.

Hooks (orchestrator): begin_step() at the top of each step, brain_done() after the
action is acquired, tool_done() after the tool returns/crashes. summary() is printed
by run.py and also written to METRICS_DUMP (default _metrics.json).
Token counts here are the provider-reported ones from reasoner.USAGE (exact). The
"reusable" figure is in CHARS; chars/3 is the same rough heuristic estimate_call uses.
"""
import json
import os
import re
import time

from . import reasoner

METRICS_DUMP = os.environ.get("METRICS_DUMP", "_metrics.json")
_KEYS = ("in", "out", "cache_read", "cache_write")
STEPS = []
_open = None          # the step currently being measured
_prev_head = None     # ARTIFACTS+KNOWN text of the previous step
_prev_state = None


def _usage():
    return {k: reasoner.USAGE.get(k, 0) for k in _KEYS}


def _common_prefix(a, b):
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    return i


def _sections(state):
    """Char size of each '=== TITLE ===' section, ledger split into its 3 lists."""
    sizes, texts = {}, {}
    parts = re.split(r"^=== (.+?) ===\n", state, flags=re.M)
    if parts[0].strip():
        sizes["preamble"] = len(parts[0])
    for title, body in zip(parts[1::2], parts[2::2]):
        key = title.split(" (")[0].strip().lower()
        if "stuck" in key:
            key = "nudge"
        if key == "ledger":
            cur = None
            for line in body.splitlines(keepends=True):
                for tag, name in (("KNOWN", "known"), ("ASSUMED", "assumed"),
                                  ("RULED OUT", "ruled_out")):
                    if line.startswith(tag):
                        cur = name
                if cur:
                    sizes[cur] = sizes.get(cur, 0) + len(line)
                    texts[cur] = texts.get(cur, "") + line
        else:
            sizes[key] = sizes.get(key, 0) + len(body)
            texts[key] = texts.get(key, "") + body
    return sizes, texts


def _close(now=None):
    global _open
    if _open is None:
        return
    cur, _open = _open, None      # clear FIRST: a bad record must not wedge later steps
    now = now or time.time()
    end, start = _usage(), cur.pop("_u0")
    cur["tokens"] = {k: end[k] - start[k] for k in _KEYS}
    cur["wall_s"] = round(now - cur.pop("_t0"), 2)
    STEPS.append(cur)


def begin_step(step, state, tier):
    """Top of a step, right after render_state(). Closes the previous step."""
    global _open, _prev_head, _prev_state
    try:
        now = time.time()
        _close(now)
        sizes, texts = _sections(state)
        # Proposed cache head: ARTIFACTS then KNOWN (both change rarely / append-only).
        head = texts.get("artifacts", "") + texts.get("known", "")
        reusable = 0
        if _prev_head is not None:
            reusable = (len(_prev_head) if head.startswith(_prev_head)
                        else _common_prefix(_prev_head, head))
        prefix_today = _common_prefix(_prev_state, state) if _prev_state else 0
        _open = {"step": step, "tier": tier, "state_chars": len(state),
                 "sections": sizes, "head_chars": len(head),
                 "head_reusable_chars": reusable,
                 "head_append_only": bool(_prev_head is not None
                                          and head.startswith(_prev_head)),
                 "full_state_common_prefix": prefix_today,
                 "brain_s": None, "tool": None, "tool_s": None,
                 "_t0": now, "_u0": _usage()}
        _prev_head, _prev_state = head, state
    except Exception as e:  # noqa: BLE001 - measurement must never break a run
        print(f"   [metrics] begin_step skipped ({e.__class__.__name__}: {e})")


def brain_done():
    if _open is not None and _open.get("brain_s") is None:
        _open["brain_s"] = round(time.time() - _open["_t0"], 2)


def tool_done(name, seconds, ok, out_chars=0):
    if _open is not None:
        _open.update(tool=name, tool_s=round(seconds, 2), tool_ok=bool(ok),
                     tool_out_chars=int(out_chars or 0))


def summary():
    """Close the last step, dump JSON, return a human-readable report."""
    try:
        _close()
        if not STEPS:
            return "(no steps measured)"
        n = len(STEPS)
        tot = {k: sum(s["tokens"][k] for s in STEPS) for k in _KEYS}
        wall = sum(s["wall_s"] for s in STEPS)
        brain = sum(s["brain_s"] or 0 for s in STEPS)
        tool = sum(s["tool_s"] or 0 for s in STEPS)
        secs = {}
        for s in STEPS:
            for k, v in s["sections"].items():
                secs[k] = secs.get(k, 0) + v
        state_tot = sum(s["state_chars"] for s in STEPS)
        reuse = sum(s["head_reusable_chars"] for s in STEPS)
        appendonly = sum(1 for s in STEPS[1:] if s["head_append_only"])
        by_tool = {}
        for s in STEPS:
            if s["tool"]:
                t = by_tool.setdefault(s["tool"], [0, 0.0])
                t[0] += 1
                t[1] += s["tool_s"] or 0
        pct = (lambda a, b: f"{100 * a / b:.0f}%" if b else "-")
        lines = [
            f"steps measured: {n}   wall {wall:.0f}s = Brain {brain:.0f}s ({pct(brain, wall)})"
            f" + tools {tool:.0f}s ({pct(tool, wall)}) + other {wall - brain - tool:.0f}s",
            f"tokens: uncached in={tot['in']:,}  out={tot['out']:,}  "
            f"cache_read={tot['cache_read']:,}  cache_write={tot['cache_write']:,}",
            f"user-message (state) chars: avg {state_tot // n:,}/step, max "
            f"{max(s['state_chars'] for s in STEPS):,}",
            "  by section (share of all state chars): " + ", ".join(
                f"{k} {pct(v, state_tot)}" for k, v in
                sorted(secs.items(), key=lambda kv: -kv[1])),
            f"cache-head (ARTIFACTS+KNOWN) reusable from previous step: {reuse:,} chars "
            f"total (~{reuse // 3:,} tokens, {pct(reuse, state_tot)} of all state chars); "
            f"append-only on {appendonly}/{max(n - 1, 0)} step transitions",
            "tool time: " + ", ".join(
                f"{k} x{c} {t:.0f}s" for k, (c, t) in
                sorted(by_tool.items(), key=lambda kv: -kv[1][1])),
        ]
        with open(METRICS_DUMP, "w") as f:
            json.dump({"steps": STEPS, "totals": tot}, f, indent=1)
        lines.append(f"(per-step detail -> {METRICS_DUMP})")
        return "\n".join(lines)
    except Exception as e:  # noqa: BLE001
        return f"(metrics summary failed: {e.__class__.__name__}: {e})"
