# -*- coding: utf-8 -*-
"""Brain = the single reasoning model.

One node: `decide` (controller — pick the next action / interpret evidence) and
`author_script` (write a solver) are two CALLS of the same Brain by default.
They stay as separate functions (the seam) so a future logic/coder split is just
a config.py change. Muscle never reasons; it only runs and returns raw output.
"""
import os
import re
import ast
import sys
import json
import time
import ollama

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from prompts import SYSTEM_PROMPT                       # noqa: E402
from ctf_playbook import ANALYSIS_DISCIPLINE, METHOD_PLAYBOOK  # noqa: E402
from . import config                                    # noqa: E402

# Static instructional prefix for CODER calls. Kept identical across calls so
# it becomes a cache prefix (Anthropic cache_control; OpenAI/Ollama auto-reuse).
CODER_SYSTEM = (SYSTEM_PROMPT + "\n\n" + ANALYSIS_DISCIPLINE + "\n\n"
                + METHOD_PLAYBOOK + "\n\n" + config.STATIC_FACTS_TEXT)


USAGE = {"calls": 0, "in": 0, "out": 0, "cache_read": 0, "cache_write": 0, "by_model": {},
         # MEASURE: which model ACTUALLY answered (resp.model) per requested model, and
         # every stop_reason=="refusal". Opus 5.5 / Fable 5.x cyber safeguards can
         # redirect cyber work to an older model or refuse with HTTP 200 - silent unless
         # we record it. {requested: {served: count}} ; [{"requested","served","call"}]
         "served_by": {}, "refusals": [], "refusal_fallbacks": 0}


def _record_usage(model, u):
    """MEASURE ONLY: per-call + running token totals (Anthropic usage object)."""
    if u is None:
        return
    d = {
        "in": getattr(u, "input_tokens", 0) or 0,
        "out": getattr(u, "output_tokens", 0) or 0,
        "cache_read": getattr(u, "cache_read_input_tokens", 0) or 0,
        "cache_write": getattr(u, "cache_creation_input_tokens", 0) or 0,
    }
    m = USAGE["by_model"].setdefault(
        model, {"calls": 0, "in": 0, "out": 0, "cache_read": 0, "cache_write": 0})
    USAGE["calls"] += 1
    m["calls"] += 1
    for k, v in d.items():
        USAGE[k] += v
        m[k] += v
    print(f"   [tok] {model} in={d['in']} out={d['out']} cache_r={d['cache_read']} "
          f"cache_w={d['cache_write']} | total in={USAGE['in']} out={USAGE['out']}")


def total_tokens():
    """Everything billed so far this run (cache reads/writes included)."""
    return USAGE["in"] + USAGE["out"] + USAGE["cache_read"] + USAGE["cache_write"]


def budget_room(estimated_tokens):
    """(fits, left) for a call estimated to bill `estimated_tokens` in total.
    MAX_RUN_TOKENS used to be checked only at the top of the loop, AFTER the fact: one
    author_and_run (up to CODER_MAX_OUTPUT_TOKENS=24576 output plus ~10k of cached
    system prompt and the evidence) could start with 1,000 tokens left and overshoot the
    ceiling by 30k+. Ask before the call, not after it."""
    if not config.MAX_RUN_TOKENS:
        return True, None
    left = config.MAX_RUN_TOKENS - total_tokens()
    return estimated_tokens <= left, left


# chars per token, MEASURED ch4 run (2026-09-27, _metrics.json, 20 steps): the per-step
# state is hex dumps / disassembly / addresses, which tokenize badly - 1.64..1.98
# chars/token (1.86 overall), NOT the ~3 assumed before. The cached system prompt +
# tool catalog (58.8k chars) billed 23,544 cache-write tokens = ~2.5 chars/token, NOT
# ~4. The old ratios under-estimated a call by ~40%, so MAX_RUN_TOKENS could be
# overshot. Use the low end of the measured range: this is a worst-case guard.
USER_CHARS_PER_TOKEN = 1.6
SYSTEM_CHARS_PER_TOKEN = 2.4


def estimate_call(user_chars, system_chars, max_out):
    """Worst case for one call, in the units total_tokens() counts (input + output +
    cache reads/writes, all summed): dynamic part at USER_CHARS_PER_TOKEN, system
    prompt at SYSTEM_CHARS_PER_TOKEN, and the FULL output ceiling, because a reply can
    use it."""
    return (int(user_chars / USER_CHARS_PER_TOKEN)
            + int(system_chars / SYSTEM_CHARS_PER_TOKEN) + int(max_out))


def usage_summary():
    lines = [f"calls={USAGE['calls']} input={USAGE['in']} output={USAGE['out']} "
             f"cache_read={USAGE['cache_read']} cache_write={USAGE['cache_write']}"]
    for mdl, v in USAGE["by_model"].items():
        lines.append(f"  {mdl}: calls={v['calls']} input={v['in']} output={v['out']} "
                     f"cache_read={v['cache_read']} cache_write={v['cache_write']}")
    for req, served in USAGE["served_by"].items():
        mism = {k: n for k, n in served.items() if not k.startswith(req)}
        tag = "  !! SERVED BY A DIFFERENT MODEL" if mism else ""
        lines.append(f"  served_by[{req}] = {served}{tag}")
    lines.append(f"  refusals={len(USAGE['refusals'])}"
                 + (f" {USAGE['refusals']}" if USAGE["refusals"] else ""))
    if USAGE.get("refusal_fallbacks"):
        lines.append(f"  refusal_fallbacks={USAGE['refusal_fallbacks']} "
                     "(refused top-tier calls rescued on the default model)")
    return "\n".join(lines)


# A Brain call is the ONLY irreplaceable step in the loop: everything else can be
# retried for free, but losing one means losing the whole run (there is no resume).
# Measured gap 2026-09-22: nothing retried and nothing was persisted, so a single
# 529/rate-limit/network blip destroyed a 40-step run mid-flight.
_TRANSIENT_MARKS = ("overloaded", "rate limit", "rate_limit", "429", "500", "502",
                    "503", "504", "529", "timeout", "timed out", "connection",
                    "temporarily", "apiconnection", "internalserver")


def _is_transient(e):
    """Prefer the HTTP status the SDK already parsed over grepping the message: a
    request_id or a quoted payload can easily contain '503' and trick a substring
    match into retrying a permanent 400 four times."""
    code = getattr(e, "status_code", None) or getattr(
        getattr(e, "response", None), "status_code", None)
    if isinstance(code, int):
        return code == 408 or code == 429 or code >= 500
    return any(t in f"{e.__class__.__name__}: {e}".lower() for t in _TRANSIENT_MARKS)


def _with_retry(fn, what):
    last = None
    for attempt in range(1, config.API_RETRIES + 1):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - classify, then re-raise or back off
            last = e
            msg = f"{e.__class__.__name__}: {e}"
            transient = _is_transient(e)
            if not transient or attempt == config.API_RETRIES:
                raise
            wait = config.API_BACKOFF * (2 ** (attempt - 1))
            print(f"   [api] {what} failed ({msg[:140]}) - retry "
                  f"{attempt}/{config.API_RETRIES - 1} in {wait:.0f}s")
            time.sleep(wait)
    raise last


def _provider(model):
    m = model.lower()
    if m.startswith("claude"):
        return "anthropic"
    if m.startswith(("gpt", "o1", "o3", "o4")):
        return "openai"
    return "ollama"


def _call_ollama(model, system, user):
    global LAST_STOP_REASON
    LAST_STOP_REASON = None
    r = ollama.chat(
        model=model,
        messages=[{"role": "system", "content": system},
                  {"role": "user", "content": user}],
        options={"num_ctx": config.NUM_CTX},
    )
    return r["message"]["content"]


_ANTHROPIC_CLIENT = None


def _anthropic_client():
    """One client for the whole run. A fresh anthropic.Anthropic() per call throws away
    the HTTP connection pool, so every single Brain call paid for a new TLS handshake -
    pure latency on a loop that makes 40+ of them."""
    global _ANTHROPIC_CLIENT
    if _ANTHROPIC_CLIENT is None:
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key or key == "chua_co":
            raise RuntimeError("ANTHROPIC_API_KEY not set (still placeholder) - "
                               "buy credit and put the key in .env")
        import anthropic
        _ANTHROPIC_CLIENT = anthropic.Anthropic(api_key=key)
    return _ANTHROPIC_CLIENT


_NO_PREFILL = set()   # models measured to reject assistant prefill

# Set after every Anthropic call. Measured in the first successful real run (ch2,
# 2026-09-22): TWO author_and_run steps came back as "solver produced NO output" when
# what actually happened was the script hitting CODER_MAX_OUTPUT_TOKENS mid-generation
# - 16384 output tokens burned each time, the most expensive kind of token, for a file
# that was then uploaded and run for nothing. stop_reason says so exactly.
LAST_STOP_REASON = None


def last_call_truncated():
    return LAST_STOP_REASON == "max_tokens"


def _call_anthropic(model, system, user, cache=False, prefill=None, max_tokens=None):
    client = _anthropic_client()
    if model in _NO_PREFILL:
        prefill = None
    if isinstance(system, list):
        sys_param = system                      # caller already set cache_control
    elif cache:
        sys_param = [{"type": "text", "text": system,
                      "cache_control": _cache_control()}]
    else:
        sys_param = system
    msgs = [{"role": "user", "content": user}]
    if prefill:
        msgs.append({"role": "assistant", "content": prefill})
    mx = max_tokens or config.MAX_OUTPUT_TOKENS

    def _do(messages):
        # STREAM, always. MEASURED ch8 run 4 step 27: a non-streaming messages.create
        # with max_tokens=24576 (the coder budget) raised ValueError "Streaming is
        # required for operations that may take longer than 10 minutes" - the SDK
        # refuses a large non-streaming request outright, so author_and_run (the
        # solver-writer) crashed EVERY time and the agent could not write a single
        # solver. Streaming lifts that ceiling and is otherwise identical; we still
        # return the whole text at the end, so nothing upstream changes.
        # The 1h/extended cache TTL is a beta: the "ttl" field in cache_control is
        # rejected unless this header is sent. Add it ONLY when CACHE_TTL is set, so a
        # default (5-min) run makes a byte-identical request to before.
        extra = ({"anthropic-beta": "extended-cache-ttl-2025-04-11"}
                 if config.CACHE_TTL else {})
        with client.messages.stream(model=model, max_tokens=mx, system=sys_param,
                                    messages=messages, extra_headers=extra) as st:
            for _ in st.text_stream:
                pass
            return st.get_final_message()

    try:
        resp = _do(msgs)
    except Exception as e:  # noqa: BLE001
        # Some models reject an assistant prefill outright (400). That is a capability
        # fact about the model, not a transient failure - remember it and retry once
        # without the prefill rather than letting one unsupported feature kill the run.
        if prefill and "prefill" in str(e).lower():
            _NO_PREFILL.add(model)
            print(f"   [api] {model} does not support assistant prefill - "
                  "retrying without it (remembered for this run)")
            resp = _do([{"role": "user", "content": user}])
            prefill = None
        else:
            raise
    global LAST_STOP_REASON
    LAST_STOP_REASON = getattr(resp, "stop_reason", None)
    _record_usage(model, getattr(resp, "usage", None))
    served = getattr(resp, "model", None) or "?"
    sb = USAGE["served_by"].setdefault(model, {})
    sb[served] = sb.get(served, 0) + 1
    # resp.model normally echoes the requested id (possibly a dated snapshot of it,
    # e.g. claude-opus-5-5-2026xxxx). Flag only when it is a DIFFERENT model family.
    if not served.startswith(model):
        print(f"   [api] !! requested {model} but response came from {served} "
              "(safeguard redirect?)")
    if LAST_STOP_REASON == "refusal":
        USAGE["refusals"].append({"requested": model, "served": served,
                                  "call": USAGE["calls"]})
        print(f"   [api] !! REFUSAL (stop_reason=refusal) from {served} on call "
              f"#{USAGE['calls']} - this is a SAFEGUARD block, not the Brain being stuck")
    if LAST_STOP_REASON == "max_tokens":
        print(f"   [tok] !! output hit the {mx}-token ceiling - the reply is CUT OFF")
    body = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
    return (prefill + body) if prefill else body


def _call_openai(model, system, user, max_tokens=None):
    key = os.environ.get("OPENAI_API_KEY", "")
    if not key or key == "chua_co":
        raise RuntimeError("OPENAI_API_KEY not set (still placeholder) - buy credit and put the key in .env")
    import openai
    client = openai.OpenAI(api_key=key)
    kw = {"model": model,
          "messages": [{"role": "system", "content": system},
                       {"role": "user", "content": user}]}
    if max_tokens:
        kw["max_completion_tokens"] = max_tokens
    resp = client.chat.completions.create(**kw)
    return resp.choices[0].message.content


def call_model(user, system=SYSTEM_PROMPT, role="logic", tier="default", cache=False,
               prefill=None, max_tokens=None):
    """One Brain, any provider. Model name decides the provider:
    claude-* -> Anthropic, gpt-*/o* -> OpenAI, else -> local Ollama.
    cache=True marks the system prefix as a cache prefix (Anthropic).
    max_tokens overrides the per-role default (used by the controller's strict retry
    to escape a truncated reply)."""
    model = (config.LOGIC_MODEL if role == "logic" else config.CODER_MODEL)[tier]
    provider = _provider(model)
    if max_tokens is None:
        max_tokens = config.CODER_MAX_OUTPUT_TOKENS if role == "coder" else config.MAX_OUTPUT_TOKENS
    what = f"{role}/{tier} ({model})"
    # Reset FIRST. It is a module global read by last_call_truncated(), and both the
    # controller and the script-writer use it: a controller reply that hit max_tokens
    # used to leave the flag set, which then skipped author_script's "is this actually
    # python?" guard on the NEXT coder reply, and made ghidra_script refuse a script
    # that was never truncated. Providers other than Anthropic never set it at all.
    global LAST_STOP_REASON
    LAST_STOP_REASON = None
    if provider != "anthropic" and isinstance(system, list):
        system = "\n\n".join(b.get("text", "") for b in system)
    if provider == "anthropic":
        out = _with_retry(lambda: _call_anthropic(model, system, user, cache=cache,
                                                  prefill=prefill, max_tokens=max_tokens), what)
        # SAFEGUARD FALLBACK (refusal). MEASURED ch7 FlareCalc: 12/12 stop_reason=refusal
        # came from the TOP model (opus); the default model (sonnet) refused 0 times on
        # the same run. A refusal returns an EMPTY reply, so the caller (decide/
        # author_script) then sees a malformed action / empty solver and the whole
        # top-tier endgame is burned on identical re-asks. When the model that just
        # refused is NOT the default model, retry the SAME call once on the default
        # model, which does not refuse this content. Only a genuine refusal triggers
        # this; a normal reply returns immediately above.
        if LAST_STOP_REASON == "refusal":
            fb = (config.LOGIC_MODEL if role == "logic" else config.CODER_MODEL)["default"]
            if fb and fb != model and _provider(fb) == "anthropic":
                print(f"   [api] refusal from {model} -> retrying THIS call on the "
                      f"fallback model {fb} (measured: it does not refuse this content)")
                USAGE["refusal_fallbacks"] = USAGE.get("refusal_fallbacks", 0) + 1
                out = _with_retry(lambda: _call_anthropic(
                    fb, system, user, cache=cache, prefill=prefill,
                    max_tokens=max_tokens), f"{role}/fallback ({fb})")
        return out
    if provider == "openai":
        return _with_retry(lambda: _call_openai(model, system, user, max_tokens=max_tokens), what)
    return _with_retry(lambda: _call_ollama(model, system, user), what)


def extract_code(text):
    """Return runnable python, tolerant of how the model fenced it. Never lets a
    stray ``` line reach exploit.py (that caused SyntaxError on line 1)."""
    if not text:
        return ""
    t = text.strip()
    # first fenced block, any info string, CRLF/trailing-space tolerant
    m = re.search(r"```[^\n]*\r?\n(.*?)```", t, re.DOTALL)
    if m:
        return m.group(1).strip("\r\n")
    # no clean pair: drop any leftover fence lines so it still parses
    lines = [ln for ln in t.splitlines() if not ln.lstrip().startswith("```")]
    return "\n".join(lines).strip("\r\n")


def _repair_json_str(s):
    """Escape raw control chars that appear INSIDE a JSON string literal.

    MEASURED ch8 run 4 step 34: the controller (opus) put a multi-line frida/ghidra
    script into an args value with LITERAL newlines - which is invalid JSON, so
    json.loads and the balanced-brace scan both failed, the whole action was lost, and
    after 3 such tries the run stopped at the top tier. An LLM writing a multi-line
    value with real newlines/tabs is exactly the shape the muscle needs (win_frida,
    ghidra_script, author_and_run all take multi-line `script`/`java`), so repair it
    instead of throwing it away: walk the text and, while inside a string, replace a
    raw newline/carriage-return/tab with its escaped form. Structural whitespace
    (outside strings) is left untouched."""
    out = []; instr = False; esc = False
    for ch in s:
        if instr:
            if esc:
                out.append(ch); esc = False; continue
            if ch == "\\":
                out.append(ch); esc = True; continue
            if ch == '"':
                out.append(ch); instr = False; continue
            if ch == "\n":
                out.append("\\n"); continue
            if ch == "\r":
                out.append("\\r"); continue
            if ch == "\t":
                out.append("\\t"); continue
            out.append(ch); continue
        if ch == '"':
            instr = True
        out.append(ch)
    return "".join(out)


def _loads(t):
    """json.loads, then one repair attempt for raw control chars inside strings."""
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        try:
            return json.loads(_repair_json_str(t))
        except json.JSONDecodeError:
            return None


def _first_json_object(s):
    """Balanced-brace scan that IGNORES braces inside string literals."""
    depth = 0; start = -1; instr = False; esc = False
    for i, ch in enumerate(s):
        if instr:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                instr = False
            continue
        if ch == '"':
            instr = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start != -1:
                    obj = _loads(s[start:i + 1])
                    if obj is not None:
                        return obj
                    start = -1
    return None


def extract_json(text):
    if not text:
        return None
    t = text.strip()
    m = re.search(r"```(?:json)?\s*\r?\n(.*?)```", t, re.DOTALL | re.IGNORECASE)
    if m:
        t = m.group(1).strip()
    obj = _loads(t)
    return obj if obj is not None else _first_json_object(t)


# CONTROLLER_SYSTEM deliberately STARTS with the same bytes as CODER_SYSTEM and adds
# the controller's own rules at the END. Anthropic prefix caching matches from byte 0,
# so prepending the controller paragraph (as this did until 2026-09-23) gave the two
# roles no shared prefix at all and each sparse author_and_run call paid a fresh cache
# WRITE on ~30KB of identical text.
CONTROLLER_RULES = (
    "=== YOU ARE THE ACTION CONTROLLER ===\n"
    "Your entire reply MUST be a single JSON object and NOTHING else - no analysis, no "
    "prose, no markdown fence, no text before or after. Put any brief reasoning inside "
    "the \"why\" field only.\n"
    "Reply with exactly ONE JSON object, one of:\n"
    '  {"tool": "<name>", "args": { ... }, "why": "<short reason>", "note": "<optional>"}\n'
    '  {"stop": "<why you cannot proceed / need a human>"}\n'
    "Pick a tool from the list; fill args as described; if two steps led nowhere or no "
    "tool can help, STOP rather than guess.\n"
    "HARD LIMITS ON EVERY REPLY: the JSON object is the WHOLE reply; `why` <= 200 "
    "chars; `note` <= 400 chars. Long content (Java, JavaScript, python, an address "
    "list) belongs inside `args`, never inside `why`/`note` - a reply that runs past "
    "the output ceiling is thrown away whole and the step is paid for twice.\n"
    "note (optional, strongly encouraged): this is your ONLY working memory. You see "
    "just the last few observations, so anything you read earlier is GONE unless you "
    "wrote it here. Prefer recording the MEASURED DETAIL you just learned and would "
    "otherwise have to go and read again - exact constants, formulas, field names, "
    "function signatures, file paths, which file holds what - over recording your "
    "plan. A plan is cheap to think up again; a constant you already dug out of a "
    "disassembly is expensive to re-derive, and re-reading it costs a whole step. "
    "Good: \"LCG: state=(mult*state+inc)%mod, params from sha256 chain of "
    "sha256(hostname); primes are 256-bit\". Weak: \"need to find the LCG params "
    "next\". Record SETTLED facts, not a multi-step derivation or a table of "
    "hypotheses you are still working through - that work belongs inside a solver "
    "(author_and_run), which prints the answer. Saved under ASSUMED and shown on every "
    "later step. Omit it only if you measured nothing new."
)

CONTROLLER_SYSTEM = CODER_SYSTEM + "\n\n" + CONTROLLER_RULES


# Everything that is constant for a whole RUN but used on EVERY step: the measured
# environment and the tool catalog. Anthropic allows several cache breakpoints, so the
# truly static half (identity, discipline, playbook, standing facts) stays cacheable
# ACROSS runs while this half is cached WITHIN a run. Before 2026-09-22 the catalog sat
# in the per-step user message: 2775 tokens re-sent 40 times for text that never moved.
RUN_CONTEXT = ""

# The raw text of the last controller reply. MEASURED ch8 run 1, steps 47-48: the run
# ENDED with "controller returned no valid action" twice and nobody - not the log, not
# the ledger, not the human reading it afterwards - ever saw what the model actually
# said. A parse failure you cannot see is a parse failure you cannot fix.
LAST_RAW = ""


def set_run_context(env_facts, catalog_text):
    """Called once by solve() after probing the VM."""
    global RUN_CONTEXT
    parts = []
    if catalog_text:
        parts.append("=== AVAILABLE TOOLS ===\n" + catalog_text)
    if env_facts:
        parts.append(env_facts)
    RUN_CONTEXT = "\n\n".join(parts)


def add_run_block(title, text):
    """Append a named block to the cached RUN_CONTEXT (after env facts, so the solver
    writer sees it too)."""
    global RUN_CONTEXT
    if text:
        RUN_CONTEXT = (RUN_CONTEXT + "\n\n" if RUN_CONTEXT else "") + (
            f"=== {title} ===\n" + text)


def add_run_notes(text):
    """Append run-start MEMORY notes (tools.seed_recall) to RUN_CONTEXT. It sits AFTER
    the environment facts, so the solver-writer (_coder_run_context) sees them too, and
    in the cached run block, so they cost one cache write per run, not per step."""
    global RUN_CONTEXT
    if text:
        RUN_CONTEXT = (RUN_CONTEXT + "\n\n" if RUN_CONTEXT else "") + (
            "=== PAST EXPERIENCE: technique notes matching THIS input's shape "
            "(auto-recalled at run start) ===\n"
            "Distilled from earlier CTF/FLARE-On work. Reason with them before choosing "
            "a line of attack - they are how this KIND of target is usually cracked, not "
            "the answer. recall(<keywords>) again once triage/decompile shows more.\n"
            + text)


def _cache_control():
    """The cache_control marker for a cached system block. Default = plain 5-minute
    ephemeral (unchanged). config.CACHE_TTL (e.g. "1h") opts into an extended TTL so the
    cached prefix survives slow steps instead of expiring and re-paying the write."""
    cc = {"type": "ephemeral"}
    if config.CACHE_TTL:
        cc["ttl"] = config.CACHE_TTL
    return cc


def _system_blocks(static_text, run_text):
    # BOTH blocks are constant for the whole run: the static tier-1 prompt, and
    # RUN_CONTEXT (env facts + tool catalog + run-start memory seed + pinned notes, all
    # set once in solve()/orchestrator, never per step - the per-step change is the USER
    # message, not the system). MEASURED ch8 run 15: 5 cache-WRITE events in 60 steps
    # (~110k write tokens) because a >5min step (Ghidra/frida/install) let the 5-min
    # cache lapse and both blocks were rewritten. With CACHE_TTL=1h each block is written
    # ~once instead. (An earlier comment wrongly said RUN_CONTEXT changes every step.)
    cc = _cache_control()
    blocks = [{"type": "text", "text": static_text, "cache_control": cc}]
    if run_text:
        blocks.append({"type": "text", "text": run_text, "cache_control": cc})
    return blocks


_DECIDE_PREAMBLE = (
    "Based ONLY on the current state below, choose the SINGLE next action. One "
    "measurable step, then you will be called again. Reply with exactly one JSON "
    "object, in the form given in your instructions - nothing else.\n\n")


def _ledger_blocks(parts, image, tail_extra):
    """User content with the stable head cached (config.CACHE_LEDGER).

    parts = Workspace.render_state_parts(): (head_pieces, tail). One text block per
    head piece (ARTIFACTS, then one per KNOWN fact) and a cache breakpoint on the last
    one. KNOWN only grows at its end, so the previous step's breakpoint position is
    still a block boundary this step: the API's lookback (it checks earlier block
    boundaries, ~20 back) finds that cached prefix and bills it as a cache READ; only
    the facts added since are written. Plain 5-minute TTL on purpose - steps are
    seconds apart, and a longer TTL costs 2x on every write. The text the model reads
    is byte-identical to the plain-string prompt; only the block boundaries differ."""
    head, tail = parts
    blocks = [{"type": "text", "text": _DECIDE_PREAMBLE + head[0]}]
    blocks += [{"type": "text", "text": p} for p in head[1:]]
    blocks[-1]["cache_control"] = {"type": "ephemeral"}
    if image:            # after the cached head: a one-shot image must not break it
        blocks.append({"type": "image", "source": {
            "type": "base64", "media_type": image.get("media_type", "image/png"),
            "data": image["data"]}})
    blocks.append({"type": "text", "text": tail + tail_extra})
    return blocks


def decide(state_text, catalog_text=None, strict=False, tier="default", image=None,
           correction="", parts=None):
    """CONTROLLER: choose the single next action from the ledger (one Brain call).
    parts (optional) = Workspace.render_state_parts() for the same state: when given
    and the model is Anthropic, the stable head of the state is sent as a cached
    prefix (see _ledger_blocks)."""
    strict_note = ""
    if strict:
        cut = last_call_truncated()
        strict_note = ("\nYOUR LAST REPLY WAS NOT VALID. Reply with NOTHING but a "
                       "single JSON object, no prose, no code fence.\n")
        if cut:
            strict_note += ("It was CUT OFF because it ran too long - you were writing "
                            "analysis into `why`/`note`. Do NOT do that here: emit the "
                            "JSON action FIRST, keep `note` under 200 chars, and put any "
                            "long derivation inside a solver via author_and_run instead.\n")
    tail_extra = f"{strict_note}" + (("\n" + correction + "\n") if correction else "")
    user = _DECIDE_PREAMBLE + f"{state_text}" + tail_extra
    # Everything that does not change between steps (the reply format, the limits, the
    # note guidance) now lives in the CACHED system block above: it was ~1.9KB of
    # byte-identical text sitting in the UNCACHED user message, re-sent on every single
    # step of every run.
    # image (optional, single-shot): a picture a tool just extracted/rendered, attached
    # ONLY when the resolved model is Anthropic (Claude vision content-block format is
    # provider-specific; openai/ollama would need a different shape - skip it there rather
    # than send a malformed request).
    model = config.LOGIC_MODEL[tier]
    if (parts and config.CACHE_LEDGER and _provider(model) == "anthropic"
            and "".join(parts[0]) + parts[1] == state_text):
        content = _ledger_blocks(parts, image, tail_extra)
    elif image and _provider(model) == "anthropic":
        content = [
            {"type": "image", "source": {"type": "base64",
                                         "media_type": image.get("media_type", "image/png"),
                                         "data": image["data"]}},
            {"type": "text", "text": user},
        ]
    else:
        content = user
    run_part = RUN_CONTEXT
    if not run_part and catalog_text:      # standalone/testing use without set_run_context
        run_part = "=== AVAILABLE TOOLS ===\n" + catalog_text
    # NO assistant prefill here. It was added 2026-09-22 as a cheap way to force JSON
    # and it broke the very first real run: claude-sonnet-5 / claude-opus-5 answer
    # `400 invalid_request_error: This model does not support assistant message
    # prefill. The conversation must end with a user message.` The plumbing below still
    # handles prefill (and now degrades instead of dying if a model refuses it), but
    # the controller does not use it. Invalid JSON is handled by the `strict` retry.
    max_out = config.CONTROLLER_RETRY_MAX_TOKENS if strict else None
    raw = call_model(content, system=_system_blocks(CONTROLLER_SYSTEM, run_part),
                     role="logic", tier=tier, cache=True, max_tokens=max_out)
    global LAST_RAW
    LAST_RAW = raw or ""
    return extract_json(raw)


def author_script(goal, evidence, host="kali", tier="default"):
    """WORKER: write a self-contained python solver (one Brain call).
    Static discipline/playbook live in the cached system prefix; only the goal
    and evidence are dynamic."""
    user = (
        f"Task: write ONE self-contained Python script for this goal:\n"
        f"GOAL: {goal}\n\n"
        "OUTPUT RULES (MANDATORY - a run with empty stdout is a FAILURE):\n"
        "- The script MUST call print() on EVERY code path.\n"
        "- print() each decoded/intermediate value AND the final decisive value "
        "(the flag or key result), each with a short label.\n"
        "- Never rely on the interpreter echoing a bare expression - only explicit "
        "print() reaches stdout.\n"
        "- Wrap the whole body in try/except Exception as e: and in the except, "
        "print the FULL traceback (import traceback; traceback.print_exc()) so any "
        "error is visible instead of silent.\n"
        "- Do NOT run dis.dis() on, or exec, marshalled bytecode from a DIFFERENT "
        "Python version. Measured 2026-09-22: marshal.loads() returns a code object "
        "(so it looks fine) and dis.dis() then dies with `tuple index out of range`, "
        "because the stdlib only carries the running version's opcode table. Read "
        "co_consts/co_names statically, or use xdis, which has a table per version: "
        "`from xdis.unmarshal import load_code` with "
        "`xdis.magics.magic2int(xdis.magics.magics['3.12.0'])`.\n\n"
        f"Runs on the {'Windows' if host == 'windows' else 'Kali'} box in the same "
        f"working dir as any target file (use bare filenames). Hardcode needed "
        f"constants from the evidence; do not reference variables that exist only "
        f"elsewhere.\n\n=== EVIDENCE ===\n{evidence}\n=== END EVIDENCE ===\n\n"
        "Reply with ONLY the script, in exactly one ```python code block. Do NOT "
        "write a sentence before it. You cannot test anything interactively and "
        "there is no next turn to refine in: this reply IS the script that gets run, "
        "so put any uncertainty INSIDE the code as try/except with prints, not "
        "outside it as a plan."
    )
    # the coder gets the measured environment too (what is already importable, which
    # pip to use) - the tool catalog is deliberately left out: it writes a script, it
    # does not call tools.
    code = extract_code(call_model(
        user, system=_system_blocks(CODER_SYSTEM, _coder_run_context()),
        role="coder", tier=tier, cache=True))
    # Measured across the ch2 and ch6 runs (2026-09-23): 4 of 9 coder replies opened
    # with prose - "Let me verify the xdis API first...", "Let's test the pipeline
    # interactively..." - and, with no fenced block to find, extract_code handed that
    # prose straight on as the script. Each one cost the controller a whole step and a
    # stall. Retry ONCE here instead, where we can say exactly what went wrong; the
    # caller only ever sees runnable code or a clean failure.
    if code.strip() and not last_call_truncated():
        try:
            ast.parse(code)
        except SyntaxError:
            print("   [coder] reply was not valid python (prose?) - retrying once")
            code = extract_code(call_model(
                "YOUR PREVIOUS REPLY WAS REJECTED: it was not valid Python. It began "
                f"with: {code.strip()[:160]!r}\n\nThere is no interactive session and "
                "no follow-up turn. Reply with NOTHING but one ```python code block.\n\n"
                + user,
                system=_system_blocks(CODER_SYSTEM, _coder_run_context()),
                role="coder", tier=tier, cache=True))
    return code


def _coder_run_context():
    """Only the environment half of RUN_CONTEXT (skip the tool catalog)."""
    if not RUN_CONTEXT:
        return ""
    i = RUN_CONTEXT.find("ENVIRONMENT FACTS")
    return RUN_CONTEXT[i:] if i >= 0 else ""
