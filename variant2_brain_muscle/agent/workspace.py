# -*- coding: utf-8 -*-
"""Workspace = the multi-artifact case folder + the evidence Ledger.

The Ledger (KNOWN / ASSUMED / RULED_OUT) is the single source of truth the
Orchestrator reasons over. Tools write to it; the controller reads it.
"""
import os
import re
import hashlib
from dataclasses import dataclass, field

from . import config

_HDR = re.compile(r"^\[.*\]$")   # tool header lines like "[file 0..4000/9999]" carry no information


@dataclass
class Artifact:
    name: str                 # short handle used in prompts/actions
    local_path: str           # path in this sandbox
    kind: str = "unknown"     # e.g. elf/pe/python_source/pdf/pcap/...
    remote_path: str = ""     # path on the VM once uploaded
    notes: dict = field(default_factory=dict)  # scratch: text, hex, strings, decompiled...


class Ledger:
    """Three-column assumption ledger (playbook R3)."""
    def __init__(self):
        self.known = []        # measured, reproducible
        self.pinned = set()    # facts that must never be trimmed (seeded task/method facts)
        self.assumed = []      # believed, not yet verified
        self.ruled_out = []    # excluded, with evidence

    @staticmethod
    def _fit(text, limit, one_line=False):
        """Ledger lines are re-sent uncached on EVERY step, so one unbounded line is
        paid for dozens of times (measured: a 1800-char Ghidra stack trace)."""
        t = " ".join(str(text).split()) if one_line else str(text)
        if len(t) <= limit:
            return t
        return t[:limit] + f" ...[+{len(t) - limit} chars cut from this ledger line]"

    def know(self, fact, pin=False):
        """pin=True marks a seeded task/environment/method fact: it is exempt from
        trimming, so the prompt-size guard can never evict the things the Brain needs
        on EVERY step (flag format, what is installed, how to install)."""
        fact = self._fit(fact, config.FACT_MAX_CHARS) if fact else fact
        if not fact or fact in self.known:
            if fact and pin:
                self.pinned.add(fact)
            return
        self.known.append(fact)
        if pin:
            self.pinned.add(fact)
        over = len(self.known) - config.KNOWN_CAP
        if over > 0:                      # drop the OLDEST unpinned facts only
            kept, dropped = [], 0
            for f in self.known:
                if dropped < over and f not in self.pinned:
                    dropped += 1
                    continue
                kept.append(f)
            self.known = kept

    def assume(self, fact):
        if fact and fact not in self.assumed:
            self.assumed.append(fact)

    def rule_out(self, fact):
        fact = self._fit(fact, config.RULED_OUT_MAX_CHARS, one_line=True) if fact else fact
        if fact and fact not in self.ruled_out:
            self.ruled_out.append(fact)
            if len(self.ruled_out) > config.RULED_OUT_CAP:
                self.ruled_out = self.ruled_out[-config.RULED_OUT_CAP:]

    @staticmethod
    def _words(s):
        return set(re.findall(r"\w+", re.sub(r"^\[s\d+\]\s*", "", s).lower()))

    def assume_note(self, text, sim=0.7):
        """B: the Brain's OWN conclusion/hypothesis (its reasoning is otherwise forgotten
        between steps). Skips near-duplicates (word-set Jaccard >= sim); keeps the newest
        ASSUMED_CAP entries. Returns True if stored."""
        w = self._words(text)
        if not w:
            return False
        for old in self.assumed:
            ow = self._words(old)
            if ow and len(w & ow) / len(w | ow) >= sim:
                return False
        self.assumed.append(text)
        if len(self.assumed) > config.ASSUMED_CAP:
            self.assumed = self.assumed[-config.ASSUMED_CAP:]
        return True

    def render(self):
        def block(title, items):
            if not items:
                return f"{title}: (none)"
            return title + ":\n" + "\n".join(f"  - {x}" for x in items)
        return "\n".join([
            block("KNOWN (measured)", self.known),
            block("ASSUMED (unverified)", self.assumed),
            block("RULED OUT (with evidence)", self.ruled_out),
        ])


_MAX_INGEST_FILES = 60   # a challenge FOLDER is small; a huge dir is almost certainly wrong input


def _expand_inputs(paths):
    """Flatten the CLI paths into individual FILES. A real CTF/RE challenge is usually a
    FOLDER of files (binary + pcap + memory dump + disk/firmware image + README), so a
    directory argument is walked recursively and every file inside is ingested - instead
    of registering the folder itself as one opaque 'artifact'. Plain files pass through.
    A non-existent path is kept so the error surfaces clearly downstream. Archives
    (.zip/.7z/.tar/...) are NOT auto-extracted here (many are password-protected); they
    are ingested as-is, surveyed, and unpacked by the `extract` muscle tool. Capped at
    _MAX_INGEST_FILES to avoid ingesting a stray giant directory."""
    out, seen = [], set()
    for raw in paths:
        if os.path.isdir(raw):
            # Mirror the folder's layout: a file at <dir>/data/x.bin keeps the relative
            # name "data/x.bin", so it uploads to samples/data/x.bin and a program run
            # from samples/ (the CWD) resolves its relative opens (./data/x.bin). The
            # folder's ROOT maps to samples/ itself, so a sibling pcap stays a sibling.
            for root, dirs, files in os.walk(raw):
                dirs[:] = [d for d in dirs if d not in (".git", "__MACOSX", ".svn")]
                for fn in sorted(files):
                    if fn in (".DS_Store", "Thumbs.db"):
                        continue
                    fp = os.path.join(root, fn)
                    if fp not in seen and os.path.isfile(fp):
                        seen.add(fp)
                        rel = os.path.relpath(fp, raw).replace(os.sep, "/")
                        out.append((fp, rel))
        else:
            if raw not in seen:
                seen.add(raw)
                out.append((raw, os.path.basename(raw.rstrip("/"))))  # file, or missing path
    if len(out) > _MAX_INGEST_FILES:
        print(f"   [ingest] {len(out)} files found; capping at {_MAX_INGEST_FILES} "
              "(pass specific files if the challenge needs more)")
        out = out[:_MAX_INGEST_FILES]
    return out



class Workspace:
    def __init__(self, files):
        self.artifacts = {}          # name -> Artifact
        self.ledger = Ledger()
        self.flag = None
        self.history = []            # list of (tool, args, summary) for trace/anti-loop
        self.seen_sigs = {}          # inspection signature -> step it was last made.
        # MUST forget on the same MEMORY_SPAN as absorb(). Measured ch6 run 4 step 28:
        # absorb() had forgotten the lines (novel=3073, i.e. "new to you now") while
        # seen_sigs still said "redundant", so a genuinely useful re-read of material
        # long gone from context was scored a stall. The two halves of the same
        # judgement must share the same notion of "recently".
        self.observations = []       # rolling (label, text) the Brain just saw
        self.strategic_nudge = ""    # a "you are stuck - change KIND of approach" line,
                                     # set at a stall and cleared the moment the run moves
                                     # again. Shown at the TOP of the state so it is the
                                     # first thing the next decision sees (a MEASURED
                                     # intervention beats a standing hint the Brain skims).
        self.seen_lines = {}         # blake2b-8 of each line shown -> step it was shown
        self.step = 0                # set by the orchestrator each step
        self.last_image = None    # one-shot {"media_type","data"} attached to the NEXT decide() call
        self.ghidra_cache = {}   # bare VM filename -> {"ghidra_overview","ghidra_program","ghidra_nfuncs"}
        # for pe_overview/decompile targets that are NOT a registered artifact (a file
        # the Brain made directly on the VM via run_cmd/run_script/author_and_run)
        for local_path, rel_name in _expand_inputs(files):
            self.add_artifact(local_path, name=rel_name)

    def add_artifact(self, local_path, kind="unknown", name=None):
        """Register a file. Two different files with the SAME basename (common in
        nested archives) used to silently overwrite each other in this dict - the
        second one won and the first became unreachable. Disambiguate instead."""
        base = name or os.path.basename(local_path)
        name, n = base, 1
        while name in self.artifacts and self.artifacts[name].local_path != local_path:
            n += 1
            root, dot, ext = base.partition(".")
            name = f"{root}~{n}{dot}{ext}"
        self.artifacts[name] = Artifact(name=name, local_path=local_path, kind=kind)
        return name

    def absorb(self, text):
        """A: return how many chars of lines in `text` never appeared in any earlier tool
        output (and remember them). Deterministic $0 measure of NEW INFORMATION; empty,
        duplicate or re-read output scores ~0."""
        novel = 0
        for ln in (text or "").splitlines():
            k = " ".join(ln.split()).lower()
            if len(k) < 4 or _HDR.match(k):
                continue
            h = hashlib.blake2b(k.encode("utf-8", "replace"), digest_size=8).hexdigest()
            last = self.seen_lines.get(h)
            if last is None or (self.step - last) > config.MEMORY_SPAN:
                novel += len(k)     # never seen, or seen so long ago it is out of context
            self.seen_lines[h] = self.step
        return novel

    def restore(self, dump):
        """Rebuild a run's memory from a _run_state.json written by an earlier run.
        Restores the three ledger columns, the action history, and the
        novelty/redundancy bookkeeping - without the last two, a resumed run would
        score every re-read as fresh progress and happily loop."""
        led = self.ledger
        for f in dump.get("known", []):
            # NOT pinned: know() only ever trims UNPINNED facts, so pinning every
            # restored fact disabled KNOWN_CAP for the rest of the run - and KNOWN is
            # in the uncached user message, re-sent in full on every Brain call.
            led.know(f)
        led.assumed = list(dump.get("assumed", []))
        led.ruled_out = list(dump.get("ruled_out", []))
        self.history = [(h.get("tool", "?"), h.get("args", ""), h.get("summary", ""))
                        for h in dump.get("history", [])]
        # REBASE the step numbers. They are from the PREVIOUS run (say 30-40) while the
        # resumed run starts again at step 1, and absorb()/redundancy both test
        # `self.step - last <= MEMORY_SPAN`. With raw numbers that difference is
        # NEGATIVE for every restored line, i.e. "you just saw this" forever: a resumed
        # run scored ~0 novelty on every step, took two stalls, escalated to the top
        # tier, took two more and stopped - within about four steps, every time.
        base = int(dump.get("step") or 0)
        def _rebase(v):
            try:
                return min(0, int(v) - base)      # <=0: recent stays recent, old goes old
            except (TypeError, ValueError):
                return -10 ** 6
        seen = dump.get("seen_lines", {})
        self.seen_lines = ({h: _rebase(v) for h, v in seen.items()}
                           if isinstance(seen, dict) else {h: -10 ** 6 for h in seen})
        sigs = dump.get("seen_sigs", {})
        self.seen_sigs = ({(tuple(eval(k)) if isinstance(k, str) else k): _rebase(v)
                           for k, v in sigs.items()} if isinstance(sigs, dict)
                          else {tuple(x): -10 ** 6 for x in sigs})
        return len(led.known), len(self.history)

    def observe(self, label, text, cap=None, keep=3):
        """Remember what a tool just surfaced so the Brain isn't blind next step."""
        if not text:
            return
        self.observations.append((label, text[:cap or config.OBS_CAP_NEWEST]))
        self.observations = self.observations[-keep:]

    def render_state(self, minimal=False):
        arts = "\n".join(
            f"  - {a.name}  [kind={a.kind}]"
            + (f"  remote={a.remote_path}" if a.remote_path else "")
            for a in self.artifacts.values()
        ) or "  (none)"
        recent = "\n".join(
            f"  {i+1}. {t}({a}) -> {s}" for i, (t, a, s) in enumerate(self.history[-8:])
        ) or "  (nothing done yet)"
        # Taper by age: the newest observation is what the next decision turns on,
        # the older ones are context. Sending all three at full 3500 chars cost ~2800
        # tokens EVERY step; tapering keeps the decisive one intact and cuts roughly
        # 1200 tokens/step. Anything trimmed is still reachable with peek/read_file.
        caps = [config.OBS_CAP_NEWEST, *config.OBS_CAP_OLDER]
        items = list(reversed(self.observations))          # newest first
        shown = []
        for i, (lbl, txt) in enumerate(items):
            cap = caps[i] if i < len(caps) else 500
            body = txt if len(txt) <= cap else (
                txt[:cap] + f"\n...[{len(txt) - cap} more chars trimmed as this "
                            "observation ages - re-read it with peek/read_file if "
                            "you still need it]")
            shown.append(f"[{lbl}]\n{body}")
        obs = "\n\n".join(reversed(shown)) or \
            "  (nothing observed yet - use peek/triage to look)"
        if minimal:
            # Last-resort prompt after the controller failed to emit JSON twice. The
            # full state (12KB of observations) is the most likely thing that pushed it
            # into writing an essay; strip it to the decisions, keep the facts.
            nudge = (f"=== !! STUCK - CHANGE APPROACH ===\n{self.strategic_nudge}\n\n"
                     if self.strategic_nudge else "")
            return (
                nudge +
                "=== ARTIFACTS ===\n" + arts + "\n\n"
                "=== KNOWN (measured, newest last) ===\n"
                + "\n".join(f"  - {x}" for x in self.ledger.known[-12:]) + "\n\n"
                "=== RECENT ACTIONS ===\n" + recent + "\n\n"
                "(Observations were left out of this prompt on purpose. Choose the next "
                "action from the facts above and reply with ONE JSON object.)"
            )
        nudge = (f"=== !! STUCK - CHANGE APPROACH ===\n{self.strategic_nudge}\n\n"
                 if self.strategic_nudge else "")
        return (
            nudge +
            "=== ARTIFACTS ===\n" + arts + "\n\n"
            "=== LEDGER ===\n" + self.ledger.render() + "\n\n"
            "=== RECENT OBSERVATIONS (what you just saw; do not re-read what is "
            "still printed here in full - a block marked as trimmed IS worth "
            "re-reading with peek/read_file) ===\n" + obs + "\n\n"
            "=== RECENT ACTIONS ===\n" + recent
        )
