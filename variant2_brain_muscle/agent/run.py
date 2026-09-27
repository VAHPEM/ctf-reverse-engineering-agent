# -*- coding: utf-8 -*-
"""Entry point:  python3 -m agent.run <file> [more files...]"""
import sys
from .orchestrator import solve

if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)   # live output even when piped to tee
    if len(sys.argv) < 2:
        print("usage: python3 -m agent.run <file> [more files...] [--resume [state.json]]")
        sys.exit(1)
    argv = sys.argv[1:]
    resume = None
    if "--resume" in argv:                     # --resume [path], default config.STATE_DUMP
        i = argv.index("--resume")
        argv.pop(i)
        from .config import STATE_DUMP
        resume = STATE_DUMP
        if i < len(argv) and not argv[i].startswith("-") and argv[i].endswith(".json"):
            resume = argv.pop(i)
    if not argv:
        print("usage: python3 -m agent.run <file> [more files...] [--resume [state.json]]")
        sys.exit(1)
    # Fail FAST and CLEARLY on a bad input path, before any VM work. Otherwise a path
    # that does not exist (e.g. a wrong relative dir) used to register as a phantom
    # artifact and every tool then crashed on it one step at a time. A directory is a
    # valid input (its files are ingested); anything that is neither a file nor a dir
    # is a typo/wrong cwd.
    import os
    missing = [p for p in argv if not os.path.exists(p)]
    if missing:
        print("input path(s) not found (check the path is relative to THIS directory, "
              "i.e. variant2_brain_muscle - challenges live at ../challenges/):")
        for p in missing:
            print(f"  - {p}")
        sys.exit(1)
    ws = solve(argv, resume=resume)
    print("\n=== RESULT ===")
    print("flag:", ws.flag if ws.flag else "(not found)")
    from .reasoner import usage_summary
    print("\n=== TOKEN USAGE ===\n" + usage_summary())
    from .metrics import summary as metrics_summary
    print("\n=== METRICS (step-0 measurement) ===\n" + metrics_summary())
