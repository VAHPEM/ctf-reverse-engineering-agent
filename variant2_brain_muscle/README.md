# Variant 2 — One Brain + one Muscle (agent loop)

The current, actively used architecture. A SINGLE strong model (Brain) makes every
decision, writes every command/script, reads output, and concludes. MUSCLE is a dumb
executor: it runs tools/VMs and returns raw, structured slices — it never concludes.
Canonical think → act → observe loop over a compressed Ledger
(KNOWN / ASSUMED / RULED-OUT), with $0 code guards (budget, stall=2, stop-don't-guess).

**Status:** the active, proven design — tested and used in practice on
**FLARE-On 12 (challenges 1–8)** and **FLARE-On 13 (challenges 1–9)**. It costs more API
tokens than variant 1 but needs little local compute.

See the [repo root README](../README.md) for full setup (dependencies, VM tooling, AI
models, `.env`, and configuring flag detection per CTF) and the complete tool catalog.

Run (from this folder):
    python3 -m agent.run <path-to-file>          # e.g. ../challenges/09_neonoutrun
    MAX_STEPS=40 python3 -m agent.run <path>      # raise the per-run step budget
    python3 -m agent.run <path> --resume          # resume from the last state dump

Shared secrets live at the repo root (../.env, ../.ssh_keys).
