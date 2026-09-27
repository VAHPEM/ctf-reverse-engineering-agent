# Variant 1 — Multi-node pipeline (cheap-first)

Fixed LangGraph with many roles: triage → planner → coder → executor → evaluator.
Each stage is a separate step and runs a **cheap / local model** (ollama, e.g.
`qwen2.5-coder:7b`), so the design optimizes for **low token cost** — it uses few or
no paid API tokens.

**This was the original idea**, kept for A/B comparison (cost vs capability) against
variant 2. The trade-off: because the reasoning runs on a local model, variant 1 is
cheap on tokens but **needs a strong machine** for that model (the "muscle") to be
capable enough. It is **not yet well-refined** — variant 2 is the polished, actively
used architecture. Reach for variant 1 when you want to minimize API cost and have the
hardware to host a good local model.

Run:
    OLLAMA_HOST=http://<local-model-host>:11434 python3 graph_skeleton.py <path-to-file>

Shared secrets live at the repo root (../.env, ../.ssh_keys).

## Rule for contributors

Every new function, rule, env knob or dependency is documented in this README **and** the
root README in the same change.
