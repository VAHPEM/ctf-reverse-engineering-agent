# Smoke-test OpenAI top tier WITHOUT running the agent. Never prints the key.
import os; from dotenv import load_dotenv; load_dotenv("../.env")
from agent import config, reasoner
m = config.TOP_MODEL
print("TOP_MODEL =", m, "| provider =", reasoner._provider(m))
assert reasoner._provider(m) == "openai", "TOP_MODEL does not route to OpenAI - check the ID"
out = reasoner.call_model('Reply with exactly this JSON and nothing else: {"ok": true}', system="You are a test.", tier="top")
print("reply =", repr(out[:200]))
print("truncated =", reasoner.last_call_truncated(), "| usage =", reasoner.USAGE)
