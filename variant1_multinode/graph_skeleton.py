import os
import re
import time
import paramiko
import ollama
from dotenv import load_dotenv
from langgraph.graph import StateGraph, START, END
from typing import TypedDict
import shlex
import socket
from prompts import (
    SYSTEM_PROMPT,
    VALID_STRATEGIES,
    build_planner_prompt,
    build_coder_prompt,
)

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))

MODEL = "qwen2.5-coder:7b"
KALI_HOST = os.environ["KALI_HOST"]
KALI_USER = os.environ["KALI_USER"]
SSH_KEY_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", ".ssh_keys", "ctf_orchestrator_ed25519"
)

# The CTF context / anti-refusal framing now lives in prompts.SYSTEM_PROMPT,
# sent as the `system` role on every model call by call_local_model().

REFUSAL_PATTERNS = [
    r"i'?m sorry", r"i can'?t assist", r"i cannot assist",
    r"i'?m not able to", r"as an ai", r"i won'?t", r"i can'?t help",
    r"xin lỗi", r"tôi không thể", r"không thể giúp",
    r"không thể hỗ trợ", r"vi phạm.{0,30}quy tắc",
    r"không an toàn",
]

def is_refusal(text: str) -> bool:
    t = text.lower()
    return any(re.search(p, t) for p in REFUSAL_PATTERNS)

def get_kali_client():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(KALI_HOST, username=KALI_USER, key_filename=SSH_KEY_PATH, timeout=10)
    return client

def upload_to_kali(local_path: str, filename: str) -> str:
    client = get_kali_client()
    sftp = client.open_sftp()
    try:
        sftp.mkdir("samples")
    except IOError:
        pass
    remote_path = f"samples/{filename}"
    sftp.put(local_path, remote_path)
    sftp.close()
    client.close()
    return remote_path

def ssh_exec_kali(cmd: str) -> str:
    client = get_kali_client()
    stdin, stdout, stderr = client.exec_command(cmd)
    out = stdout.read().decode(errors="replace").strip()
    client.close()
    return out

GHIDRA_SCRIPTS_DIR = "/home/vahpem/ghidra_scripts"
GHIDRA_POST_SCRIPT = "dump_decompile.py"
GHIDRA_MARK_START = "===DECOMPILE_START==="
GHIDRA_MARK_END = "===DECOMPILE_END==="

GHIDRA_POST_SCRIPT_CONTENT = '''# Ghidra headless post-script (Jython) - dump pseudocode C cho tat ca ham.
# File nay duoc ghi tu graph_skeleton.py moi lan can, khong sua tay tren Kali.
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def run():
    program = currentProgram
    ifc = DecompInterface()
    ifc.openProgram(program)
    monitor = ConsoleTaskMonitor()
    fm = program.getFunctionManager()
    funcs = fm.getFunctions(True)
    print("===DECOMPILE_START===")
    count = 0
    for func in funcs:
        if func.isThunk():
            continue
        if count >= 40:
            break
        results = ifc.decompileFunction(func, 30, monitor)
        if results.decompileCompleted():
            code = results.getDecompiledFunction().getC()
            print("// ---- FUNCTION: " + func.getName() + " ----")
            print(code)
        count += 1
    print("===DECOMPILE_END===")

run()
'''

def ensure_ghidra_script():
    # Ghi (hoac ghi de) script Jython Ghidra se goi khi phan tich.
    # Deterministic, KHONG phai do AI sinh ra: goi dung API cua Ghidra can
    # chinh xac tuyet doi, giao cho model local 7B tu viet se khong dang tin cay.
    ssh_exec_kali(f"mkdir -p {shlex.quote(GHIDRA_SCRIPTS_DIR)}")
    client = get_kali_client()
    sftp = client.open_sftp()
    with sftp.file(f"{GHIDRA_SCRIPTS_DIR}/{GHIDRA_POST_SCRIPT}", "w") as f:
        f.write(GHIDRA_POST_SCRIPT_CONTENT)
    sftp.close()
    client.close()

def run_ghidra_headless(remote_path: str) -> str:
    # Chay Ghidra headless that tren Kali de decompile binary da upload,
    # tra ve pseudocode C (rut gon) de dua cho AI doc va suy luan.
    ensure_ghidra_script()
    proj_dir = f"/tmp/ghidra_proj_{os.getpid()}_{int(time.time())}"
    # Wrap in a login shell (bash -lc) so the Ghidra install dir on PATH
    # (added via the shell profile) is available: a non-interactive SSH
    # command does NOT source the profile, so a bare `analyzeHeadless` can be
    # "command not found". [NEEDS LIVE VERIFICATION on the Kali box.]
    inner = (
        f"timeout 180 analyzeHeadless {shlex.quote(proj_dir)} proj "
        f"-import {shlex.quote(remote_path)} -scriptPath {shlex.quote(GHIDRA_SCRIPTS_DIR)} "
        f"-postScript {shlex.quote(GHIDRA_POST_SCRIPT)} -deleteProject 2>&1"
    )
    raw = ssh_exec_kali(f"bash -lc {shlex.quote(inner)}")
    match = re.search(
        re.escape(GHIDRA_MARK_START) + r"(.*?)" + re.escape(GHIDRA_MARK_END),
        raw, re.DOTALL,
    )
    if not match:
        return f"(Ghidra khong tra ve duoc pseudocode - raw output cuoi: {raw[-800:]})"
    return match.group(1).strip()[:6000]

WIN_HOST = os.environ.get("WIN_HOST", "")
WIN_USER = os.environ.get("WIN_USER", "")
WIN_PYTHON_EXE = os.environ.get(
    "WIN_PYTHON_EXE", r"C:\Users\vahpem\AppData\Local\Programs\Python\Python314\python.exe"
)

def get_windows_client():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(WIN_HOST, username=WIN_USER, key_filename=SSH_KEY_PATH, timeout=10)
    return client

def upload_to_windows(local_path: str, filename: str) -> str:
    client = get_windows_client()
    sftp = client.open_sftp()
    try:
        sftp.mkdir("samples")
    except IOError:
        pass
    remote_path = f"samples/{filename}"
    sftp.put(local_path, remote_path)
    sftp.close()
    client.close()
    return remote_path

class CTFState(TypedDict):
    file_path: str
    file_type_raw: str
    hex_dump: str
    strings_sample: str
    remote_path: str
    windows_remote_path: str
    category: str
    source_code: str
    sibling_files: str
    decompiled_code: str
    strategy: str
    plan: str
    code: str
    exec_result: str
    flag: str
    retry_count: int
    refusal_count: int
    refused: bool

def call_local_model(prompt: str, system: str = SYSTEM_PROMPT) -> str:
    # num_ctx bumped to 16384: the discipline + technique playbook prepended
    # to coder prompts (plus Ghidra pseudocode on retries) can exceed 8192
    # tokens, and Ollama SILENTLY truncates anything past num_ctx, which would
    # drop part of the instructions or the evidence. 16k keeps it in-window.
    resp = ollama.chat(
        model=MODEL,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        options={"num_ctx": 16384},
    )
    return resp["message"]["content"]

def triage_node(state: CTFState) -> CTFState:
    print(">> TRIAGE (chi thu thap bang chung, KHONG tu ket luan loai file)")
    local_path = state["file_path"]
    filename = os.path.basename(local_path)
    remote_path = upload_to_kali(local_path, filename)
    state["remote_path"] = remote_path

    q = shlex.quote(remote_path)
    file_output = ssh_exec_kali(f"file {q}")
    hex_dump = ssh_exec_kali(f"xxd -l 64 {q}")
    strings_sample = ssh_exec_kali(f"strings {q} | head -50")

    state["file_type_raw"] = file_output
    state["hex_dump"] = hex_dump
    state["strings_sample"] = strings_sample

    # Thu doc nhu text (khong dua vao ten file/extension/output cua `file`,
    # vi tat ca deu co the bi co tinh danh lua trong CTF)
    try:
        with open(local_path, "r", encoding="utf-8") as f:
            state["source_code"] = f.read()
    except (UnicodeDecodeError, OSError):
        state["source_code"] = ""

    dirpath = os.path.dirname(local_path) or "."
    try:
        siblings = [f for f in os.listdir(dirpath) if f != filename]
    except OSError:
        siblings = []
    state["sibling_files"] = ", ".join(siblings) if siblings else "(khong co file nao khac)"

    state.setdefault("refusal_count", 0)
    print("   file output (chi la 1 nguon bang chung, chua phai ket luan):", file_output)
    print("   hex dump (64 byte dau):", hex_dump.replace("\n", " | ")[:200])
    print("   sibling_files:", state["sibling_files"])
    return state

def _ask_planner(state: CTFState, strict: bool) -> str:
    return call_local_model(build_planner_prompt(state, strict))

def planner_node(state: CTFState) -> CTFState:
    print(">> PLANNER (AI tu doc bang chung va tu ket luan, khong dua san category)")
    response = _ask_planner(state, strict=False)
    lines = [l.strip() for l in response.strip().splitlines() if l.strip() and not l.strip().startswith("```")]
    category = lines[0].lower() if len(lines) > 0 else ""
    strategy = lines[1].lower() if len(lines) > 1 else ""

    if strategy not in VALID_STRATEGIES:
        print(f"   !! Lan 1: model tra loi sai dinh dang (nhan duoc strategy='{strategy}'), thu lai 1 lan voi yeu cau chat che hon")
        response = _ask_planner(state, strict=True)
        lines = [l.strip() for l in response.strip().splitlines() if l.strip() and not l.strip().startswith("```")]
        category = lines[0].lower() if len(lines) > 0 else ""
        strategy = lines[1].lower() if len(lines) > 1 else ""

    state["category"] = category or "khong_xac_dinh_duoc"
    state["plan"] = response

    if strategy not in VALID_STRATEGIES:
        print("   !! Model KHONG the dua ra chien luoc hop le sau 2 lan thu.")
        print("   !! KHONG doan thay AI — dung pipeline tai day, can nguoi kiem tra thu cong.")
        state["strategy"] = ""
    else:
        state["strategy"] = strategy

    print("   category (AI tu ket luan):", state["category"])
    print("   strategy:", state["strategy"] or "(chua xac dinh duoc)")
    print("   plan/ly do:", response[:200])
    return state

def route_after_planner(state: CTFState) -> str:
    if not state.get("strategy"):
        return END
    return "coder"

def coder_node(state: CTFState) -> CTFState:
    print(">> CODER")
    strategy = state.get("strategy", "")

    # Side effects that must happen before the prompt can be built:
    if strategy == "ghidra_decompile" and not state.get("decompiled_code"):
        print("   (running headless Ghidra on Kali to decompile - may take 30-180s...)")
        state["decompiled_code"] = run_ghidra_headless(state["remote_path"])
        print("   decompiled_code (first 500 chars):", state["decompiled_code"][:500])
    if strategy == "run_on_windows" and not state.get("windows_remote_path"):
        win_filename = os.path.basename(state["file_path"])
        state["windows_remote_path"] = upload_to_windows(state["file_path"], win_filename)

    prompt = build_coder_prompt(state, strategy)
    state["code"] = call_local_model(prompt)

    # A reply is a real refusal only if it contains NO python code block.
    # Otherwise phrases like "as an AI" or "I won't" inside a valid answer
    # (or a comment/string) would be misread as a refusal.
    has_code = bool(re.search(r"```python", state["code"]))
    state["refused"] = is_refusal(state["code"]) and not has_code
    if state["refused"]:
        state["refusal_count"] = state.get("refusal_count", 0) + 1
        print(f"   !! Refusal detected (refusal_count={state['refusal_count']}):", state["code"][:60])
    else:
        print("   code (full):\n" + state["code"])
    return state

def route_after_coder(state: CTFState) -> str:
    if state.get("refused"):
        if state["refusal_count"] >= 2:
            print("!! Refused more than twice, stopping")
            return END
        return "coder"
    return "executor"

def executor_node(state: CTFState) -> CTFState:
    print(">> EXECUTOR")
    match = re.search(r"```python\n(.*?)```", state["code"], re.DOTALL)
    script = match.group(1) if match else state["code"]

    if state.get("strategy") == "run_on_windows":
        print("   (running on Windows via SSH, with a channel-read timeout guard)")
        client = get_windows_client()
        sftp = client.open_sftp()
        with sftp.file("samples/exploit.py", "w") as f:
            f.write(script)
        sftp.close()

        win_timeout = 60
        try:
            stdin, stdout, stderr = client.exec_command(
                f'cd samples && "{WIN_PYTHON_EXE}" exploit.py', timeout=win_timeout
            )
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
        except socket.timeout:
            out = ""
            err = (f"(TIMEOUT: no output/exit within {win_timeout}s - likely a GUI "
                   "app or a script blocked waiting on input over non-interactive SSH)")
        client.close()
    else:
        client = get_kali_client()
        sftp = client.open_sftp()
        with sftp.file("samples/exploit.py", "w") as f:
            f.write(script)
        sftp.close()

        # angr symbolic execution co the can nhieu thoi gian hon nhieu so voi script binh thuong
        kali_timeout = 120 if state.get("strategy") == "angr_symbolic" else 10
        stdin, stdout, stderr = client.exec_command(
            f"cd samples && timeout {kali_timeout} /home/vahpem/ctf-venv/bin/python3 exploit.py"
        )
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        client.close()

    state["exec_result"] = (out + "\n" + err).strip()
    state["retry_count"] = state.get("retry_count", 0) + 1
    print("   exec_result:", state["exec_result"][:200])
    return state

def evaluator_node(state: CTFState) -> CTFState:
    print(">> EVALUATOR (retry_count =", state["retry_count"], ")")
    result = state["exec_result"]
    if "flag{" in result or "@flare-on.com" in result:
        state["flag"] = result
    return state

def route_after_eval(state: CTFState) -> str:
    if state.get("flag"):
        return END
    if state["retry_count"] >= 3:
        print("!! Da toi han retry, dung lai")
        return END
    return "coder"

graph = StateGraph(CTFState)
graph.add_node("triage", triage_node)
graph.add_node("planner", planner_node)
graph.add_node("coder", coder_node)
graph.add_node("executor", executor_node)
graph.add_node("evaluator", evaluator_node)

graph.add_edge(START, "triage")
graph.add_edge("triage", "planner")
graph.add_conditional_edges("planner", route_after_planner, {"coder": "coder", END: END})
graph.add_conditional_edges("coder", route_after_coder, {"executor": "executor", "coder": "coder", END: END})
graph.add_edge("executor", "evaluator")
graph.add_conditional_edges("evaluator", route_after_eval, {"coder": "coder", END: END})

app = graph.compile()

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "/tmp/kali_ls_elf"
    result = app.invoke({"file_path": target, "retry_count": 0, "refusal_count": 0})
    print("\nFINAL STATE:", {k: v for k, v in result.items() if k != "code"})
