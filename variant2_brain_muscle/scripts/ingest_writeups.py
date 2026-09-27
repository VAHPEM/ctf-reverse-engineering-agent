#!/usr/bin/env python3
"""Tier-2 corpus ingestion: turn CTF/RE writeups into recall notes.

Run where the writeup repos are cloned (they have text; e.g. on the Kali VM which has
network). It chunks each writeup by heading into knowledge/writeups/<slug>.md notes that
the `recall` muscle tool searches. Re-run any time to refresh / add sources.

SOURCES:
  * allthingsreversed.io (pawlos)  -> 93 diverse-CTF writeups, chunked here. Low benchmark
    contamination risk (mostly non-FLARE-On CTFs).
  * fareedfauzi/Flare-On-Challenges -> the Challenges/ dir is BINARIES (use as a regression
    TEST corpus, not notes); its Write-ups/ dir is per-FLARE-On-challenge solutions. Those
    are contamination risk if you benchmark on the same challenge - DISTILL them into
    general notes rather than raw-ingesting, or exclude them during benchmark runs.

    git clone --depth 1 https://github.com/pawlos/allthingsreversed.io /tmp/wr/allthingsreversed.io
    python3 ingest_writeups.py     # writes /tmp/knowledge_out/writeups, tar back to the repo
"""

import re, os, glob, hashlib  # noqa
SRC="/tmp/wr/allthingsreversed.io"
OUT="/tmp/knowledge_out/writeups"; os.makedirs(OUT, exist_ok=True)
TOOLWORDS=("ghidra ida x64dbg x32dbg gdb radare2 r2 angr frida z3 unicorn capstone "
           "dnspy dotpeek il2cpp jadx apktool pwntools binja binaryninja windbg ollydbg "
           "qemu wireshark volatility upx pyinstaller uncompyle decompyle scylla").split()
n=0
for path in sorted(glob.glob(os.path.join(SRC,"20*.md"))):
    base=os.path.basename(path)[:-3]
    m=re.match(r"(\d{8})-(.+)", base)
    title=(m.group(2) if m else base).replace("-"," ").replace("_"," ")
    txt=open(path,encoding="utf-8",errors="replace").read()
    txt=re.sub(r"^---\n.*?\n---\n","",txt,flags=re.S)  # strip frontmatter
    # split by headings; keep the heading with its body
    parts=re.split(r"(?m)^(#{1,4}\s+.*)$", txt)
    chunks=[]
    if len(parts)>1:
        # parts: [pre, head1, body1, head2, body2, ...]
        pre=parts[0].strip()
        if pre: chunks.append(("",pre))
        for i in range(1,len(parts),2):
            head=parts[i].strip("# ").strip(); body=parts[i+1] if i+1<len(parts) else ""
            chunks.append((head, body.strip()))
    else:
        chunks=[("",txt.strip())]
    for head,body in chunks:
        body=body.strip()
        if len(body)<120: continue
        # cap very long chunks to ~1600 chars on a paragraph boundary
        if len(body)>1600:
            cut=body.rfind("\n\n",0,1600); body=body[:cut if cut>800 else 1600].rstrip()
        low=(title+" "+head+" "+body).lower()
        tools=sorted({w for w in TOOLWORDS if re.search(r"\b"+re.escape(w)+r"\b",low)})
        tags=" ".join([title]+([head] if head else [])+tools)[:200]
        n+=1
        slug=re.sub(r"[^a-z0-9]+","-",(base+"-"+head).lower()).strip("-")[:60]
        h=hashlib.blake2b(body.encode(),digest_size=4).hexdigest()
        open(os.path.join(OUT,f"{n:03d}_{slug}_{h}.md"),"w").write(
            f"---\ntags: {tags}\nsource: writeup/allthingsreversed/{base}\n---\n{body}\n")
print("chunks written:", n)
