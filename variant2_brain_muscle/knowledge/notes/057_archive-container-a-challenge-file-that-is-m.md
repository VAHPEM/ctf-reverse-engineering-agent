---
tags: Archive / container
source: distilled/writeup
---
A challenge file that is many oddly-named folders plus `manifest.json`/`repositories` is a Docker image archive: `docker load -i file.tar` then `docker run` it. Inspect each `layer.tar`; the odd-one-out layer (a different file set, or a lone ELF) holds the real program to open in Ghidra.
