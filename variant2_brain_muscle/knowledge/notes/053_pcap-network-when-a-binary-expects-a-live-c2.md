---
tags: PCAP / network
source: distilled/writeup
---
When a binary expects a live C2 you don't have, write a tiny fake server that REPLAYS the responses seen in the provided PCAP. It unblocks the code path so you can keep following execution to the flag without the real infrastructure.
