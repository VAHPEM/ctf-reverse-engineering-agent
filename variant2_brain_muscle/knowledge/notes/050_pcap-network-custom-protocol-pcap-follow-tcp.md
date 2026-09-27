---
tags: PCAP / network
source: distilled/writeup
---
Custom-protocol PCAP: Follow TCP stream, then carve by file magic — `PNG`/`IHDR`, `MZ`, `PK` reveal embedded files inside the byte stream. A stream framed by a repeating ASCII tag is a structured protocol; parse the length field after each tag to split records.
