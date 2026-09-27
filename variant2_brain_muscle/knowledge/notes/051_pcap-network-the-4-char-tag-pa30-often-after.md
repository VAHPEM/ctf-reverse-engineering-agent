---
tags: PCAP / network
source: distilled/writeup
---
The 4-char tag `PA30` (often after a `ME0W`-style header) is the Windows MS Delta patch format — reassemble the payload with the Delta API (ApplyDeltaB) rather than trying to decode the bytes by hand. Recognizing the container format is the whole trick.
