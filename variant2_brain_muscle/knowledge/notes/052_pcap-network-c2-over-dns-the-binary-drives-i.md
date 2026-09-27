---
tags: PCAP / network
source: distilled/writeup
---
C2-over-DNS: the binary drives itself off DNS name-resolution replies. Stand up your own DNS server and feed the answers in the correct order to advance each stage; the final stage typically decrypts a flag image from a binary section. Patch any `Sleep` first so the exchange runs fast.
