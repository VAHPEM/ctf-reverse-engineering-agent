---
tags: WFP traffic tampering
source: distilled/flareon
---
A rootkit that transforms network traffic does it in kernel mode via the Windows Filtering Platform (imports from fwpkclnt.sys; registers sublayer/filter callbacks). If decrypted payload data still doesn't match the captured PCAP, look for a WFP callout driver mutating the stream in kernel space — that hidden driver is the missing transform, often loaded by another driver and not in the module list.
