---
tags: Bootkit / MBR
source: distilled/flareon
---
Boot-sector ransomware: extract the MBR with `dd if=disk.img bs=512 count=1`, load it in IDA as 16-bit real mode at 0000:7C00, and expect it to relocate itself to 0000:0600 (reopen the IDB at that base). It reads the rest of track 0 (sectors 2-63) into 0000:1000 and frequently RC4-decrypts that payload before jumping — extract and decrypt statically with `dd skip=1 count=62 | openssl rc4 -K <hexkey>`.
