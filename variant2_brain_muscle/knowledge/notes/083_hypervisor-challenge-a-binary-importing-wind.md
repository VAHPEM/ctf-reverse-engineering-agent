---
tags: Hypervisor challenge
source: distilled/flareon
---
A binary importing Windows Hypervisor Platform APIs (WinHvPlatform.dll / WHvCreatePartition) runs its real logic as GUEST code inside a VM; the guest shellcode is usually a PE resource (dump with CFF Explorer / Resource Hacker). It boots through 16->32->64-bit with far jumps (opcode 0xEA, seg:offset) that IDA mis-decodes — reload or re-segment the shellcode as the new bitness at each mode switch.
