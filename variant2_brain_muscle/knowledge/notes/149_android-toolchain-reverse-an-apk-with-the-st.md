---
tags: Android toolchain
source: distilled/flareon
---
Reverse an APK with the standard toolchain: apktool d (decode manifest + smali + resources), dex2jar + jd-gui (or JADX) for readable Java, and read smali directly for the exact bytecode. Logic sometimes lives in a native .so reached via JNI — reverse that ELF separately. The check is usually in an Activity's onCreate/onClick or a helper method.
