---
tags: Find output artifacts
source: distilled/flareon
---
To locate where a program drops a decrypted/output file, monitor it with ProcMon filtered on file-write (CreateFile/WriteFile) operations rather than tracing every path in code. `%LocalAppData%` (os.UserCacheDir on Windows) is a common drop location.
