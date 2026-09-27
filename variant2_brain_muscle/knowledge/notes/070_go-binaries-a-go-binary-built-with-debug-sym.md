---
tags: Go binaries
source: distilled/flareon
---
A Go binary built with debug symbols exposes all Go symbols in IDA; when only a handful of non-library funcs exist (main + one or two), the real logic is tiny — read those functions first and ignore the runtime.
