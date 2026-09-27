---
tags: Staged infostealer keys
source: distilled/flareon
---
In chained-blob infostealers each stage keys the next off a real app's on-disk artifact — Steam config.vdf's first 16 bytes `InstallConfigSt`, Discord's `SQLite format 3\0`, an HTTP Content-Length. Those fixed known headers ARE the keys; pull them from documentation instead of installing every app.
