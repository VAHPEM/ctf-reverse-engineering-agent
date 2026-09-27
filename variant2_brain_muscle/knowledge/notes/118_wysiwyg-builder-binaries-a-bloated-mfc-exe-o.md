---
tags: WYSIWYG-builder binaries
source: distilled/flareon
---
A bloated MFC exe (often UPX-packed) built by a WYSIWYG tool (Multimedia Builder, AutoPlay Media Studio, etc.) drops its real content to a %TEMP% subfolder at runtime — monitor file creation (ProcMon) to grab index.html, plugin DLLs and images. Embedded project objects/scripts are located by a marker near EOF (e.g. STANDALONE) followed by a negative offset from end-of-file. Reverse the tool's scripting layer, not the machine code.
