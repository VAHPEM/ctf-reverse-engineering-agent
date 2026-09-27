---
tags: Steganography
source: distilled/flareon
---
When the challenge is (or hides data in) an image/audio/video, suspect steganography: check least-significant-bit (LSB) planes, appended data after the file's real EOF, extra chunks, and palette tricks. Tools: zsteg/stegsolve for images, binwalk/foremost to carve appended files, strings/exiftool for metadata. Recover the steganogram, then treat it as the next stage.
