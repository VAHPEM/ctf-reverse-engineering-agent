---
tags: Hidden primitives via odd APIs
source: distilled/flareon
---
Operations can be hidden behind unexpected APIs. BitBlt with the SRCINVERT raster op XORs two bitmaps — an XOR decryptor with no XOR instruction, often used to decrypt a DLL stored inside an image (DIB buffer). When an image/graphics op feeds decrypted code, treat the raster operation itself as the crypto.
