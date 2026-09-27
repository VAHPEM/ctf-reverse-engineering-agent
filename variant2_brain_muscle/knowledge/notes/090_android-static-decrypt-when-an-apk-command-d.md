---
tags: Android / static decrypt
source: distilled/flareon
---
When an APK command decrypts a bundled resource, do it statically: `apktool d app.apk`, take the blob from res/raw/, and reproduce the key derivation (often resource strings from res/values/strings.xml, sliced and concatenated, then CRC32'd into an AES-CBC key with an IV also stored as a string). Resource references are R.string.*/R.raw.* IDs resolved in strings.xml.
