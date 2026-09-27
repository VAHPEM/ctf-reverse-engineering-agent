---
tags: Android / dynamic tasking
source: distilled/flareon
---
To exercise cloud-tasked APK behaviour (e.g. FCM C2), patch its config to point at your own project: `apktool d`, replace the config strings in strings.xml, then rebuild `apktool b` + `zipalign -v 4` + self-signed `apksigner sign`, install, and send it commands.
