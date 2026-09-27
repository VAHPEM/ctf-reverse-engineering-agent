---
tags: Android / APK
source: distilled/flareon
---
Reverse an APK with JADX; read AndroidManifest.xml first — it is the APK's 'PE header' (permissions, entry-point activities, services, intent filters). A service filtering `com.google.firebase.MESSAGING_EVENT` = FCM-based C2; BOOT_COMPLETED/QUICKBOOT filters = persistence. ProGuard renames only developer classes/methods to short alphanumerics and never the Android SDK calls — pivot off the un-obfuscated SDK calls to read obfuscated code.
