# Dnivio Approver — ProGuard Rules

# Keep cryptographic classes
-keep class dev.dnivio.approver.key.** { *; }
-keep class dev.dnivio.approver.crypto.** { *; }
-keep class dev.dnivio.approver.messaging.** { *; }

# Keep BouncyCastle / security providers
-keep class org.bouncycastle.** { *; }
-keep class javax.crypto.** { *; }
-keep class java.security.** { *; }

# OkHttp
-dontwarn okhttp3.**
-keep class okhttp3.** { *; }

# Firebase
-keep class com.google.firebase.** { *; }

# CBOR
-keep class com.upokecenter.cbor.** { *; }
