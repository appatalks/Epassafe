# ProGuard rules for BouncyCastle optimization

# Keep BouncyCastle Provider and specific cryptographic classes
-keep class org.bouncycastle.jce.provider.BouncyCastleProvider { *; }

# Only keep the cryptographic algorithms your app actually uses
# Using AES-GCM and ChaCha20-Poly1305
-keep class org.bouncycastle.jcajce.provider.symmetric.AES { *; }
-keep class org.bouncycastle.jcajce.provider.symmetric.ChaCha { *; }
-keep class org.bouncycastle.jcajce.provider.symmetric.Poly1305 { *; }

# Keep necessary PBKDF2 classes for key derivation
-keep class org.bouncycastle.jcajce.provider.keystore.PKCS12 { *; }
-keep class org.bouncycastle.jcajce.provider.digest.SHA512 { *; }

# Standard ProGuard rules for Android
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes SourceFile,LineNumberTable
-keep public class * extends java.lang.Exception

# Keep JNI methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# For R8 compatibility
-keepclassmembers,allowobfuscation class * {
  @com.google.gson.annotations.SerializedName <fields>;
}

# For native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep debug intact
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable
