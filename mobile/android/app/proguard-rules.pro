# Keep rustls-platform-verifier JNI-invoked Android verification runtime classes intact.
-keep,includedescriptorclasses class org.rustls.platformverifier.** { *; }

# Keep MeshNativeInit JNI entrypoint invoked by native rustls-platform-verifier/mesh-sys.
-keep class dev.meshvpn.android.ffi.MeshNativeInit { *; }
-keepclassmembers class dev.meshvpn.android.ffi.MeshNativeInit {
    public static final dev.meshvpn.android.ffi.MeshNativeInit INSTANCE;
    boolean initPlatformVerifier(android.content.Context);
}

# Keep JNA classes, native callbacks, and proxy structures used by UniFFI 0.29.5.
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { *; }
-keepclassmembers interface * extends com.sun.jna.Library { *; }
-keepclassmembers interface * extends com.sun.jna.Callback { *; }
-dontwarn com.sun.jna.**
-dontwarn java.awt.*

# Keep UniFFI 0.29.5 generated bindings and Rust callback vtables.
-keep class uniffi.mesh_mobile_ffi.** { *; }
-keepclassmembers class uniffi.mesh_mobile_ffi.** { *; }

# Strip debug and verbose log calls in release builds (SEC-01 / MOB-SEC-05).
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
}
