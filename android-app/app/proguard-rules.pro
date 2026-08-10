# Keep WebView JS interface if added later; safe defaults for a WebView shell.
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}
