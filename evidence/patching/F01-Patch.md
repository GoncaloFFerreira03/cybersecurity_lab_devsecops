--- a/baseline_secure_coding_api.py
+++ b/baseline_secure_coding_api.py
@@ -182,8 +182,27 @@
 
 @app.get("/files")
 def download_file():
+    # R1: require a server-side user, same helper as /grades/update.
+    user = current_user()
+    if user is None:
+        return {"error": "authentication required"}, 401
+
+    # R6: canonicalise, then require the result to stay under MATERIALS_DIR.
+    # resolve() collapses '..' and follows symlinks; an absolute path replaces
+    # the base, which is_relative_to() then rejects. is_relative_to() compares
+    # path components, so a sibling such as 'materials-private' does not match.
+    # R7: one generic 404 for "outside", "missing", "not a file" and malformed
+    # input, so callers learn nothing about the filesystem and no path or
+    # exception text reaches the catch-all 500 handler.
+    not_found = {"error": "file not found"}, 404
     raw_path = flask.request.args.get("path", "")
-    target = MATERIALS_DIR / raw_path
+    base = pathlib.Path(MATERIALS_DIR).resolve()
+    try:
+        target = (base / raw_path).resolve()
+    except (OSError, RuntimeError, ValueError):  # e.g. NUL byte, symlink loop
+        return not_found
+    if not target.is_relative_to(base) or not target.is_file():
+        return not_found
     return flask.send_file(target)
 
 @app.errorhandler(Exception)