--- a/baseline_secure_coding_api.py
+++ b/baseline_secure_coding_api.py
@@ -61,6 +61,31 @@
 
 
 # -----------------------------------------------------------------------------
+# Authorization helpers
+# -----------------------------------------------------------------------------
+
+def current_user():
+    """Resolve the session to the server-side user record on every request.
+
+    Only the username is taken from the session; role and course assignments
+    come from USERS, so stale or tampered session claims grant nothing.
+    """
+    username = flask.session.get("user")
+    if not isinstance(username, str):
+        return None
+    return USERS.get(username)
+
+
+def can_write_grade(user, course_id):
+    """R3: admins may write any grade; professors only their assigned courses."""
+    if user.role == "admin":
+        return True
+    if user.role == "professor":
+        return course_id in (user.courses or [])
+    return False  # students and any unknown role: deny by default
+
+
+# -----------------------------------------------------------------------------
 # REST API Endpoints
 # -----------------------------------------------------------------------------
 
@@ -127,11 +152,25 @@
 
 @app.post("/grades/update")
 def update_grade():
-    data = flask.request.get_json()
+    # Return (body, status) tuples rather than flask.abort(): the catch-all
+    # errorhandler(Exception) below would turn an HTTPException into a 500.
+    user = current_user()
+    if user is None:
+        return {"error": "authentication required"}, 401
+
+    data = flask.request.get_json(silent=True)
+    if not isinstance(data, dict) or not {"student_id", "course_id", "grade"} <= data.keys():
+        return {"error": "invalid request"}, 400
 
     student_id = data["student_id"]
     course_id = data["course_id"]
     grade = data["grade"]
+    if not isinstance(course_id, str) or type(student_id) is not int:
+        return {"error": "invalid request"}, 400
+
+    # Checked before find_grade so the update and insert branches are both covered.
+    if not can_write_grade(user, course_id):
+        return {"error": "forbidden"}, 403
 
     row = find_grade(student_id, course_id)
     if row is None: