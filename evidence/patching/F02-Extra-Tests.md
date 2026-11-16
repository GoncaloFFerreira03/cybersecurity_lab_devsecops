--- /dev/null
+++ b/tests_security/test_grade_authorization_regression.py
@@ -0,0 +1,127 @@
+"""Additional regression tests for F02 (missing authorization on grade updates)."""
+import copy
+
+import pytest
+
+import baseline_secure_coding_api as api
+
+
+def login(client, username, password):
+    response = client.post(
+        "/login", data={"username": username, "password": password}, follow_redirects=True
+    )
+    assert response.status_code == 200
+    assert response.get_json()["user"] == username
+
+
+def snapshot():
+    return copy.deepcopy(api.GRADES)
+
+
+def update(client, student_id=1001, course_id="SRS", grade=18):
+    return client.post(
+        "/grades/update",
+        json={"student_id": student_id, "course_id": course_id, "grade": grade},
+    )
+
+
+# --- Legitimate insert branch still works ------------------------------------
+
+def test_assigned_professor_can_create_grade_in_own_course(client):
+    """R3: the insert branch must stay open for the assigned professor."""
+    api.GRADES[:] = [g for g in api.GRADES if not (g["student_id"] == 1002 and g["course_id"] == "SRS")]
+    login(client, "prof_srs", "profpw")
+    response = update(client, student_id=1002, course_id="SRS", grade=12)
+    assert response.status_code == 200
+    assert response.get_json() == {"status": "ok", "student_id": 1002, "course_id": "SRS", "grade": 12}
+    assert api.find_grade(1002, "SRS")["grade"] == 12
+
+
+def test_admin_can_create_grade_in_any_course(client):
+    login(client, "admin1", "adminpw")
+    response = update(client, student_id=1002, course_id="SSD", grade=11)
+    assert response.status_code == 200
+    assert api.find_grade(1002, "SSD")["grade"] == 11
+
+
+# --- R4: session claims are not trusted --------------------------------------
+
+def test_tampered_session_role_does_not_grant_access(client):
+    """A session that claims role=admin / courses=[SSD] for a student grants nothing."""
+    login(client, "alice", "alicepw")
+    with client.session_transaction() as sess:
+        sess["role"] = "admin"
+        sess["courses"] = ["SRS", "SSD"]
+    before = snapshot()
+    assert update(client, course_id="SSD", grade=20).status_code == 403
+    assert api.GRADES == before
+
+
+def test_revoked_course_assignment_takes_effect_on_next_request(client):
+    """Authorization is re-evaluated per request, not cached at login."""
+    login(client, "prof_srs", "profpw")
+    api.USERS["prof_srs"].courses = []
+    before = snapshot()
+    assert update(client, course_id="SRS", grade=0).status_code == 403
+    assert api.GRADES == before
+
+
+def test_session_for_deleted_user_is_unauthenticated(client):
+    login(client, "prof_srs", "profpw")
+    del api.USERS["prof_srs"]
+    before = snapshot()
+    assert update(client).status_code == 401
+    assert api.GRADES == before
+
+
+def test_logout_revokes_write_access(client):
+    login(client, "prof_srs", "profpw")
+    client.post("/logout")
+    before = snapshot()
+    assert update(client).status_code == 401
+    assert api.GRADES == before
+
+
+def test_unknown_role_is_denied_by_default(client):
+    api.USERS["ta1"] = api.User(username="ta1", password="tapw", role="assistant", courses=["SRS"])
+    login(client, "ta1", "tapw")
+    before = snapshot()
+    assert update(client, course_id="SRS").status_code == 403
+    assert api.GRADES == before
+
+
+def test_course_match_is_exact(client):
+    """'srs' / 'SRS ' are not SRS: no case-folding or trimming bypass."""
+    login(client, "prof_srs", "profpw")
+    before = snapshot()
+    for course in ("srs", "SRS ", "SR"):
+        assert update(client, course_id=course).status_code == 403
+    assert api.GRADES == before
+
+
+# --- Ordering and malformed input: fail closed, never 500 --------------------
+
+def test_unauthenticated_malformed_body_still_returns_401(client):
+    """Authentication is checked before the body is parsed."""
+    response = client.post("/grades/update", data="not json", content_type="text/plain")
+    assert response.status_code == 401
+
+
+@pytest.mark.parametrize(
+    "kwargs",
+    [
+        {"data": "not json", "content_type": "text/plain"},
+        {"json": ["student_id", 1001]},
+        {"json": {"student_id": 1001, "course_id": "SRS"}},  # missing grade
+        {"json": {"student_id": 1001, "course_id": ["SRS"], "grade": 1}},
+        {"json": {"student_id": "1001", "course_id": "SRS", "grade": 1}},
+        {"json": {"student_id": True, "course_id": "SRS", "grade": 1}},
+    ],
+)
+def test_malformed_body_is_rejected_without_change(client, kwargs):
+    login(client, "prof_srs", "profpw")
+    before = snapshot()
+    response = client.post("/grades/update", **kwargs)
+    assert response.status_code == 400
+    assert "type" not in response.get_json()  # not the generic exception handler
+    assert api.GRADES == before