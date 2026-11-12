# Static security review: `baseline_secure_coding_api.py`

**Scope and method.** I read the source by hand and executed nothing. Line numbers refer to the uploaded file. Each finding has two labels:
- **[Fact]** is something the code demonstrably does.
- **[Req]** is a security requirement I inferred from the application context. The context doesn't spell out an access-control policy, so wherever one matters I state the policy I assumed.

**Assumed policy (A0).** The context doesn't define who may do what, so I assumed the following:
- Students may read only their own profile and grades.
- Professors may read and update grades only for their assigned courses, and may read profiles only of students enrolled in those courses.
- Administrators have full access.
- Teaching materials are available only to authenticated users, and only from `MATERIALS_DIR`.
- Unauthenticated callers may use only `/`, `/login` and `/me`.

## Findings table

| ID | Title | Location | Severity* | Confidence |
|---|---|---|---|---|
| F1 | Unauthenticated, unauthorized grade creation and modification | `update_grade`, L128–142 | Critical | High |
| F2 | Path traversal and arbitrary file read in material download | `download_file`, L144–148 | Critical | High |
| F3 | Unauthenticated access to any student's profile, including personal data (IDOR) | `get_profile`, L115–120 | High | High |
| F4 | Unauthenticated access to any student's grades (IDOR) | `get_grades`, L122–126 | High | High |
| F5 | Hard-coded, guessable session signing key lets attackers forge sessions | L8; session use at L91–94, L105–113 | High (conditional) | High that a forgery works; medium on impact today |
| F6 | Debug mode on all interfaces exposes the Werkzeug debugger | L158–159 | High (conditional) | Medium |
| F7 | No validation of grade-update input (type, range, existence, size) | `update_grade`, L130–140; `find_grade`, L56–60 | Medium | High |
| F8 | Verbose global error handler leaks internals and acts as a file-existence oracle | `handle_error`, L150–155 | Medium | High |
| F9 | Plaintext, hard-coded passwords compared in non-constant time | L36–43, L88 | Medium | High |
| F10 | No brute-force protection on login | `login`, L82–96 | Low–Medium | Medium |
| F11 | Session can't be revoked and role data goes stale | L91–94, L98–101 | Low | Medium |
| F12 | No CSRF protection and no explicit cookie hardening | L82–101; app config | Low | Medium |
| F13 | No audit trail for grade changes | `update_grade` | Low | Medium |

\*Severity is my estimate under the assumed policy (A0) and assumes the app is reachable by multiple users, as the context states.

## Supporting explanations

### F1: Unauthenticated, unauthorized grade update (L128–142)
- **Input and path:** The attacker controls the JSON body `student_id`, `course_id` and `grade` (L130–134). The values pass to `find_grade` (L136), and then either a new record is appended (L138) or the existing grade is overwritten (L140).
- **Missing control. [Fact]:** The handler never reads `flask.session`, so there is no authentication check, no role check, and no check that a professor is assigned to `course_id`.
  - **[Req]:** Under A0, only admins, or professors for their own courses, may write grades.
  - **Root cause:** Authorization was never designed into the endpoint.
- **Preconditions:** Network access only.
- **Impact:** Anyone, including logged-out callers and students changing their own marks, can change any grade or create grades for any student in any course. This is a complete loss of grade integrity.
- **Test to confirm or reject:**
  - With no cookie, POST `{"student_id":1001,"course_id":"SRS","grade":20}`, then GET `/grades/1001`. A 200 response and the changed grade confirm the finding.
  - Repeat as `alice`, and as `prof_srs` against `course_id:"SSD"`. Under A0, each request should be rejected.
- **Assumptions:** Write rights are as described in A0. That anonymous writes are allowed is a code fact, and they are almost certainly not intended.

### F2: Path traversal and arbitrary file read (L144–148)
- **Input and path:** The attacker controls the query parameter `path` (L146). The code joins it to the base with `MATERIALS_DIR / raw_path` (L147) and passes the result to `flask.send_file` (L148).
- **Missing control. [Fact]:** The code never canonicalizes the path or checks that it stays inside `MATERIALS_DIR`, and it doesn't use `send_from_directory` or `safe_join`. It also has no authentication check.
  - When `raw_path` is absolute, `pathlib` discards the base directory, so `?path=/etc/passwd` resolves to `/etc/passwd`.
  - Relative traversal such as `?path=../baseline_secure_coding_api.py` also escapes the directory.
- **Root cause:** User input is trusted as a filesystem path, and the code relies on path joining, which doesn't contain the result inside the base directory.
- **Preconditions:** Network access, and the process can read the target file.
- **Impact:** Arbitrary file read. Exposed files would include the application source, which holds the passwords and the secret key, plus system files.
  - This can chain with F5 (forging an admin session) and F6 (the debugger PIN can be derived from files such as `/etc/machine-id` and the MAC address).
- **Tests to confirm or reject:**
  - Request `GET /files?path=/etc/hostname` and `GET /files?path=../baseline_secure_coding_api.py`. File contents in a 200 response confirm the finding.
  - Also try URL-encoded variants (`..%2f`) and request without a session cookie.
- **Assumptions:** Under A0, only files inside `MATERIALS_DIR` should be served. The traversal behavior follows from documented `pathlib` semantics and is high confidence.

### F3 and F4: IDOR on profiles (L115–120) and grades (L122–126)
- **Input and path:** The attacker controls the URL segment `student_id`. It goes through `int()` and is then used directly as the lookup key.
- **Missing control. [Fact]:** Neither handler checks the session, so there is no authentication and no ownership check against `session["student_id"]`.
  - **[Req]:** Under A0, students may access only their own records, and professors only students in their courses.
- **Impact:**
  - F3: Anyone can read every student's name, email and program. This is personal-data exposure, with likely GDPR relevance given the `uc.pt` addresses.
  - F4: Anyone can read every grade.
  - Because the IDs are small sequential integers (1001, 1002, …), enumeration is trivial.
- **Tests to confirm or reject:**
  - With no cookie, request `GET /students/1002/profile` and `GET /grades/1002`.
  - As `alice`, request the same URLs. Under A0, both should be refused.
  - As `prof_srs`, request `/grades/1001`. The response also includes Alice's SSD grade, which is outside that professor's course.
- **Assumptions:** The exact visibility rules (A0) are inferred. That no check exists at all is a code fact.

### F5: Hard-coded session signing key (L8)
- **[Fact]:** `SECRET_KEY = "dev-secret-key"` is a constant that can be guessed or read from the source. Flask's default sessions are client-side cookies signed with this key, and the identity and role data written at L91–94 lives in that cookie.
- **Input and path:** An attacker who knows the key can create a cookie containing, for example, `{"user":"admin1","role":"admin"}`. `/me` would trust it (L105–113).
- **Impact today:** Limited, because no endpoint enforces roles yet (see F1, F3 and F4). This becomes high-impact as soon as role checks are added that rely on `session["role"]`, because any such check could be bypassed with a forged cookie. Separately, session contents are only signed, not encrypted, so any user can read them (a minor point).
- **Test to confirm or reject:** Sign `{"user":"admin1","role":"admin"}` with Flask's session serializer and key `dev-secret-key`, send it in a request to `/me`, and check whether admin is reflected back.
- **Confidence:** High that forgery is possible. Impact depends on future authorization code.

### F6: Debug server bound to 0.0.0.0 (L159)
- **[Fact]:** `debug=True, host="0.0.0.0"` enables the Werkzeug interactive debugger on every network interface whenever the file is run directly.
- **Impact:** Werkzeug's debugger console allows arbitrary Python execution once its PIN is known. The PIN is derived from host data that F2 can read, so the two findings may chain into remote code execution.
- **Uncertainty:** The catch-all `errorhandler(Exception)` (L150) probably stops traceback pages from appearing for errors in route handlers. Whether the `/console` endpoint is reachable depends on the Werkzeug version and configuration. If the app is deployed under a production WSGI server, this finding doesn't apply.
- **Test to confirm or reject:** Run `python app.py` in an isolated lab and request `/console` from another host.

### F7: No input validation on grade update (L130–140)
- **[Fact]:**
  - `get_json()` can return `None`, or fail, for a missing or invalid body. The code then subscripts the result without any check.
  - No types are checked: `student_id` may be `"1001"` (a string), and `grade` may be `-5`, `999`, `"A"`, `null`, or a nested object.
  - Nothing checks that the student or course exists. Unknown pairs are silently appended as new records (L138).
  - There is no limit on payload size or record count.
- **Impact:**
  - Corrupt or out-of-range grades.
  - Type confusion: a string `"1001"` never matches the integer IDs, so it creates shadow records that `GET /grades/1001` doesn't show.
  - Records for nonexistent students.
  - Memory exhaustion from repeated appends by an unauthenticated caller (F1).
- **[Req]:** I assumed grades follow the Portuguese 0–20 scale based on the existing values. The required range isn't stated, so it needs confirmation.
- **Test to confirm or reject:** POST each of these bodies and inspect `GRADES` through `/grades/<id>`:
  - `{"student_id":"1001","course_id":"SRS","grade":-1}`
  - `{"student_id":9999,"course_id":"X","grade":{"a":1}}`
  - an empty body

### F8: Verbose catch-all error handler (L150–155)
- **[Fact]:** Every exception, including Werkzeug `HTTPException`s, is returned as a 500 response that contains `str(exc)` and the class name.
- **Paths:**
  - `/files?path=nope` returns a `FileNotFoundError` that includes the absolute server path.
  - Responses for missing files differ from responses for existing ones, which gives a file-existence oracle.
  - `/grades/abc` exposes the `ValueError` text.
  - Genuine 404, 405 and 415 errors become misleading 500s.
- **Impact:** Leaks internal paths and implementation details that help with F2, and degrades monitoring.
- **Test to confirm or reject:** Request `/files?path=does-not-exist`, `/files?path=` (a directory) and `/grades/x`, and look for absolute paths and exception text in the responses.

### F9: Plaintext, hard-coded credentials (L36–43, L88)
- **[Fact]:** Passwords are stored in plaintext in the source, are weak, and are compared with `!=`.
- **Impact:** Anyone who can read the source, for example through F2, gets every account including admin. The `!=` comparison isn't constant-time, but given network jitter the timing leak is low risk.
- **Context caveat:** The data is a deliberate teaching simplification. The finding is about the pattern rather than the dataset.
- **Test to confirm or reject:** Fetch the source via F2 and log in as `admin1`. Separately, use code review to confirm there's no hashing (no bcrypt, argon2 or `werkzeug.security`).

### F10: No login throttling (L82–96)
- **[Fact]:** Nothing limits attempts by account or IP and nothing locks accounts. The error message doesn't reveal whether a username exists. A dictionary lookup that misses returns a little faster, which is a weak enumeration signal.
- **Impact:** Weak passwords (F9) can be found by online guessing.
- **Test to confirm or reject:** Send around 1,000 failed logins for `admin1` and check for any rate limiting or lockout.
- **Confidence:** Medium. Throttling may exist upstream in a proxy that isn't shown.

### F11: Stateless sessions that can't be revoked (L91–101)
- **[Fact]:**
  - Role and courses are copied into the cookie at login.
  - Logout clears only the client's copy, so a copied cookie stays valid.
  - Changes to a user's role or courses don't take effect until they log in again.
  - The identifier isn't rotated, though client-side sessions make fixation less relevant.
- **Impact:** Stolen sessions can be replayed after logout, and stale privileges persist.
- **Test to confirm or reject:** Save the cookie, log out, then replay it against `/me`.
- **Uncertainty:** How long a replayed cookie stays valid depends on Flask's `PERMANENT_SESSION_LIFETIME` handling in the deployed version.

### F12: CSRF and cookie flags
- **[Fact]:**
  - There are no CSRF tokens.
  - `SESSION_COOKIE_SECURE` and `SAMESITE` aren't set. Flask's defaults are not Secure and no SameSite attribute, although browsers may apply Lax.
  - `/login` and `/logout` accept cross-site form posts, which allows login CSRF and forced logout.
- `/grades/update` is partly protected because `get_json()` requires a JSON content type. A JSON request sent cross-site triggers a CORS preflight, and no CORS policy is configured.
- **Test to confirm or reject:** Submit a cross-origin HTML form to `/login` and check whether the victim's browser ends up logged in as the attacker.

### F13: No audit logging
- **[Req, inferred]:** Grade changes are high-integrity academic records. Who changed what, when, and from which value should be recorded. **[Fact]:** Nothing is logged.
- **Impact:** Tampering through F1 can't be detected or attributed.
- **Test to confirm or reject:** Review the code and logs after an update.

## Not reported, or out of scope
- **Thread-safety of the global `GRADES` list:** Concurrent updates to the list aren't synchronized. Per the context, in-memory storage is a deliberate simplification, so I consider this low risk but worth noting.
- **Redirect after login (L96):** It goes to a fixed `/me`, so it isn't an open redirect.
- **`/me`:** It returns only the caller's own session data, which I don't consider a vulnerability.
- **Coverage limits:** This review covers only the attached file. Deployment configuration, the reverse proxy, the TLS setup and the Flask and Werkzeug versions weren't provided. Several findings (F6, F10, F11, F12) depend on them. Finding nothing in an area is not evidence that it is safe.

**Priority:** F1 and F2 are exploitable anonymously and with certainty. F2 also leads into F5, F6 and F9, so I'd test those two first.