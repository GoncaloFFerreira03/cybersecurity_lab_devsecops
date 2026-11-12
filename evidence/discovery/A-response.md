# Static security review: `baseline_secure_coding_api.py`

I worked only from the source, as your prompt asked. I didn't run any code or look anything up. All line numbers refer to the uploaded file.

**Policy assumptions.** The code contains no access-control policy, so the inferred requirements below are my assumptions, based on the data model (roles `student`, `professor` with `courses`, `admin`) and normal academic norms:
- **A1:** A student may read only their own profile and grades.
- **A2:** A professor may read grades for, and update grades in, only the courses listed in their `courses`.
- **A3:** An admin may do everything.
- **A4:** Course materials are for authenticated users only, and nothing outside `materials/` should ever be served.
- **A5:** The app is meant to be reachable over a network, not only by a single local developer.

If your real policy is different, findings SC-02 to SC-04 need to be re-graded.

## Findings table

| ID | Title | Location | Severity | Confidence |
|---|---|---|---|---|
| SC-01 | Path traversal / arbitrary file read | `download_file`, L144–148 | Critical | High |
| SC-02 | Anyone can change grades with no login | `update_grade`, L128–142 | Critical | High |
| SC-03 | Missing authorization on grade reads (IDOR) | `get_grades`, L122–126 | High | High (given A1/A2) |
| SC-04 | Missing authorization on profile reads (personal data exposure) | `get_profile`, L115–120 | High | High (given A1) |
| SC-05 | Hardcoded, guessable `SECRET_KEY` allows session forgery | L8; session writes L91–94 | High (latent) | High |
| SC-06 | Debug server bound to all interfaces | `__main__`, L158–159 | High | Medium |
| SC-07 | Plaintext, weak, hardcoded passwords; no brute-force limits | `USERS` L36–43; `login` L84–89 | Medium | High |
| SC-08 | Verbose catch-all error handler leaks details and returns wrong status codes | `handle_error`, L150–155 | Medium | High |
| SC-09 | No input validation on grade updates | `update_grade`, L130–140 | Medium | High |
| SC-10 | Session management weaknesses (no revocation, stale role, cookie flags, login CSRF) | L8, L91–101 | Low–Medium | Medium |
| SC-11 | Unsynchronized, unbounded mutation of shared in-memory state | L136–140 | Low | Low–Medium |
| SC-12 | Unauthenticated endpoint list | `index`, L67–80 | Informational | High |

## Supporting explanations

### SC-01: Path traversal / arbitrary file read
- **Input and data flow:** the `path` query parameter goes to `raw_path` (L146), then `MATERIALS_DIR / raw_path` (L147), then `flask.send_file(target)` (L148).
- **Code facts:** the path is never normalized, contained or allow-listed. With `pathlib`, joining an *absolute* right-hand side throws away the base, so `MATERIALS_DIR / "/etc/passwd"` is just `/etc/passwd`. `../` segments also survive the join. `send_file` adds no directory restriction (unlike `send_from_directory`). There is also no authentication check.
- **Root cause:** a file path controlled by the user is passed straight to a file-serving function, with no check that it stays inside `MATERIALS_DIR`.
- **Preconditions:** none. A network-reachable server is enough.
- **Impact:** the attacker can read any file the process can read, including:
  - this source file, which exposes `SECRET_KEY` and every password (feeding SC-05 and SC-07);
  - `/proc/self/environ`;
  - the machine-id and MAC files, which help derive the Werkzeug debugger PIN (feeding SC-06).
- **Test:** with the test client, send `GET /files?path=../baseline_secure_coding_api.py` and `GET /files?path=/etc/passwd`. The finding is confirmed if either returns 200 with the file contents, and rejected if both return 4xx. Also confirm that `GET /files?path=srs-summary.txt` still works.
- **Uncertainty:** none on the core flaw. The exact set of readable files depends on OS permissions.

### SC-02: Anyone can change grades with no login
- **Input and data flow:** the JSON body fields `student_id`, `course_id` and `grade` (L130–134) go to `find_grade`, then either mutate a row (L140) or append a new one (L138).
- **Code fact:** the function never reads `flask.session`. It has no authentication and no role or course check.
- **Inferred requirement:** A2/A3. Only the professor of that course, or an admin, should be able to write grades.
- **Root cause:** authorization is missing entirely on a state-changing operation.
- **Impact:** an anonymous user, or any student, can change any grade, including their own, and can create grades for any course or student. This is a complete loss of grade integrity.
- **Test:** with no cookie, `POST /grades/update` with `{"student_id":1001,"course_id":"SRS","grade":20}`, then `GET /grades/1001`. Repeat the POST logged in as `alice`, and as `prof_srs` for course `SSD`. The expected secure result is 401 or 403 for all three.

### SC-03: Missing authorization on grade reads (IDOR)
- **Input and data flow:** the `student_id` path segment (L123) goes through `int()` and filters `GRADES` (L125).
- **Code fact:** the session is never checked.
- **Inferred requirement:** A1/A2.
- **Impact:** anyone can read every student's grades by counting through IDs. This is a confidentiality breach of academic records.
- **Test:** with no cookie, and again as `bob`, send `GET /grades/1001`. The expected secure result is 401 or 403.

### SC-04: Missing authorization on profile reads (personal data exposure)
- **Input and data flow:** the `student_id` path segment (L116) is used for a `STUDENT_PROFILES` lookup (L117).
- **Code fact:** there is no authentication. The response includes the student's name and email.
- **Inferred requirement:** A1. Whether professors may see profiles is a policy decision I can't infer.
- **Impact:** anyone can count through IDs and collect personal data (a GDPR concern, given the `uc.pt` domain).
- **Test:** with no cookie, and as `bob`, send `GET /students/1001/profile`. The expected secure result is 401 or 403.

### SC-05: Hardcoded, guessable `SECRET_KEY` allows session forgery
- **Code facts:** the key is the literal `"dev-secret-key"` (L8). Flask's default sessions are client-side cookies that are signed with this key but not encrypted. The `role`, `student_id` and `courses` values are stored in them (L91–94).
- **Root cause:** the secret is hardcoded and guessable, and authorization data is trusted from the client.
- **Impact:** anyone who knows or guesses the key, or reads it via SC-01, can forge a cookie with `role=admin` or any `courses`. Today this is *latent*, because no endpoint enforces roles. It becomes a full authorization bypass as soon as the checks for SC-02 to SC-04 rely on the session. Separately, cookie contents can be decoded without the key.
- **Test:** sign `{"user":"x","role":"admin"}` with the same signing scheme and key (itsdangerous `URLSafeTimedSerializer`, salt `cookie-session`), send it as the cookie, and call `/me`. The finding is confirmed if `/me` returns the forged role.

### SC-06: Debug server bound to all interfaces
- **Code fact:** the app runs with `app.run(debug=True, host="0.0.0.0")` (L159).
- **Inference:** debug mode enables the Werkzeug debugger. Its `/console` is reachable from the network behind a PIN. That PIN is derived from host data that SC-01 can read, which is a known chain to remote code execution.
- **Uncertainty:**
  - The catch-all handler (L150) probably stops the debugger traceback pages from appearing, but `/console` still does not depend on that handler.
  - This only applies when the file is started directly, not through a WSGI server.
  - Behavior depends on the Werkzeug version, which I can't see.
- **Test:** start the app via `__main__` and request `/console` from another host. The finding is confirmed if a PIN prompt appears, and rejected if the response is 404.

### SC-07: Plaintext, weak, hardcoded passwords; no brute-force limits
- **Code facts:**
  - Passwords are stored in plaintext in the source (L36–43) and are trivially weak (`adminpw`).
  - The comparison uses `!=` (L88), which is not constant-time.
  - `/login` has no rate limiting or lockout.
- **Impact:** source exposure via SC-01 or the repository gives every credential, including admin. Online guessing is also feasible.
- **Lower confidence:** the timing side channel is negligible in practice. The login error message is the same for an unknown user and a wrong password, so it does not reveal which usernames exist (good).
- **Test:** inspection confirms the storage issue. For brute force, send 100 failed logins in a row and check whether throttling, 429 or lockout ever occurs.

### SC-08: Verbose catch-all error handler
- **Code fact:** `@app.errorhandler(Exception)` (L150) returns `str(exc)` and the class name with status 500 for *every* exception. In Flask that includes HTTP errors such as 404, 405 and 415.
- **Impact:**
  - It leaks internal details, for example the absolute filesystem path in `FileNotFoundError` from `/files?path=nope`, which helps SC-01.
  - Different errors for missing vs. existing files and directories give an attacker a way to test whether a path exists.
  - Turning client errors into 500 hides attacks and breaks monitoring.
  - Non-numeric IDs (`int("abc")`, L117/L124) also become 500 instead of 400.
- **Test:** send `GET /files?path=nope`, `GET /students/abc/profile` and `GET /nonexistent`. The finding is confirmed if the responses are 500 with paths or exception text.

### SC-09: No input validation on grade updates
- **Input and data flow:** the request body goes through `get_json()` (L130) and its fields are used directly (L132–140).
- **Code facts:** nothing validates that:
  - the body exists or is JSON (a missing body or wrong content type leads to an exception and a 500 via SC-08; the exact path depends on the Flask version);
  - the student or course actually exists;
  - the types are right (a string `"1001"` doesn't match the int `1001`, so a duplicate "shadow" row is appended that `GET /grades/1001` never shows);
  - the grade is in range (any value of any JSON type is accepted).
- **Inferred requirement:** grades should be numbers on an assumed 0–20 scale, for an existing enrolled student and an existing course.
- **Impact:** corrupted data, inconsistent records, and (with SC-11) unlimited memory growth.
- **Test:** POST `{"student_id":"1001","course_id":"SRS","grade":"A+"}` and `{"student_id":9999,"course_id":"X","grade":-50}`, then send an empty body. The expected secure result is 400 or 422 in every case.

### SC-10: Session management weaknesses
- **Code facts:**
  - Logout only clears the client's cookie (L100). Because the session is stored client-side, a copied cookie stays valid until Flask's signature max-age runs out (31 days by default), with no server-side revocation.
  - The role and courses are cached at login, so a revoked privilege persists.
  - `SESSION_COOKIE_SECURE` and `SAMESITE` are not set.
  - There is no CSRF protection on form-based `/login` (login CSRF) or `/logout`.
- **Partly mitigated:** for `/grades/update`, a cross-site JSON request triggers a CORS preflight. That partly mitigates CSRF once authentication is added, but only if the JSON content type is strictly enforced.
- **Test:** log in, save the cookie, log out, then replay the saved cookie to `/me`. The finding is confirmed if the replay still shows an authenticated user.

### SC-11: Unsynchronized, unbounded mutation of shared state
- **Code facts:** the global `GRADES` list is read and then written with no lock (L136–140), and the development server is threaded by default. It also grows without bound through anonymous appends (SC-02).
- **Impact:** a race in the check-then-insert (`find_grade` then `append`) can create duplicate rows, and repeated appends can exhaust memory.
- **Confidence:** low to medium. This is a demo store, and Python's GIL limits corruption to logic-level duplicates.
- **Test:** fire concurrent POSTs for a new `(student, course)` pair and count the resulting rows.

### SC-12: Unauthenticated endpoint list
The index (L67–80) lists every route to anyone, which makes reconnaissance easier. On its own this is informational and only matters in combination with the findings above.

## Limits of this review
- I couldn't see Flask or Werkzeug versions, how the app is deployed (WSGI server, reverse proxy, TLS) or the OS permissions, so findings that depend on them are marked with lower confidence.
- I did not review the security of dependencies.
- Finding nothing in an area I didn't examine is not evidence that the area is safe.