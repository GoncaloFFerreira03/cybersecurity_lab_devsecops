# Static Security Review — Baseline Secure Coding API

Scope: static reading of `baseline_secure_coding_api.py` only; nothing was executed. Line numbers refer to that file. **Fact** = demonstrated in code; **Inferred** = depends on deployment, library version, or requirement interpretation.

## Findings table

| ID | Title | Location | Req. | Severity | Confidence |
|---|---|---|---|---|---|
| F01 | Missing authentication on protected endpoints; no 401/403 distinction | `get_profile` L115–120, `get_grades` L122–126, `update_grade` L128–142, `download_file` L144–148 | R1, R7 | Critical | High |
| F02 | Profile IDOR — any caller (incl. professors) reads any profile | `get_profile` L115–120 | R2, R3, R4 | High | High |
| F03 | Grade-read IDOR — no per-record / per-course filtering | `get_grades` L122–126 | R2, R3, R4 | High | High |
| F04 | Unauthorized grade modification — anyone can change any grade | `update_grade` L128–142 | R3, R4 | Critical | High |
| F05 | Missing input validation on grade update | `update_grade` L130–140 | R5, R7 | High | High |
| F06 | Weak student-identifier validation in path params | L117, L124 | R5, R7 | Low–Medium | High |
| F07 | Path traversal / arbitrary file read | `download_file` L146–148 | R6 | Critical | High |
| F08 | Global error handler leaks details and maps all errors to 500 | `handle_error` L150–155 | R7 | Medium | High |
| F09 | Hard-coded, guessable `SECRET_KEY` → session cookie forgery | L8, L91–94 | R1, R4 | High | High (Inferred: key reused in deployment) |
| F10 | Authorization attributes (role, courses) stored in client-side session; no server-side revocation | L91–94, L98–101 | R4 | Medium | Medium |
| F11 | Plaintext passwords, non-constant-time compare, no brute-force limiting | L36–43, L87–89 | R1 | Medium | Medium |
| F12 | Werkzeug debug mode bound to all interfaces | L159 | R7 | Medium–High | Medium (Inferred: run via `__main__`) |
| F13 | Unsynchronized mutation of shared in-memory state | L50–54, L136–140 | R7 (integrity) | Low | Low–Medium |
| F14 | Cookie hardening / CSRF posture not configured | L7–8, L82–101 | R1 | Low | Low–Medium |

## Supporting explanations

### F01 — Missing authentication
- **Input / path:** Any HTTP request, with or without a session cookie, reaches L115, L122, L128, L144.
- **Control / root cause (Fact):** None of these handlers checks `flask.session["user"]`; there is no decorator or `before_request` hook. Only `/me` reads the session. No code path returns 401 or 403.
- **Preconditions / impact:** None required; anonymous network attacker gets all capabilities in F02–F07.
- **Test:** With a fresh client (no login), `GET /students/1001/profile`, `GET /grades/1001`, `POST /grades/update`, `GET /files?path=srs-summary.txt` → expect 401 each. Currently 200.
- **Assumptions:** None — R1 is explicit.

### F02 — Profile IDOR
- **Input / path:** URL `student_id` → `int()` (L117) → `STUDENT_PROFILES` lookup → returned in full (L120).
- **Control / root cause (Fact):** No comparison against `session["student_id"]`; no role check. Professors are not denied (R3 says they must be).
- **Impact:** PII disclosure (name, email, programme) for all students; 200/404 difference enables student-ID enumeration.
- **Test:** Login as alice → `/students/1002/profile` → expect 403. Login as prof_srs → `/students/1001/profile` → expect 403. admin1 → 200.

### F03 — Grade-read IDOR
- **Input / path:** `student_id` (L124) → unconditional filter over `GRADES` (L125).
- **Control / root cause (Fact):** No filtering by requester's own `student_id` or by professor `courses`. Unknown/unpermitted IDs return `200 []` rather than the denial R4 requires.
- **Impact:** Students see others' grades; SRS professor sees SSD grades.
- **Test:** alice → `/grades/1002` → 403. prof_srs → `/grades/1001` → only the SRS row. prof_srs → student with only SSD grades → 403. alice → `/grades/9999` → 403/404, not `[]`.

### F04 — Unauthorized grade modification
- **Input / path:** JSON body (L130) → `find_grade` (L136) → mutate (L140) or append (L138).
- **Control / root cause (Fact):** No role or course check; students, anonymous callers, and out-of-scope professors can all write.
- **Impact:** Complete loss of grade integrity (e.g., alice sets her own grade to 20; anyone inserts fabricated records).
- **Test:** As alice, POST `{"student_id":1001,"course_id":"SRS","grade":20}` → expect 403 and grade still 14. As prof_srs, update SSD → 403; update SRS → 200.

### F05 — Grade-update input validation
- **Input / path:** `student_id`, `course_id`, `grade` from L132–134 stored verbatim at L138/L140.
- **Root causes (Fact):**
  - No type or range checks: `grade` of `true`, `"A"`, `-5`, `999`, `null`, or nested objects is accepted and stored; same for `course_id: "XYZ"`.
  - `student_id` not validated against `STUDENT_PROFILES`; unknown IDs or the string `"1001"` (which doesn't match int key) create orphan records via `append`.
  - Missing key → `KeyError`; non-object body → `TypeError`/`KeyError`; both reach F08 → 500 with details instead of 400.
  - Unbounded record creation → memory growth (DoS).
- **Inferred:** `get_json()` behaviour on wrong Content-Type / invalid JSON is version-dependent (older Flask returns `None`; ≥2.1 raises 400/415); either way F08 converts it to 500.
- **Test:** Parameterized malformed bodies (missing fields, `true`, `"15"`, `-1`, `21`, `15.5` if integers required, unknown course, unknown student, `[]`, non-JSON body) → each 400/422 and `GRADES` unchanged afterwards.
- **Assumption:** R5 says "numeric 0–20"; whether non-integers (e.g., `15.5`) are valid is not stated.

### F06 — Path-parameter ID validation
- **Input / path:** `<student_id>` string → `int()` at L117/L124.
- **Root cause (Fact):** Python `int()` accepts `-1`, `0`, `+1001`, `" 1001 "`, `1_001`, and Unicode digits — none fit "positive integer". Non-numeric input raises `ValueError` → F08 returns 500 including the input.
- **Impact:** Mostly correctness and info disclosure; alternative spellings could defeat future ID-based checks (e.g., string comparisons) or confuse logging.
- **Test:** `/grades/abc` → 400 without exception text; `/grades/-1`, `/grades/0` → 400; `/grades/1_001` → rejected.

### F07 — Path traversal / arbitrary file read
- **Input / path:** `path` query param (L146) → `MATERIALS_DIR / raw_path` (L147) → `send_file` (L148).
- **Root cause (Fact):** No check that the resolved path stays inside `MATERIALS_DIR`. `../` escapes; additionally, pathlib discards the base when the right operand is absolute, so `MATERIALS_DIR / "/etc/passwd"` → `/etc/passwd`. No symlink protection.
- **Impact:** Read any file the process can read, e.g., `?path=../baseline_secure_coding_api.py` exposes source, `SECRET_KEY`, and plaintext passwords → chains directly into F09 (forged admin session). Empty or nonexistent paths leak absolute server paths via F08.
- **Test:** `?path=../baseline_secure_coding_api.py`, `?path=/etc/passwd`, `?path=..%2f..%2fetc%2fpasswd` → expect 400/404 and no content; `?path=` → 400; `?path=srs-summary.txt` with session → 200.

### F08 — Error handler information leakage
- **Path:** Any exception, including Werkzeug `HTTPException` subclasses (NotFound, MethodNotAllowed, BadRequest) → L150.
- **Root cause (Fact):** Returns `str(exc)` and class name, always with status 500. Loses 4xx semantics and reveals internals (e.g., `[Errno 2] No such file or directory: '/abs/path/...'`).
- **Inferred:** In Flask ≥1.1 an `Exception` handler also catches HTTPExceptions, so even an unknown route returns 500 instead of 404.
- **Test:** `GET /nonexistent` → 404; `GET /files?path=nope` → 404 without an absolute path in the body; `/grades/abc` → 400 without exception text.

### F09 — Hard-coded `SECRET_KEY`
- **Root cause (Fact):** `"dev-secret-key"` in source (L8). Flask default sessions are client-side signed cookies; `role` is stored in the session (L92).
- **Impact:** Anyone knowing/guessing the key (or reading it via F07) can sign `{"user":"x","role":"admin"}` — a full authorization bypass once role checks exist.
- **Preconditions (Inferred):** Deployed instance uses the same key; nothing loads it from the environment.
- **Test:** Use `itsdangerous` / Flask's `SecureCookieSessionInterface` with the known key to mint an admin cookie; call `/me` → currently shows `role: admin`. After a fix, the key must come from configuration and startup should fail if it is absent.

### F10 — Authorization state in client-side session
- **Root cause (Fact):** `role`, `student_id`, `courses` copied into the cookie at login (L91–94). `logout` only clears the client copy (L100); there is no server-side session store.
- **Impact (Inferred):** A captured cookie remains valid after logout (no server-side expiry); role/course changes don't take effect until re-login; authorization built on `session["role"]` trusts cookie contents and inherits F09.
- **Test:** Login, copy cookie, logout, replay old cookie to `/me` → currently still authenticated.

### F11 — Credential handling
- **Facts:** Plaintext passwords (L36–43); `!=` comparison (L88), not constant-time; different code path for unknown user vs. wrong password; no rate limiting or lockout.
- **Impact:** Credential exposure on source/memory disclosure (see F07); online brute force; theoretical but weak username-enumeration timing oracle (low).
- **Assumption:** Demo credentials are acceptable for teaching; risk applies if the pattern reaches production.
- **Test:** 1,000 consecutive failed logins → expect throttling/lockout; code review for a password hash (bcrypt/argon2) and `hmac.compare_digest`.

### F12 — Debug mode on all interfaces
- **Fact:** `app.run(debug=True, host="0.0.0.0")` (L159).
- **Impact (Inferred):** Enables the Werkzeug debugger and reloader on all interfaces. The console is PIN-protected, but the PIN is derivable from machine data that F07 can read → potential RCE. Applies only when run as `__main__`, not under a WSGI server.
- **Test:** Run directly and check whether `/console` is reachable from another host; after a fix, debug must be off unless explicitly configured.

### F13 — Concurrency on shared state
- **Fact:** Module-level `GRADES` list read and mutated (L136–140) without a lock.
- **Inferred:** Under a threaded server with multiple users, two concurrent updates for the same new (student, course) pair can both miss in `find_grade` and both append → duplicate records and ambiguous reads. The in-memory store is a simplification, so this matters only if the pattern carries over.
- **Test:** Fire N concurrent identical updates for a new pair; assert exactly one row.

### F14 — Cookie hardening / CSRF
- **Facts:** `SESSION_COOKIE_SECURE` and `SESSION_COOKIE_SAMESITE` not set; no CSRF token on form-encoded `/login` or `/logout`.
- **Inferred:** Modern browsers default to SameSite=Lax, limiting cross-site POST; `/grades/update` requires JSON, which forces a CORS preflight and hinders classic CSRF. Residual risks: login CSRF, forced logout, cookie sent over plain HTTP.
- **Test:** Inspect `Set-Cookie` attributes after login; submit a cross-origin form POST to `/login` and check whether the session switches.

## Scope and uncertainty notes
- **Interacting findings:** The highest-impact chain is F07 → source disclosure → F09 forged admin cookie. Fixing F01–F04 with session-based checks alone would leave that chain open.
- **Requirement gaps:** Not specified whether admins may download materials (R6 says "authenticated users", assumed yes), whether non-integer grades are valid, or whether professors may *create* a missing grade row versus only update existing ones. These are flagged rather than decided.
- **Limits:** Some behaviour (`get_json` error handling, error-handler treatment of `HTTPException`, `send_file` on a directory) depends on the Flask/Werkzeug version and was not confirmed by execution. The absence of further findings is not evidence of safety.