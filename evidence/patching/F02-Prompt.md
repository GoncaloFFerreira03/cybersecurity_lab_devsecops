We are now repairing a confirmed vulnerability in the supplied application.

Confirmed finding:
F02 - Missing authorization on grade updates.
Affected code: update_grade (POST /grades/update, lines 128-142).
Root cause: the handler never reads the session, so it checks neither authentication, nor role, nor the professor's assigned courses before updating or appending a row in GRADES.
Reproduction (CI security tests, output attached): an anonymous request returns 200 instead of 401; student alice updating her own grade returns 200 instead of 403; prof_srs (assigned only to SRS) updating or creating an SSD grade returns 200 instead of 403. In every case GRADES is modified.

Required behavior:
R1: grade updates require an authenticated user; unauthenticated requests return 401.
R3: professors may update grades only for their assigned courses; administrators may update any grade; students may not update grades.
R4: authorization is checked on every request; login or a role name alone does not grant permission.
R7: unauthorized requests return 403, and a denied update leaves stored data unchanged.
Legitimate use cases: prof_srs updates an SRS grade; admin1 updates an SSD grade.

Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner
rules to hide the issue. Identify all affected paths that need the same
control.

Return a unified diff, explain the control being implemented, and identify
remaining assumptions or limitations. Suggest additional regression tests.