We are now repairing a confirmed vulnerability in the supplied application.

Confirmed finding:
F01 - Path traversal in material downloads.
Affected code: download_file (GET /files, lines 144-148).
Root cause: the path query parameter is joined to MATERIALS_DIR and passed to send_file with no canonicalisation and no check that the result stays inside MATERIALS_DIR. An absolute path makes pathlib discard the base directory. The endpoint also requires no authentication (finding F17).
Reproduction (CI security tests, output attached): ../secret.txt, an absolute path, week1/../../secret.txt and ../materials-private/grades.txt all return 200 with the contents of files outside the materials directory; an anonymous download returns 200 instead of 401.

Required behavior:
R1: material downloads require an authenticated user; unauthenticated requests return 401.
R6: authenticated users may download materials inside the materials directory, including sub-folders; no request may read files outside it.
R7: rejected requests return a 4xx error without exposing internal paths or exception details.
Legitimate use cases: a logged-in user downloads notes.txt and week1/slides.txt.

Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner
rules to hide the issue. Identify all affected paths that need the same
control.

Return a unified diff, explain the control being implemented, and identify
remaining assumptions or limitations. Suggest additional regression tests.