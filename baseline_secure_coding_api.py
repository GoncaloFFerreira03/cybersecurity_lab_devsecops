import dataclasses
import pathlib
import typing

import flask

app = flask.Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key"

# -----------------------------------------------------------------------------
# Intentionally small in-memory "database"
# -----------------------------------------------------------------------------

BASE_DIR = pathlib.Path(__file__).resolve().parent
MATERIALS_DIR = BASE_DIR / "materials"
MATERIALS_DIR.mkdir(exist_ok=True)

# Seed a couple of demo files.
(MATERIALS_DIR / "srs-summary.txt").write_text(
    "Secure Requirements Engineering summary", encoding="utf-8"
)
(MATERIALS_DIR / "secure-coding.txt").write_text(
    "Secure coding practices notes", encoding="utf-8"
)


@dataclasses.dataclass
class User:
    username: str
    password: str
    role: str
    student_id: typing.Optional[int] = None
    courses: typing.Optional[list[str]] = None


USERS = {
    "alice": User(username="alice", password="alicepw", role="student", student_id=1001),
    "bob": User(username="bob", password="bobpw", role="student", student_id=1002),
    "prof_srs": User(
        username="prof_srs", password="profpw", role="professor", courses=["SRS"]
    ),
    "admin1": User(username="admin1", password="adminpw", role="admin"),
}

STUDENT_PROFILES = {
    1001: {"student_id": 1001, "name": "Alice", "email": "alice@uc.pt", "program": "MEI"},
    1002: {"student_id": 1002, "name": "Bob", "email": "bob@uc.pt", "program": "MEI"},
}

GRADES = [
    {"student_id": 1001, "course_id": "SRS", "grade": 14},
    {"student_id": 1002, "course_id": "SRS", "grade": 15},
    {"student_id": 1001, "course_id": "SSD", "grade": 16},
]

def find_grade(student_id, course_id):
    for row in GRADES:
        if row["student_id"] == student_id and row["course_id"] == course_id:
            return row
    return None


# -----------------------------------------------------------------------------
# Authorization helpers
# -----------------------------------------------------------------------------

def current_user():
    """Resolve the session to the server-side user record on every request.

    Only the username is taken from the session; role and course assignments
    come from USERS, so stale or tampered session claims grant nothing.
    """
    username = flask.session.get("user")
    if not isinstance(username, str):
        return None
    return USERS.get(username)


def can_write_grade(user, course_id):
    """R3: admins may write any grade; professors only their assigned courses."""
    if user.role == "admin":
        return True
    if user.role == "professor":
        return course_id in (user.courses or [])
    return False  # students and any unknown role: deny by default


# -----------------------------------------------------------------------------
# REST API Endpoints
# -----------------------------------------------------------------------------

@app.get("/")
def index():
    return {
        "message": "Baseline Secure Coding API",
        "endpoints": [
            "POST /login",
            "POST /logout",
            "GET /me",
            "GET /students/<student_id>/profile",
            "POST /grades/update",
            "GET /grades/<student_id>",
            "GET /files?path=<name>",
        ],
    }

@app.post("/login")
def login():
    username = flask.request.form.get("username", "")
    password = flask.request.form.get("password", "")

    user = USERS.get(username)
    if user is None or user.password != password:
        return {"error": "invalid credentials"}, 401

    flask.session["user"] = user.username
    flask.session["role"] = user.role
    flask.session["student_id"] = user.student_id
    flask.session["courses"] = user.courses or []

    return flask.redirect("/me")

@app.post("/logout")
def logout():
    flask.session.clear()
    return {"status": "logged out"}

@app.get("/me")
def me():
    if "user" not in flask.session:
        return {"user": None}

    return {
        "user": flask.session.get("user"),
        "role": flask.session.get("role"),
        "student_id": flask.session.get("student_id"),
        "courses": flask.session.get("courses"),
    }

@app.get("/students/<student_id>/profile")
def get_profile(student_id):
    profile = STUDENT_PROFILES.get(int(student_id))
    if profile is None:
        return {"error": "student not found"}, 404
    return flask.jsonify(profile)

@app.get("/grades/<student_id>")
def get_grades(student_id):
    sid = int(student_id)
    rows = [row for row in GRADES if row["student_id"] == sid]
    return flask.jsonify(rows)

@app.post("/grades/update")
def update_grade():
    # Return (body, status) tuples rather than flask.abort(): the catch-all
    # errorhandler(Exception) below would turn an HTTPException into a 500.
    user = current_user()
    if user is None:
        return {"error": "authentication required"}, 401

    data = flask.request.get_json(silent=True)
    if not isinstance(data, dict) or not {"student_id", "course_id", "grade"} <= data.keys():
        return {"error": "invalid request"}, 400

    student_id = data["student_id"]
    course_id = data["course_id"]
    grade = data["grade"]
    if not isinstance(course_id, str) or type(student_id) is not int:
        return {"error": "invalid request"}, 400

    # Checked before find_grade so the update and insert branches are both covered.
    if not can_write_grade(user, course_id):
        return {"error": "forbidden"}, 403

    row = find_grade(student_id, course_id)
    if row is None:
        GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
    else:
        row["grade"] = grade

    return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}

@app.get("/files")
def download_file():
    # R1: require a server-side user, same helper as /grades/update.
    user = current_user()
    if user is None:
        return {"error": "authentication required"}, 401

    # R6: canonicalise, then require the result to stay under MATERIALS_DIR.
    # resolve() collapses '..' and follows symlinks; an absolute path replaces
    # the base, which is_relative_to() then rejects. is_relative_to() compares
    # path components, so a sibling such as 'materials-private' does not match.
    # R7: one generic 404 for "outside", "missing", "not a file" and malformed
    # input, so callers learn nothing about the filesystem and no path or
    # exception text reaches the catch-all 500 handler.
    not_found = {"error": "file not found"}, 404
    raw_path = flask.request.args.get("path", "")
    base = pathlib.Path(MATERIALS_DIR).resolve()
    try:
        target = (base / raw_path).resolve()
    except (OSError, RuntimeError, ValueError):  # e.g. NUL byte, symlink loop
        return not_found
    if not target.is_relative_to(base) or not target.is_file():
        return not_found
    return flask.send_file(target)

@app.errorhandler(Exception)
def handle_error(exc):
    return {
        "error": str(exc),
        "type": exc.__class__.__name__,
    }, 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)