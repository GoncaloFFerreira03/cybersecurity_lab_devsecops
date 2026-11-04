from baseline_secure_coding_api import app


def test_index_lists_endpoints():
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    data = response.get_json()
    assert data["message"] == "Baseline Secure Coding API"
    assert "POST /login" in data["endpoints"]


def test_me_without_login_returns_no_user():
    client = app.test_client()

    response = client.get("/me")

    assert response.status_code == 200
    data = response.get_json()
    assert data["user"] is None


def test_login_with_valid_credentials():
    client = app.test_client()

    response = client.post(
        "/login",
        data={"username": "alice", "password": "alicepw"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["user"] == "alice"
    assert data["role"] == "student"
    assert data["student_id"] == 1001


def test_get_student_profile():
    client = app.test_client()

    response = client.get("/students/1001/profile")

    assert response.status_code == 200
    data = response.get_json()
    assert data["student_id"] == 1001
    assert data["name"] == "Alice"


def test_get_student_grades():
    client = app.test_client()

    response = client.get("/grades/1001")

    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, list)
    assert any(row["course_id"] == "SRS" for row in data)