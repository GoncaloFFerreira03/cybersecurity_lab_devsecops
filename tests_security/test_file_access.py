import pytest

import baseline_secure_coding_api as api

ALLOWED = "Allowed teaching material"
NESTED = "Nested teaching material"
OUTSIDE_SECRET = "OUTSIDE-SECRET-7f3a"
SIBLING_SECRET = "SIBLING-SECRET-91c2"


def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username


@pytest.fixture
def materials(tmp_path, monkeypatch):
    """tmp/materials/{notes.txt, week1/slides.txt}, tmp/secret.txt, tmp/materials-private/grades.txt"""
    base = tmp_path / "materials"
    (base / "week1").mkdir(parents=True)
    (base / "notes.txt").write_text(ALLOWED, encoding="utf-8")
    (base / "week1" / "slides.txt").write_text(NESTED, encoding="utf-8")

    outside = tmp_path / "secret.txt"
    outside.write_text(OUTSIDE_SECRET, encoding="utf-8")

    sibling_dir = tmp_path / "materials-private"
    sibling_dir.mkdir()
    (sibling_dir / "grades.txt").write_text(SIBLING_SECRET, encoding="utf-8")

    monkeypatch.setattr(api, "MATERIALS_DIR", base)
    return {"base": base, "outside": outside, "tmp": tmp_path}


def assert_blocked(response, materials):
    body = response.get_data(as_text=True)
    assert 400 <= response.status_code < 500
    assert OUTSIDE_SECRET not in body
    assert SIBLING_SECRET not in body
    assert str(materials["tmp"]) not in body  # R7: no internal paths


def test_authenticated_user_can_download_material(client, materials):
    login(client, "alice", "alicepw")
    response = client.get("/files", query_string={"path": "notes.txt"})
    assert response.status_code == 200
    assert response.get_data(as_text=True) == ALLOWED


def test_authenticated_user_can_download_material_in_subfolder(client, materials):
    """Guards against an over-strict patch that rejects every '/'."""
    login(client, "alice", "alicepw")
    response = client.get("/files", query_string={"path": "week1/slides.txt"})
    assert response.status_code == 200
    assert response.get_data(as_text=True) == NESTED


def test_relative_traversal_is_rejected(client, materials):
    login(client, "alice", "alicepw")
    response = client.get("/files", query_string={"path": "../secret.txt"})
    assert_blocked(response, materials)


def test_absolute_path_is_rejected(client, materials):
    """pathlib drops the base for an absolute right operand; a '..' filter misses this."""
    login(client, "alice", "alicepw")
    response = client.get("/files", query_string={"path": str(materials["outside"])})
    assert_blocked(response, materials)


def test_traversal_hidden_after_valid_subfolder_is_rejected(client, materials):
    """A check on the first path segment only would accept this."""
    login(client, "alice", "alicepw")
    response = client.get("/files", query_string={"path": "week1/../../secret.txt"})
    assert_blocked(response, materials)


def test_sibling_directory_with_same_prefix_is_rejected(client, materials):
    """materials-private starts with 'materials'; a str.startswith() check accepts it."""
    login(client, "alice", "alicepw")
    response = client.get(
        "/files", query_string={"path": "../materials-private/grades.txt"}
    )
    assert_blocked(response, materials)


def test_unauthenticated_download_is_rejected(client, materials):
    response = client.get("/files", query_string={"path": "notes.txt"})
    assert response.status_code == 401
    assert ALLOWED not in response.get_data(as_text=True)
