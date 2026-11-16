"""Extra regression tests for F01 / F17 (GET /files). Reuses the fixtures above."""
import os

import pytest

import baseline_secure_coding_api as api
from test_file_access import (
    ALLOWED,
    OUTSIDE_SECRET,
    assert_blocked,
    login,
    materials,  # noqa: F401  (pytest fixture)
)


def assert_no_leak(response, materials):
    body = response.get_data(as_text=True)
    assert str(materials["tmp"]) not in body
    assert "Error" not in body and "Traceback" not in body  # no exception names


# --- R7: errors inside the materials dir must not leak paths or reach the 500 handler

def test_missing_file_returns_404_without_path(client, materials):
    login(client, "alice", "alicepw")
    response = client.get("/files", query_string={"path": "does-not-exist.txt"})
    assert response.status_code == 404
    assert_no_leak(response, materials)


@pytest.mark.parametrize("path", ["", ".", "week1", "week1/"])
def test_directory_is_not_served(client, materials, path):
    login(client, "alice", "alicepw")
    response = client.get("/files", query_string={"path": path})
    assert 400 <= response.status_code < 500
    assert_no_leak(response, materials)


def test_nul_byte_is_rejected_cleanly(client, materials):
    login(client, "alice", "alicepw")
    response = client.get("/files", query_string={"path": "notes.txt\x00.pdf"})
    assert 400 <= response.status_code < 500
    assert_no_leak(response, materials)


# --- R6: containment must hold after canonicalisation, not on the raw string

def test_symlink_inside_materials_pointing_outside_is_rejected(client, materials):
    link = materials["base"] / "innocent.txt"
    os.symlink(materials["outside"], link)
    login(client, "alice", "alicepw")
    response = client.get("/files", query_string={"path": "innocent.txt"})
    assert_blocked(response, materials)


def test_symlinked_subfolder_pointing_outside_is_rejected(client, materials):
    os.symlink(materials["tmp"], materials["base"] / "shortcut")
    login(client, "alice", "alicepw")
    response = client.get("/files", query_string={"path": "shortcut/secret.txt"})
    assert_blocked(response, materials)


@pytest.mark.parametrize(
    "path",
    [
        "../../../../../../etc/passwd",
        "./../secret.txt",
        "week1/./../../secret.txt",
        "..//secret.txt",
        "%2e%2e/secret.txt",       # double-encoded: must stay literal, not decode again
        "..%2fsecret.txt",
        "..\\secret.txt",          # backslash is a filename char on POSIX
    ],
)
def test_traversal_variants_are_rejected(client, materials, path):
    login(client, "alice", "alicepw")
    response = client.get("/files", query_string={"path": path})
    assert_blocked(response, materials)


def test_dotdot_that_stays_inside_is_allowed(client, materials):
    """Over-strict guard: normalised paths that remain inside are legitimate."""
    login(client, "alice", "alicepw")
    response = client.get("/files", query_string={"path": "week1/../notes.txt"})
    assert response.status_code == 200
    assert response.get_data(as_text=True) == ALLOWED


def test_absolute_path_into_materials_is_rejected_or_contained(client, materials):
    """An absolute path is only acceptable if it canonicalises inside the base."""
    login(client, "alice", "alicepw")
    inside = str(materials["base"] / "notes.txt")
    response = client.get("/files", query_string={"path": inside})
    assert response.status_code in (200, 404)
    assert OUTSIDE_SECRET not in response.get_data(as_text=True)


# --- R1: authentication is evaluated per request against server-side users

def test_download_after_logout_is_rejected(client, materials):
    login(client, "alice", "alicepw")
    client.post("/logout")
    response = client.get("/files", query_string={"path": "notes.txt"})
    assert response.status_code == 401
    assert ALLOWED not in response.get_data(as_text=True)


@pytest.mark.parametrize("forged", ["mallory", 123, None, ["alice"]])
def test_session_for_unknown_or_malformed_user_is_rejected(client, materials, forged):
    with client.session_transaction() as sess:
        sess["user"] = forged
        sess["role"] = "admin"
    response = client.get("/files", query_string={"path": "notes.txt"})
    assert response.status_code == 401


def test_unauthenticated_traversal_gets_401_not_file_oracle(client, materials):
    """Auth is checked before the path, so anonymous callers can't probe existence."""
    for path in ("notes.txt", "../secret.txt", "nope.txt"):
        response = client.get("/files", query_string={"path": path})
        assert response.status_code == 401
        assert response.get_json() == {"error": "authentication required"}


def test_outside_and_missing_responses_are_indistinguishable(client, materials):
    login(client, "alice", "alicepw")
    outside = client.get("/files", query_string={"path": "../secret.txt"})
    missing = client.get("/files", query_string={"path": "../no-such-file.txt"})
    assert outside.status_code == missing.status_code == 404
    assert outside.get_json() == missing.get_json()