import copy

import baseline_secure_coding_api as api


def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username


def snapshot():
    return copy.deepcopy(api.GRADES)


def test_assigned_professor_can_update_grade(client):
    login(client, "prof_srs", "profpw")
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 18},
    )
    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18


def test_admin_can_update_grade_in_any_course(client):
    """R3: administrators may update grades, including courses no professor here owns."""
    login(client, "admin1", "adminpw")
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SSD", "grade": 17},
    )
    assert response.status_code == 200
    assert api.find_grade(1001, "SSD")["grade"] == 17

def test_unauthenticated_update_is_rejected_and_data_unchanged(client):
    """R1 + R7: no session -> 401 and GRADES untouched."""
    before = snapshot()
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 20},
    )
    assert response.status_code == 401
    assert api.GRADES == before


def test_student_cannot_update_own_grade(client):
    """R3/R4: being logged in and owning the record does not grant write access."""
    login(client, "alice", "alicepw")
    before = snapshot()
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 20},
    )
    assert response.status_code == 403
    assert api.GRADES == before



def test_professor_cannot_update_grade_outside_assigned_course(client):
    """R3/R4: a "login + role == professor" patch would wrongly allow this.

    prof_srs is assigned only to SRS; Alice's SSD grade (16) must not change.
    """
    login(client, "prof_srs", "profpw")
    before = snapshot()
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SSD", "grade": 0},
    )
    assert response.status_code == 403
    assert api.GRADES == before


def test_professor_cannot_create_grade_in_unassigned_course(client):
    """R3/R4: the insert branch (find_grade -> append) needs the same course check.

    Bob has no SSD record; a patch that only guards the overwrite branch would
    still let prof_srs create one.
    """
    login(client, "prof_srs", "profpw")
    before = snapshot()
    response = client.post(
        "/grades/update",
        json={"student_id": 1002, "course_id": "SSD", "grade": 20},
    )
    assert response.status_code == 403
    assert api.find_grade(1002, "SSD") is None
    assert api.GRADES == before
