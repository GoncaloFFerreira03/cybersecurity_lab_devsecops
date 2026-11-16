

https://github.com/GoncaloFFerreira03/cybersecurity_lab_devsecops/actions/runs/43913051384/job/133459789831



Run python -m pytest -v tests_security
  python -m pytest -v tests_security
  shell: /usr/bin/bash -e {0}
  env:
    IMAGE_NAME: ghcr.io/GoncaloFFerreira03/cybersecurity_lab_devsecops/secure-coding-api
    pythonLocation: /opt/hostedtoolcache/Python/3.10.22/x64
    PKG_CONFIG_PATH: /opt/hostedtoolcache/Python/3.10.22/x64/lib/pkgconfig
    Python_ROOT_DIR: /opt/hostedtoolcache/Python/3.10.22/x64
    Python2_ROOT_DIR: /opt/hostedtoolcache/Python/3.10.22/x64
    Python3_ROOT_DIR: /opt/hostedtoolcache/Python/3.10.22/x64
    LD_LIBRARY_PATH: /opt/hostedtoolcache/Python/3.10.22/x64/lib
============================= test session starts ==============================
platform linux -- Python 3.10.22, pytest-9.2.0, pluggy-1.7.0 -- /opt/hostedtoolcache/Python/3.10.22/x64/bin/python
cachedir: .pytest_cache
rootdir: /home/runner/work/cybersecurity_lab_devsecops/cybersecurity_lab_devsecops
collecting ... collected 13 items

tests_security/test_file_access.py::test_authenticated_user_can_download_material PASSED [  7%]
tests_security/test_file_access.py::test_authenticated_user_can_download_material_in_subfolder PASSED [ 15%]
tests_security/test_file_access.py::test_relative_traversal_is_rejected FAILED [ 23%]
tests_security/test_file_access.py::test_absolute_path_is_rejected FAILED [ 30%]
tests_security/test_file_access.py::test_traversal_hidden_after_valid_subfolder_is_rejected FAILED [ 38%]
tests_security/test_file_access.py::test_sibling_directory_with_same_prefix_is_rejected FAILED [ 46%]
tests_security/test_file_access.py::test_unauthenticated_download_is_rejected FAILED [ 53%]
tests_security/test_grade_authorization.py::test_assigned_professor_can_update_grade PASSED [ 61%]
tests_security/test_grade_authorization.py::test_admin_can_update_grade_in_any_course PASSED [ 69%]
tests_security/test_grade_authorization.py::test_unauthenticated_update_is_rejected_and_data_unchanged FAILED [ 76%]
tests_security/test_grade_authorization.py::test_student_cannot_update_own_grade FAILED [ 84%]
tests_security/test_grade_authorization.py::test_professor_cannot_update_grade_outside_assigned_course FAILED [ 92%]
tests_security/test_grade_authorization.py::test_professor_cannot_create_grade_in_unassigned_course FAILED [100%]

=================================== FAILURES ===================================
_____________________ test_relative_traversal_is_rejected ______________________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = {'base': PosixPath('/tmp/pytest-of-runner/pytest-0/test_relative_traversal_is_rej0/materials'), 'outside': PosixPath('...ive_traversal_is_rej0/secret.txt'), 'tmp': PosixPath('/tmp/pytest-of-runner/pytest-0/test_relative_traversal_is_rej0')}

    def test_relative_traversal_is_rejected(client, materials):
        login(client, "alice", "alicepw")
        response = client.get("/files", query_string={"path": "../secret.txt"})
>       assert_blocked(response, materials)

tests_security/test_file_access.py:66: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

response = <WrapperTestResponse 19 bytes [200 OK]>
materials = {'base': PosixPath('/tmp/pytest-of-runner/pytest-0/test_relative_traversal_is_rej0/materials'), 'outside': PosixPath('...ive_traversal_is_rej0/secret.txt'), 'tmp': PosixPath('/tmp/pytest-of-runner/pytest-0/test_relative_traversal_is_rej0')}

    def assert_blocked(response, materials):
        body = response.get_data(as_text=True)
>       assert 400 <= response.status_code < 500
E       assert 400 <= 200
E        +  where 200 = <WrapperTestResponse 19 bytes [200 OK]>.status_code

tests_security/test_file_access.py:42: AssertionError
________________________ test_absolute_path_is_rejected ________________________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = {'base': PosixPath('/tmp/pytest-of-runner/pytest-0/test_absolute_path_is_rejected0/materials'), 'outside': PosixPath('...ute_path_is_rejected0/secret.txt'), 'tmp': PosixPath('/tmp/pytest-of-runner/pytest-0/test_absolute_path_is_rejected0')}

    def test_absolute_path_is_rejected(client, materials):
        """pathlib drops the base for an absolute right operand; a '..' filter misses this."""
        login(client, "alice", "alicepw")
        response = client.get("/files", query_string={"path": str(materials["outside"])})
>       assert_blocked(response, materials)

tests_security/test_file_access.py:73: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

response = <WrapperTestResponse 19 bytes [200 OK]>
materials = {'base': PosixPath('/tmp/pytest-of-runner/pytest-0/test_absolute_path_is_rejected0/materials'), 'outside': PosixPath('...ute_path_is_rejected0/secret.txt'), 'tmp': PosixPath('/tmp/pytest-of-runner/pytest-0/test_absolute_path_is_rejected0')}

    def assert_blocked(response, materials):
        body = response.get_data(as_text=True)
>       assert 400 <= response.status_code < 500
E       assert 400 <= 200
E        +  where 200 = <WrapperTestResponse 19 bytes [200 OK]>.status_code

tests_security/test_file_access.py:42: AssertionError
___________ test_traversal_hidden_after_valid_subfolder_is_rejected ____________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = {'base': PosixPath('/tmp/pytest-of-runner/pytest-0/test_traversal_hidden_after_va0/materials'), 'outside': PosixPath('...rsal_hidden_after_va0/secret.txt'), 'tmp': PosixPath('/tmp/pytest-of-runner/pytest-0/test_traversal_hidden_after_va0')}

    def test_traversal_hidden_after_valid_subfolder_is_rejected(client, materials):
        """A check on the first path segment only would accept this."""
        login(client, "alice", "alicepw")
        response = client.get("/files", query_string={"path": "week1/../../secret.txt"})
>       assert_blocked(response, materials)

tests_security/test_file_access.py:80: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

response = <WrapperTestResponse 19 bytes [200 OK]>
materials = {'base': PosixPath('/tmp/pytest-of-runner/pytest-0/test_traversal_hidden_after_va0/materials'), 'outside': PosixPath('...rsal_hidden_after_va0/secret.txt'), 'tmp': PosixPath('/tmp/pytest-of-runner/pytest-0/test_traversal_hidden_after_va0')}

    def assert_blocked(response, materials):
        body = response.get_data(as_text=True)
>       assert 400 <= response.status_code < 500
E       assert 400 <= 200
E        +  where 200 = <WrapperTestResponse 19 bytes [200 OK]>.status_code

tests_security/test_file_access.py:42: AssertionError
_____________ test_sibling_directory_with_same_prefix_is_rejected ______________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = {'base': PosixPath('/tmp/pytest-of-runner/pytest-0/test_sibling_directory_with_sa0/materials'), 'outside': PosixPath('...ng_directory_with_sa0/secret.txt'), 'tmp': PosixPath('/tmp/pytest-of-runner/pytest-0/test_sibling_directory_with_sa0')}

    def test_sibling_directory_with_same_prefix_is_rejected(client, materials):
        """materials-private starts with 'materials'; a str.startswith() check accepts it."""
        login(client, "alice", "alicepw")
        response = client.get(
            "/files", query_string={"path": "../materials-private/grades.txt"}
        )
>       assert_blocked(response, materials)

tests_security/test_file_access.py:89: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

response = <WrapperTestResponse 19 bytes [200 OK]>
materials = {'base': PosixPath('/tmp/pytest-of-runner/pytest-0/test_sibling_directory_with_sa0/materials'), 'outside': PosixPath('...ng_directory_with_sa0/secret.txt'), 'tmp': PosixPath('/tmp/pytest-of-runner/pytest-0/test_sibling_directory_with_sa0')}

    def assert_blocked(response, materials):
        body = response.get_data(as_text=True)
>       assert 400 <= response.status_code < 500
E       assert 400 <= 200
E        +  where 200 = <WrapperTestResponse 19 bytes [200 OK]>.status_code

tests_security/test_file_access.py:42: AssertionError
__________________ test_unauthenticated_download_is_rejected ___________________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = {'base': PosixPath('/tmp/pytest-of-runner/pytest-0/test_unauthenticated_download_0/materials'), 'outside': PosixPath('...henticated_download_0/secret.txt'), 'tmp': PosixPath('/tmp/pytest-of-runner/pytest-0/test_unauthenticated_download_0')}

    def test_unauthenticated_download_is_rejected(client, materials):
        response = client.get("/files", query_string={"path": "notes.txt"})
>       assert response.status_code == 401
E       assert 200 == 401
E        +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code

tests_security/test_file_access.py:94: AssertionError
__________ test_unauthenticated_update_is_rejected_and_data_unchanged __________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>

    def test_unauthenticated_update_is_rejected_and_data_unchanged(client):
        """R1 + R7: no session -> 401 and GRADES untouched."""
        before = snapshot()
        response = client.post(
            "/grades/update",
            json={"student_id": 1001, "course_id": "SRS", "grade": 20},
        )
>       assert response.status_code == 401
E       assert 200 == 401
E        +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code

tests_security/test_grade_authorization.py:47: AssertionError
_____________________ test_student_cannot_update_own_grade _____________________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>

    def test_student_cannot_update_own_grade(client):
        """R3/R4: being logged in and owning the record does not grant write access."""
        login(client, "alice", "alicepw")
        before = snapshot()
        response = client.post(
            "/grades/update",
            json={"student_id": 1001, "course_id": "SRS", "grade": 20},
        )
>       assert response.status_code == 403
E       assert 200 == 403
E        +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code

tests_security/test_grade_authorization.py:59: AssertionError
__________ test_professor_cannot_update_grade_outside_assigned_course __________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>

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
>       assert response.status_code == 403
E       assert 200 == 403
E        +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code

tests_security/test_grade_authorization.py:75: AssertionError
___________ test_professor_cannot_create_grade_in_unassigned_course ____________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>

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
>       assert response.status_code == 403
E       assert 200 == 403
E        +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code

tests_security/test_grade_authorization.py:91: AssertionError
=========================== short test summary info ============================
FAILED tests_security/test_file_access.py::test_relative_traversal_is_rejected - assert 400 <= 200
 +  where 200 = <WrapperTestResponse 19 bytes [200 OK]>.status_code
FAILED tests_security/test_file_access.py::test_absolute_path_is_rejected - assert 400 <= 200
 +  where 200 = <WrapperTestResponse 19 bytes [200 OK]>.status_code
FAILED tests_security/test_file_access.py::test_traversal_hidden_after_valid_subfolder_is_rejected - assert 400 <= 200
 +  where 200 = <WrapperTestResponse 19 bytes [200 OK]>.status_code
FAILED tests_security/test_file_access.py::test_sibling_directory_with_same_prefix_is_rejected - assert 400 <= 200
 +  where 200 = <WrapperTestResponse 19 bytes [200 OK]>.status_code
FAILED tests_security/test_file_access.py::test_unauthenticated_download_is_rejected - assert 200 == 401
 +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code
FAILED tests_security/test_grade_authorization.py::test_unauthenticated_update_is_rejected_and_data_unchanged - assert 200 == 401
 +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code
FAILED tests_security/test_grade_authorization.py::test_student_cannot_update_own_grade - assert 200 == 403
 +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code
FAILED tests_security/test_grade_authorization.py::test_professor_cannot_update_grade_outside_assigned_course - assert 200 == 403
 +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code
FAILED tests_security/test_grade_authorization.py::test_professor_cannot_create_grade_in_unassigned_course - assert 200 == 403
 +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code
========================= 9 failed, 4 passed in 0.12s ==========================
Error: Process completed with exit code 1.