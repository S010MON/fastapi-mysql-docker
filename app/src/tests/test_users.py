import json


def test_root(test_app):
    response = test_app.get("/")
    assert response.status_code == 200
    assert response.json()["msg"] == "coded law"


def test_create_user(test_app, user_authentication_headers):
    username = "testUser"
    # Ensure no user exists in system
    test_app.delete(f"/api/user/{username}",
                    headers=user_authentication_headers)

    data = {"username": username,
            "password": "testing"}
    response = test_app.post("/api/user/",
                             json.dumps(data),
                             headers=user_authentication_headers)
    assert response.status_code == 200
    assert response.json()["username"] == username
    assert response.json()["disabled"] == False


def test_delete_user(test_app, user_authentication_headers):
    username = "testUser"
    # Ensure user exists in system
    data = {"username": username,
            "password": "testing"}
    test_app.post("/api/user/",
                  json.dumps(data),
                  headers=user_authentication_headers)

    response = test_app.delete(f"/api/user/{username}",
                               headers=user_authentication_headers)
    assert response.status_code == 200


def test_get_user(test_app, user_authentication_headers):
    response = test_app.get("/api/user/root",
                            headers=user_authentication_headers)
    assert response.status_code == 200
    assert response.json()["username"] == "root"
