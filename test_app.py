import pytest
import sqlite3
import os
from app import app, initialize_database
from unittest import mock
import jwt
import time

@pytest.fixture
def client():
    """Pytest fixture to create a test client for the Flask app."""
    initialize_database()  # Ensure the database is set up before tests
    with app.test_client() as client:
        yield client


def test_register(client):
    """Test the /register endpoint for successful user registration."""
    response = client.post('/register', json={"username": "testuser", "email": "testuser@example.com"})
    assert response.status_code == 201
    data = response.get_json()
    assert "password" in data

    # Validate that the user was added to the database
    with sqlite3.connect("totally_not_my_privateKeys.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username = ?", ("testuser",))
        user = cursor.fetchone()
        assert user is not None
        assert user[0] == "testuser"


def test_auth_success(client):
    """Test the /auth endpoint for successful authentication."""
    # First, register a user to authenticate
    register_response = client.post('/register', json={"username": "authuser", "email": "authuser@example.com"})
    assert register_response.status_code == 201
    password = register_response.get_json()["password"]

    # Authenticate the user
    auth_response = client.post('/auth', json={"username": "authuser", "password": password})
    assert auth_response.status_code == 200
    data = auth_response.get_json()
    assert data["message"] == "Request allowed"



