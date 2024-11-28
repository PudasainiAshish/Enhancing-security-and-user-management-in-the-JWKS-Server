import sqlite3
import uuid
from flask import Flask, request ,jsonify, make_response
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.backends import default_backend
from argon2.exceptions import VerifyMismatchError
import time
import threading
from collections import deque
from threading import Lock

import sqlite3
import uuid
from flask import Flask, request, jsonify, make_response
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.backends import default_backend
from argon2.exceptions import VerifyMismatchError
from time import time
from collections import deque
from threading import Lock

# Rate Limiting Implementation Class
class TimeWindowRateLimiter:
    """
    Implements a time-window-based rate limiter.

    Attributes:
        max_requests (int): Maximum number of requests allowed within the time window.
        time_window (float): Time window duration in seconds.
        requests (deque): Queue to track timestamps of incoming requests.
        lock (Lock): Thread-safe lock for handling concurrent requests.
    """
    def __init__(self, max_requests, time_window):
        self.max_requests = max_requests
        self.time_window = time_window  # Time window in seconds
        self.requests = deque()
        self.lock = Lock()

    def allow_request(self):
        """
        Check if a request is allowed based on the rate limit.

        Returns:
            bool: True if the request is allowed, False otherwise.
        """
        current_time = time()
        with self.lock:
            while self.requests and self.requests[0] < current_time - self.time_window:
                self.requests.popleft()

            # Check if within request limit
            if len(self.requests) < self.max_requests:
                self.requests.append(current_time)
                return True
            return False


rate_limiter = TimeWindowRateLimiter(max_requests=10, time_window=1)  # 10 requests per second

app = Flask(__name__)

AES_KEY = os.getenv("NOT_MY_KEY", "default_key_32_bytes_long______")
if len(AES_KEY) < 32:
    AES_KEY = AES_KEY.ljust(32, '_')  # Padding with underscores to make it 32 bytes
elif len(AES_KEY) > 32:
    AES_KEY = AES_KEY[:32]  # Truncating to 32 bytes

DB_PATH = "totally_not_my_privateKeys.db"

# Password Hasher (using Argon2)
ph = PasswordHasher()

# Database Initialization Functions
def create_users_table():
    """
    Creates the 'users' table if it doesn't exist in the database.

    The 'users' table stores user information, including username, hashed password,
    email, registration date, and the last login timestamp.
    """
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            FOREIGN KEY (id) REFERENCES auth_logs (user_id)
        );
        """)
        conn.commit()

def create_auth_logs_table():
    """
    Creates the 'auth_logs' table if it doesn't exist in the database.

    The 'auth_logs' table logs authentication attempts with request IP,
    timestamp, and the corresponding user ID.
    """
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,  
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
        conn.commit()

def create_keys_table():
    """
    Creates the 'keys' table if it doesn't exist in the database.

    The 'keys' table stores RSA private keys along with their expiration timestamps.
    """
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        );
        """)
        conn.commit()

# RSA Key Management
def rsa_generate_private_key():
    """
    Generate a new RSA private key.

    Returns:
        rsa.RSAPrivateKey: A newly generated RSA private key object.
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return key

def generate_and_store_keys():
    """
    Generate an RSA private key, encrypt it using AES, and store it in the database.

    The key is encrypted to ensure secure storage, and its expiration is set
    to 24 hours from the time of creation.
    """
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM keys")  # Clear existing keys
        conn.commit()

    valid_key = rsa_generate_private_key()
    valid_key_pem = valid_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_key = aes_encrypt(valid_key_pem, AES_KEY)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO keys (key, exp)
        VALUES (?, ?);
        """, (encrypted_key, int(datetime.now().timestamp()) + 86400))  # Expiration 24 hours later
        conn.commit()

def initialize_database():
    """
    Initialize the database by creating necessary tables and generating initial keys.
    """
    create_users_table()
    create_auth_logs_table()
    create_keys_table()
    generate_and_store_keys()

# AES Encryption
def aes_encrypt(data: bytes, key: str) -> bytes:
    """
    Encrypt data using AES encryption in ECB mode.

    Args:
        data (bytes): The plaintext data to encrypt.
        key (str): The AES encryption key (must be 32 bytes).

    Returns:
        bytes: The encrypted data.
    """
    if len(key) != 32:
        raise ValueError("AES_KEY must be exactly 32 bytes.")
    cipher = Cipher(algorithms.AES(key.encode("utf-8")), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()  # 128-bit block size for AES
    padded_data = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted

# Flask Routes
@app.route("/register", methods=["POST"])
def register():
    """
    Handle user registration by creating a new user record in the database.

    Generates a random UUID password for the user, hashes it, and stores
    the user's details in the 'users' table.

    Request Body:
        - username (str): The username of the new user.
        - email (str, optional): The email address of the user.

    Returns:
        JSON Response: Success message with generated password or an error.
    """
    data = request.json
    username = data.get("username")
    email = data.get("email", None)

    if not username:
        return jsonify({"error": "Username is required"}), 400

    password = str(uuid.uuid4())  # Generating UUID password
    hashed_password = ph.hash(password)  # Hash password using Argon2

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO users (username, password_hash, email, date_registered)
            VALUES (?, ?, ?, ?);
            """, (username, hashed_password, email, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

    return jsonify({"password": password}), 201

@app.route("/auth", methods=["POST"])
def auth():
    """
    Authenticate a user based on their username and password.

    Performs rate-limiting checks, verifies the provided credentials,
    updates the last login time, and logs the authentication attempt.

    Request Body:
        - username (str): The user's username.
        - password (str): The user's password.

    Returns:
        JSON Response: Authentication success or failure message.
    """
    # Rate limit check
    if not rate_limiter.allow_request():
        return jsonify({"message": "Too Many Requests"}), 429

    try:
        data = request.get_json()
        if not data:
            raise ValueError("Invalid JSON payload")

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    # Database interaction
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user is None or not ph.verify(user[1], password):
                return jsonify({"error": "Invalid credentials"}), 401

        # Update last login time
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE users
            SET last_login = ?
            WHERE id = ?
            """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user[0]))
            conn.commit()

        # Log successful authentication
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO auth_logs (user_id, request_ip, request_timestamp)
            VALUES (?, ?, ?)
            """, (user[0], request.remote_addr, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()

    except sqlite3.Error as db_error:
        return jsonify({"error": f"Database error: {db_error}"}), 500

    except VerifyMismatchError:
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({"message": "Request allowed"}), 200


if __name__ == "__main__":
    initialize_database()
    app.run(port=8080, debug=True, threaded=True)
