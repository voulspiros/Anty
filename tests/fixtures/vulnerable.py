# Deliberately vulnerable Python file for testing Anty
# DO NOT use any of this code in production!

import pickle
import yaml
import subprocess
import hashlib
import os

# Bad: hardcoded AWS key
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# Bad: hardcoded password
db_password = "admin123!"

# Bad: database URL with credentials
DATABASE_URL = "postgres://dbuser:s3cur3p4ss@db.prod.example.com:5432/production"

# Bad: private key in source
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGcY5unA67hbYMC+...
-----END RSA PRIVATE KEY-----"""

# Bad: pickle deserialization
def load_data(data):
    return pickle.loads(data)

# Bad: unsafe yaml
def load_config(path):
    with open(path) as f:
        return yaml.load(f.read())

# Bad: shell=True
def run_command(user_input):
    subprocess.call(f"echo {user_input}", shell=True)

# Bad: SQL injection via f-string
def get_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# Bad: MD5 hashing
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Bad: eval
def calculate(expression):
    return eval(expression)

# Good: proper environment variable usage (should NOT trigger)
API_KEY = os.environ.get("API_KEY")
DB_HOST = os.getenv("DB_HOST", "localhost")
