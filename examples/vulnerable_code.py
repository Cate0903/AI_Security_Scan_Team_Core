"""
Example vulnerable code for testing the AI Security Scanner
This file contains intentional security vulnerabilities for demonstration purposes.
DO NOT use this code in production!
"""
import os
import subprocess
import pickle
import hashlib

# SQL Injection vulnerability
def get_user_by_id(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)  # SQL001 - SQL Injection
    return cursor.fetchone()

# Hardcoded credentials
API_KEY = "sk-1234567890abcdef"  # CRED001 - Hardcoded Credentials
PASSWORD = "admin123"  # CRED001 - Hardcoded Credentials
database_password = "mySecretPass123"  # CRED001 - Hardcoded Credentials

# Command injection
def run_command(user_input):
    os.system("ls " + user_input)  # CMD001 - Command Injection
    subprocess.call("ping " + user_input, shell=True)  # CMD001 - Command Injection

# Path traversal
def read_user_file(filename):
    with open("/var/data/" + filename, 'r') as f:  # PATH001 - Path Traversal
        return f.read()

# Insecure deserialization
def load_user_data(data):
    user = pickle.loads(data)  # DESER001 - Insecure Deserialization
    return user

# Use of eval
def calculate(expression):
    result = eval(expression)  # EVAL001 - Dangerous Function
    return result

# Weak cryptography
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # CRYPTO001 - Weak Cryptographic Algorithm

# Debug mode enabled
DEBUG = True  # DEBUG001 - Debug Mode Enabled
debug = True  # DEBUG001 - Debug Mode Enabled

# SSL verification disabled
import requests
response = requests.get("https://example.com", verify=False)  # SSL001 - Insufficient SSL/TLS Verification

def main():
    print("This is an example of vulnerable code")
    print("Do not use in production!")

if __name__ == "__main__":
    main()
