#!/usr/bin/env python3

import subprocess
import os

# Sample Python code with potential security issues for testing
user_input = input("Enter command: ")
os.system(user_input)  # Command injection vulnerability

password = "hardcoded_password"  # Hardcoded secret

# SQL injection vulnerability
def unsafe_query(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

# Insecure deserialization
import pickle
data = pickle.loads(open("user_data.pkl", "rb").read())  # Unsafe deserialization

