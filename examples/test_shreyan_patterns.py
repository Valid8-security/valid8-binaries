"""
Test file for new security patterns from Shreyan's branch.
These demonstrate vulnerabilities that should now be detected.
"""

# JWT Security Issues
import jwt

JWT_SECRET = "hardcoded-secret-key"  # CWE-798: Hardcoded JWT Secret
payload = {"sub": "1234567890"}

# Weak algorithm
token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')  # CWE-327: Weak JWT Algorithm

# Missing signature verification  
decoded = jwt.decode(token, options={"verify_signature": False})  # CWE-295: Missing Signature Verification


# SSTI (Server-Side Template Injection)
from flask import render_template_string
from jinja2 import Template

def unsafe_template(user_input):
    # CWE-94: SSTI via render_template_string
    template = f"Hello {user_input}"
    render_template_string(template)

def unsafe_jinja2(user_input):
    # CWE-94: SSTI via jinja2
    template = Template(user_input)
    return template.render()


# NoSQL Injection
from pymongo import MongoClient

db = MongoClient().database

def unsafe_query(username, password):
    # CWE-943: NoSQL Injection
    return db.collection.find({"username": username, "password": password})


# ReDoS (Regular Expression Denial of Service)
import re

# Vulnerable regex patterns
pattern1 = r"(a+)+b"  # CWE-1333: ReDoS - nested quantifiers
result = re.match(pattern1, input_string)

pattern2 = r"(.*a)+b"  # CWE-1333: ReDoS - expensive alternation
result2 = re.search(pattern2, input_string)

