import pickle
import requests
import xml.etree.ElementTree as ET
import tempfile
import os

# HIGH: Insecure deserialization
def load_session(data):
    return pickle.loads(data)

# HIGH: SSRF vulnerability
def fetch_url(url):
    return requests.get(url, verify=False)

# MEDIUM: XXE vulnerability
def parse_xml(xml_string):
    return ET.fromstring(xml_string)

# MEDIUM: Predictable temp file
def write_temp(data):
    path = "/tmp/output.txt"
    with open(path, "w") as f:
        f.write(data)
    return path

# LOW: Use of assert for security
def check_admin(user):
    assert user.role == "admin", "Not admin"
    return True

# MEDIUM: Weak random for token
import random
def generate_token():
    return str(random.randint(10000, 99999))
