import urllib.request
import urllib.error
import json

BASE = "http://localhost:8000"

def post_json(path, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(f"{BASE}{path}", data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        res = urllib.request.urlopen(req)
        return res.getcode(), json.loads(res.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

USERNAME = "sentineladmin"
EMAIL = "sentineladmin@gmail.com"
PASSWORD = "Admin1234!"

# 1. Register user
print("1. Registering user...")
code, body = post_json("/auth/signup", {"username": USERNAME, "email": EMAIL, "password": PASSWORD})
print(f"   Status: {code}")
if code == 201:
    print("   REGISTERED OK:", body.get("username"))
elif code == 400 and "already exists" in str(body):
    print("   Already registered (OK)")
else:
    print("   Response:", body)

# 2. Login
print("\n2. Logging in...")
code, body = post_json("/auth/login", {"username": USERNAME, "password": PASSWORD})
print(f"   Status: {code}")
if code == 200 and "access_token" in body:
    print("   LOGIN SUCCESS!")
    print(f"   Token: {body['access_token'][:40]}...")
else:
    print("   FAILED:", body)
    
print("\nDone.")
