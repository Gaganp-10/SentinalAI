"""
demo_osv.py - Demonstrates raw OSV API requests and unreachable OSV behavior.
Run from: backend/ directory as: python scripts/demo_osv.py
"""
import sys
import os
import json

# Make 'backend' importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.sca.osv_client import OSVClient, _QUERY_CACHE
import httpx

_QUERY_CACHE.clear()

queries = [
    {"ecosystem": "PyPI",  "name": "requests", "version": "2.19.0"},
    {"ecosystem": "npm",   "name": "lodash",   "version": "4.17.20"},
    {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1"},
]

batch_payload = {
    "queries": [
        {"package": {"name": q["name"], "ecosystem": q["ecosystem"]}, "version": q["version"]}
        for q in queries
    ]
}

print("=== RAW OSV /v1/querybatch REQUEST BODY ===")
print(json.dumps(batch_payload, indent=2))
print()

print("=== MAKING LIVE REQUEST to https://api.osv.dev/v1/querybatch ===")
try:
    with httpx.Client(timeout=15.0) as client:
        resp = client.post("https://api.osv.dev/v1/querybatch", json=batch_payload)
        print(f"HTTP Status: {resp.status_code}")
        data = resp.json()
        for i, (q, res) in enumerate(zip(queries, data.get("results", []))):
            vuln_ids = [v["id"] for v in res.get("vulns", [])]
            eco = q["ecosystem"]
            name = q["name"]
            ver = q["version"]
            print(f"  [{i}] {eco}:{name}@{ver} => {vuln_ids[:5]}" + ("..." if len(vuln_ids) > 5 else ""))
except Exception as e:
    print(f"ERROR: {e}")
