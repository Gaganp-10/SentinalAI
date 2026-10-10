import subprocess
import pickle
import hashlib

def test_sqli(cursor, val):
    # ruleid: python-sqli
    cursor.execute("SELECT * FROM users WHERE id = " + val)
    # ok: python-sqli
    cursor.execute("SELECT * FROM users WHERE id = %s", (val,))

def test_subprocess(cmd):
    # ruleid: python-subprocess-shell
    subprocess.run(cmd, shell=True)
    # ok: python-subprocess-shell
    subprocess.run(["tar", "-xvf", "file.tar"])

def test_pickle(data):
    # ruleid: python-pickle-loads
    pickle.loads(data)

def test_hashlib(data):
    # ruleid: python-hashlib-md5
    hashlib.md5(data)
    # ok: python-hashlib-md5
    hashlib.sha256(data)

def test_eval(code):
    # ruleid: python-eval
    eval(code)
    # ok: python-eval
    int(code)
