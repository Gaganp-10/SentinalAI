import ast
from backend.detectors.ast_detector import ASTVisitor

def test_ast_hardcoded_secrets():
    code = """
db_password = "supersecretpassword123"
api_key = "AIzaSyD-mock-key"
normal_var = "hello world"
empty_pass = ""
"""
    visitor = ASTVisitor("test.py", code)
    tree = ast.parse(code)
    visitor.visit(tree)
    
    findings = visitor.findings
    assert len(findings) == 2
    types = [f.type for f in findings]
    assert "Hardcoded Secret" in types
    
    # Verify we did not flag normal_var or empty_pass
    descriptions = [f.description for f in findings]
    assert any("db_password" in d for d in descriptions)
    assert any("api_key" in d for d in descriptions)

def test_ast_weak_hashing():
    code = """
import hashlib
h1 = hashlib.md5(b"test")
h2 = hashlib.sha1(b"test")
h3 = hashlib.sha256(b"test")
"""
    visitor = ASTVisitor("test.py", code)
    tree = ast.parse(code)
    visitor.visit(tree)
    
    findings = visitor.findings
    assert len(findings) == 2
    types = [f.type for f in findings]
    assert all(t == "Weak Hashing Algorithm" for t in types)

def test_ast_dangerous_eval():
    code = """
eval("print('hello')")
exec("x = 1")
"""
    visitor = ASTVisitor("test.py", code)
    tree = ast.parse(code)
    visitor.visit(tree)
    
    findings = visitor.findings
    assert len(findings) == 2
    types = [f.type for f in findings]
    assert all(t == "Dangerous Function Execution" for t in types)

def test_ast_sql_injection():
    code = """
cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
cursor.execute(f"SELECT * FROM products WHERE id = {prod_id}")
cursor.execute("INSERT INTO logs (msg) VALUES (%s)", (msg,)) # safe
cursor.execute("UPDATE users SET email = '{}'".format(email))
"""
    visitor = ASTVisitor("test.py", code)
    tree = ast.parse(code)
    visitor.visit(tree)
    
    findings = visitor.findings
    # Should find 3 SQL injections (first, second, fourth) and ignore the third (safe)
    assert len(findings) == 3
    types = [f.type for f in findings]
    assert all(t == "SQL Injection" for t in types)
