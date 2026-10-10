import os
import fnmatch

def is_manifest_filename(filename: str) -> bool:
    """
    Identifies dependency manifests for SCA analysis:
    requirements.txt, requirements-*.txt, package.json, package-lock.json, pom.xml.
    """
    base = os.path.basename(filename).lower()
    if base == "requirements.txt" or fnmatch.fnmatch(base, "requirements-*.txt"):
        return True
    if base in ("package.json", "package-lock.json", "pom.xml"):
        return True
    return False

def detect_language(filename: str) -> str:
    if is_manifest_filename(filename):
        return "manifest"
    _, ext = os.path.splitext(filename.lower())
    if ext == ".py":
        return "python"
    elif ext in [".js", ".jsx"]:
        return "javascript"
    elif ext in [".ts", ".tsx"]:
        return "typescript"
    elif ext == ".java":
        return "java"
    elif ext in [".c", ".cpp", ".h", ".hpp"]:
        return "c"
    elif ext == ".php":
        return "php"
    return "unknown"
