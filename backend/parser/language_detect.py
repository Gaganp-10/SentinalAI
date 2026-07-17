import os

def detect_language(filename: str) -> str:
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
