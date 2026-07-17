from backend.parser.language_detect import detect_language

def test_detect_python():
    assert detect_language("main.py") == "python"
    assert detect_language("src/utils/helper.py") == "python"

def test_detect_javascript_typescript():
    assert detect_language("app.js") == "javascript"
    assert detect_language("components/Button.jsx") == "javascript"
    assert detect_language("index.ts") == "typescript"
    assert detect_language("types.tsx") == "typescript"

def test_detect_java():
    assert detect_language("Application.java") == "java"

def test_detect_c_cpp():
    assert detect_language("main.c") == "c"
    assert detect_language("math.cpp") == "c"
    assert detect_language("header.h") == "c"

def test_detect_php():
    assert detect_language("index.php") == "php"

def test_detect_unknown():
    assert detect_language("README.md") == "unknown"
    assert detect_language("styles.css") == "unknown"
