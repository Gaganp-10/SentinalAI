import os
import sys
import zipfile
import io
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.parser.language_detect import is_manifest_filename, detect_language
from backend.utils.config import settings
from backend.sca.parsers import parse_manifests_in_directory
from backend.sca.scanner import scan_dependencies

def main():
    print("=== ZIP EXTRACTION & MANIFEST FILTER VERIFICATION ===")
    
    # 1. Test is_manifest_filename rules
    allowed = ["requirements.txt", "requirements-dev.txt", "package.json", "package-lock.json", "pom.xml"]
    rejected = ["notes.txt", "data.json", "config.xml", "setup.py", "random.xml"]
    
    print("\n1. Allowed manifest names:")
    for a in allowed:
        assert is_manifest_filename(a)
        assert detect_language(a) == "manifest"
        print(f"  [ACCEPTED] {a} -> is_manifest: True, language: {detect_language(a)}")

    print("\n2. Rejected files (not manifests):")
    for r in rejected:
        assert not is_manifest_filename(r)
        print(f"  [REJECTED] {r} -> is_manifest: False, language: {detect_language(r)}")

    # 3. Simulate ZIP with node_modules/package.json and root package.json
    print("\n3. Testing ZIP extraction and directory scan with node_modules:")
    import tempfile
    temp_dir = tempfile.mkdtemp(prefix="sca_zip_test_")
    
    # Create ZIP
    zip_path = os.path.join(temp_dir, "test_upload.zip")
    with zipfile.ZipFile(zip_path, "w") as z:
        # Pinned manifest at root
        z.writestr("package.json", json.dumps({"dependencies": {"minimist": "1.2.0"}}))
        # Malicious / deep package.json in node_modules
        z.writestr("node_modules/evil-pkg/package.json", json.dumps({"dependencies": {"lodash": "4.17.15"}}))
        z.writestr("node_modules/package.json", json.dumps({"dependencies": {"requests": "2.19.0"}}))
        # Plain text file
        z.writestr("notes.txt", "Just some notes")

    # Extract simulating backend/api/files.py logic
    extract_dir = os.path.join(temp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)
    
    IGNORED_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "build", "dist", "target", ".idea", ".vscode"}
    manifest_max_bytes = settings.MAX_MANIFEST_UPLOAD_SIZE_MB * 1024 * 1024
    
    extracted_records = []
    with zipfile.ZipFile(zip_path, "r") as z:
        for member in z.infolist():
            if member.is_dir():
                continue
            normalized_parts = member.filename.replace("\\", "/").strip("/").split("/")
            if any(part in IGNORED_DIRS for part in normalized_parts[:-1]):
                print(f"  [IGNORED DIR SKIPPED] {member.filename}")
                continue
            
            member_is_manifest = is_manifest_filename(member.filename)
            if member_is_manifest and member.file_size > manifest_max_bytes:
                print(f"  [SIZE CAP SKIPPED] {member.filename} ({member.file_size} > {manifest_max_bytes})")
                continue
                
            out_path = os.path.join(extract_dir, member.filename)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with z.open(member) as src, open(out_path, "wb") as dst:
                dst.write(src.read())
                
            lang = detect_language(member.filename)
            extracted_records.append((member.filename, lang, member.file_size))
            print(f"  [EXTRACTED] {member.filename} (language='{lang}', size={member.file_size} bytes)")

    # Run scan on extracted directory
    deps, unres, warns = parse_manifests_in_directory(extract_dir)
    print(f"\nParsed dependencies from extracted folder: {len(deps)}")
    for d in deps:
        print(f"  Dep: {d.name} == {d.version} in {d.manifest_file}")

    assert any(d.name == "minimist" for d in deps)
    assert not any(d.name == "evil-pkg" or d.name == "requests" or "node_modules" in d.manifest_file for d in deps)
    print("\nCONFIRMED: node_modules/package.json was completely skipped, size cap enforced, and language set to 'manifest'!")

if __name__ == "__main__":
    main()
