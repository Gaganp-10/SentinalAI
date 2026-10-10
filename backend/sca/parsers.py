import os
import re
import json
import logging
import fnmatch
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional, Any
import defusedxml.ElementTree as ET
from defusedxml.common import DefusedXmlException

logger = logging.getLogger(__name__)

PACKAGE_CAP = 5000


@dataclass
class ParsedDependency:
    ecosystem: str          # "PyPI" | "npm" | "Maven"
    name: str
    version: str
    manifest_file: str
    line: int = 1
    direct: Any = "unknown" # True | False | "unknown"
    dev: bool = False


@dataclass
class UnresolvedDependency:
    ecosystem: str
    name: str
    manifest_file: str
    line: int = 1
    reason: str = "version not pinned"


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of -_. replaced by single '-'."""
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def parse_requirements_txt(content: str, rel_path: str) -> Tuple[List[ParsedDependency], List[UnresolvedDependency], List[str]]:
    """
    Parses requirements.txt defensively.
    Supports comments, extras, environment markers, --hash continuations.
    Ignores URLs, VCS, options (-r, -e, etc.).
    Exact pins (==) only.
    """
    deps: List[ParsedDependency] = []
    unresolved: List[UnresolvedDependency] = []
    warnings: List[str] = []

    lines = content.splitlines()
    i = 0
    while i < len(lines):
        line_num = i + 1
        raw_line = lines[i].strip()
        i += 1

        if not raw_line or raw_line.startswith("#"):
            continue

        # Handle line continuation with backslash or --hash continuation lines
        combined = raw_line
        while combined.endswith("\\") and i < len(lines):
            combined = combined[:-1].strip() + " " + lines[i].strip()
            i += 1

        # Strip inline comments (if not part of quotes or markers)
        comment_split = re.split(r"\s+#", combined, maxsplit=1)
        line_text = comment_split[0].strip()
        if not line_text:
            continue

        # Ignore options
        if line_text.startswith(("-r", "-e", "-i", "-f", "--index-url", "--extra-index-url", "--find-links", "--trusted-host")):
            unresolved.append(UnresolvedDependency(
                ecosystem="PyPI",
                name=line_text.split()[0],
                manifest_file=rel_path,
                line=line_num,
                reason="option line"
            ))
            continue

        # Ignore URL / VCS lines
        if re.match(r"^(https?://|git\+|hg\+|svn\+|bzr\+)", line_text, re.IGNORECASE):
            unresolved.append(UnresolvedDependency(
                ecosystem="PyPI",
                name=line_text[:40],
                manifest_file=rel_path,
                line=line_num,
                reason="URL or VCS dependency"
            ))
            continue

        # Strip environment marker (; python_version < "3.9", etc.)
        if ";" in line_text:
            line_text = line_text.split(";", 1)[0].strip()

        # Strip hash options (--hash=...)
        line_text = re.sub(r"--hash=\S+", "", line_text).strip()

        # Check for exact pin (==)
        if "==" in line_text:
            parts = line_text.split("==", 1)
            raw_name = parts[0].strip()
            version = parts[1].strip()

            # Strip extras: pkg[extra] -> pkg
            name = re.sub(r"\[.*?\]", "", raw_name).strip()
            # Clean version: take first token before any comma/whitespace
            clean_ver = version.split()[0].rstrip(",").strip() if version else ""

            if name and clean_ver:
                deps.append(ParsedDependency(
                    ecosystem="PyPI",
                    name=normalize_pypi_name(name),
                    version=clean_ver,
                    manifest_file=rel_path,
                    line=line_num,
                    direct=True,
                    dev=False
                ))
            else:
                unresolved.append(UnresolvedDependency(
                    ecosystem="PyPI",
                    name=name or line_text,
                    manifest_file=rel_path,
                    line=line_num,
                    reason="version not pinned"
                ))
        else:
            # Unpinned or range (>=, <=, ~=, >, <, !=)
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)", line_text)
            pkg_name = match.group(1) if match else line_text
            pkg_name = re.sub(r"\[.*?\]", "", pkg_name).strip()
            unresolved.append(UnresolvedDependency(
                ecosystem="PyPI",
                name=normalize_pypi_name(pkg_name) if pkg_name else line_text,
                manifest_file=rel_path,
                line=line_num,
                reason="version not pinned"
            ))

    return deps, unresolved, warnings


def parse_package_lock_json(content: str, rel_path: str) -> Tuple[List[ParsedDependency], List[UnresolvedDependency], List[str]]:
    """
    Parses package-lock.json defensively.
    Supports lockfileVersion 1 (nested dependencies) and 2/3 (packages dictionary).
    """
    deps: List[ParsedDependency] = []
    unresolved: List[UnresolvedDependency] = []
    warnings: List[str] = []

    try:
        data = json.loads(content)
    except Exception as e:
        warnings.append(f"Malformed JSON in {rel_path}: {e}")
        return deps, unresolved, warnings

    if not isinstance(data, dict):
        warnings.append(f"Invalid package-lock.json root structure in {rel_path}")
        return deps, unresolved, warnings

    lock_version = data.get("lockfileVersion", 1)

    # Detect direct dependencies from root
    root_direct_deps: Dict[str, bool] = {} # pkg_name -> is_dev
    if "packages" in data and isinstance(data["packages"], dict) and "" in data["packages"]:
        root_pkg = data["packages"][""]
        for dep in root_pkg.get("dependencies", {}):
            root_direct_deps[dep] = False
        for dep in root_pkg.get("devDependencies", {}):
            root_direct_deps[dep] = True
    elif "dependencies" in data and isinstance(data["dependencies"], dict):
        for dep, dep_data in data["dependencies"].items():
            if isinstance(dep_data, dict):
                root_direct_deps[dep] = bool(dep_data.get("dev", False))

    if lock_version in (2, 3) and "packages" in data and isinstance(data["packages"], dict):
        # lockfileVersion 2/3: packages keyed by node_modules/...
        for key, entry in data["packages"].items():
            if not key or key == "":
                continue  # skip root
            if not isinstance(entry, dict):
                continue
            if entry.get("link") is True:
                continue

            version = entry.get("version")
            # Extract package name after last "node_modules/"
            if "node_modules/" in key:
                name = key.split("node_modules/")[-1]
            else:
                name = entry.get("name", key)

            if not version:
                unresolved.append(UnresolvedDependency(
                    ecosystem="npm",
                    name=name,
                    manifest_file=rel_path,
                    line=1,
                    reason="version missing"
                ))
                continue

            is_dev = bool(entry.get("dev", False))
            if name in root_direct_deps:
                direct = True
                is_dev = root_direct_deps[name]
            else:
                direct = False

            deps.append(ParsedDependency(
                ecosystem="npm",
                name=name,
                version=str(version).strip(),
                manifest_file=rel_path,
                line=1,
                direct=direct,
                dev=is_dev
            ))

    elif "dependencies" in data and isinstance(data["dependencies"], dict):
        # lockfileVersion 1 (or fallback): recursive dependencies tree
        def recurse_deps(dep_dict: dict, depth: int = 0):
            for name, entry in dep_dict.items():
                if not isinstance(entry, dict):
                    continue
                version = entry.get("version")
                is_dev = bool(entry.get("dev", False))
                direct = (depth == 0)

                if not version or entry.get("bundled", False):
                    continue

                deps.append(ParsedDependency(
                    ecosystem="npm",
                    name=name,
                    version=str(version).strip(),
                    manifest_file=rel_path,
                    line=1,
                    direct=direct,
                    dev=is_dev
                ))

                if "dependencies" in entry and isinstance(entry["dependencies"], dict):
                    recurse_deps(entry["dependencies"], depth + 1)

        recurse_deps(data["dependencies"])

    return deps, unresolved, warnings


def parse_package_json(content: str, rel_path: str) -> Tuple[List[ParsedDependency], List[UnresolvedDependency], List[str]]:
    """
    Parses package.json (used ONLY when no package-lock.json covers the same folder).
    Accepts exact versions only (no ^, ~, ranges, tags, URLs).
    """
    deps: List[ParsedDependency] = []
    unresolved: List[UnresolvedDependency] = []
    warnings: List[str] = []

    try:
        data = json.loads(content)
    except Exception as e:
        warnings.append(f"Malformed JSON in {rel_path}: {e}")
        return deps, unresolved, warnings

    if not isinstance(data, dict):
        warnings.append(f"Invalid package.json root structure in {rel_path}")
        return deps, unresolved, warnings

    sections = [
        ("dependencies", False),
        ("devDependencies", True)
    ]

    exact_ver_regex = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")

    for sec_name, is_dev in sections:
        sec = data.get(sec_name)
        if isinstance(sec, dict):
            for name, raw_ver in sec.items():
                if not isinstance(raw_ver, str):
                    continue
                ver_str = raw_ver.strip()
                if exact_ver_regex.match(ver_str):
                    deps.append(ParsedDependency(
                        ecosystem="npm",
                        name=name,
                        version=ver_str,
                        manifest_file=rel_path,
                        line=1,
                        direct=True,
                        dev=is_dev
                    ))
                else:
                    unresolved.append(UnresolvedDependency(
                        ecosystem="npm",
                        name=name,
                        manifest_file=rel_path,
                        line=1,
                        reason="version range"
                    ))

    return deps, unresolved, warnings


def _strip_ns(tag: str) -> str:
    """Helper to remove XML namespace prefix from tag name."""
    return tag.split("}")[-1] if "}" in tag else tag


def parse_pom_xml(content: str, rel_path: str) -> Tuple[List[ParsedDependency], List[UnresolvedDependency], List[str]]:
    """
    Parses pom.xml defensively using defusedxml.
    Resolves versions defined as literals or local properties (${prop}).
    Rejects entity expansion / external entity attacks safely.
    """
    deps: List[ParsedDependency] = []
    unresolved: List[UnresolvedDependency] = []
    warnings: List[str] = []

    try:
        root = ET.fromstring(content)
    except DefusedXmlException as dxe:
        warn_msg = f"Security check rejected hostile XML in {rel_path}: {dxe}"
        logger.warning(warn_msg)
        warnings.append(warn_msg)
        return deps, unresolved, warnings
    except Exception as e:
        warn_msg = f"Malformed XML in {rel_path}: {e}"
        logger.warning(warn_msg)
        warnings.append(warn_msg)
        return deps, unresolved, warnings

    if root is None or _strip_ns(root.tag).lower() != "project":
        warnings.append(f"pom.xml root tag is not <project> in {rel_path}")
        return deps, unresolved, warnings

    # 1. Collect properties
    properties: Dict[str, str] = {}
    # Check for root project.version
    for child in root:
        ctag = _strip_ns(child.tag)
        if ctag == "version" and child.text:
            properties["project.version"] = child.text.strip()
            properties["pom.version"] = child.text.strip()
        elif ctag == "properties":
            for prop in child:
                ptag = _strip_ns(prop.tag)
                if prop.text:
                    properties[ptag] = prop.text.strip()

    # 2. Find dependencies
    # Look for both root <dependencies> and <dependencyManagement><dependencies>
    for elem in root.iter():
        if _strip_ns(elem.tag) == "dependency":
            group_id = ""
            artifact_id = ""
            version_raw = ""
            scope = ""

            for child in elem:
                ctag = _strip_ns(child.tag)
                text = (child.text or "").strip()
                if ctag == "groupId":
                    group_id = text
                elif ctag == "artifactId":
                    artifact_id = text
                elif ctag == "version":
                    version_raw = text
                elif ctag == "scope":
                    scope = text.lower()

            if not group_id or not artifact_id:
                continue

            pkg_name = f"{group_id}:{artifact_id}"
            is_dev = (scope == "test")

            if not version_raw:
                unresolved.append(UnresolvedDependency(
                    ecosystem="Maven",
                    name=pkg_name,
                    manifest_file=rel_path,
                    line=1,
                    reason="version not resolvable"
                ))
                continue

            # Resolve property reference ${foo}
            resolved_version = version_raw
            prop_match = re.match(r"^\$\{([^}]+)\}$", version_raw)
            if prop_match:
                prop_key = prop_match.group(1).strip()
                if prop_key in properties:
                    resolved_version = properties[prop_key]
                else:
                    unresolved.append(UnresolvedDependency(
                        ecosystem="Maven",
                        name=pkg_name,
                        manifest_file=rel_path,
                        line=1,
                        reason="version not resolvable"
                    ))
                    continue

            # Check for unresolved nested or remaining ${...}
            if "${" in resolved_version or "}" in resolved_version:
                unresolved.append(UnresolvedDependency(
                    ecosystem="Maven",
                    name=pkg_name,
                    manifest_file=rel_path,
                    line=1,
                    reason="version not resolvable"
                ))
                continue

            deps.append(ParsedDependency(
                ecosystem="Maven",
                name=pkg_name,
                version=resolved_version,
                manifest_file=rel_path,
                line=1,
                direct=True,
                dev=is_dev
            ))

    return deps, unresolved, warnings


def parse_manifests_in_directory(project_dir: str) -> Tuple[List[ParsedDependency], List[UnresolvedDependency], List[str]]:
    """
    Discovers and parses all supported manifest files in project_dir.
    Rules:
    - Lockfile precedence: if package-lock.json exists in a folder, package.json in that folder is skipped.
    - Capped at 5,000 unique dependencies per scan.
    """
    all_deps: List[ParsedDependency] = []
    all_unresolved: List[UnresolvedDependency] = []
    all_warnings: List[str] = []

    # Map folders to check package-lock precedence
    folders_with_lockfile = set()
    manifest_files_by_folder = {}

    for root, _, files in os.walk(project_dir):
        rel_root = os.path.relpath(root, project_dir).replace("\\", "/")
        # Skip node_modules and other ignored dirs
        parts = rel_root.strip("/").split("/")
        if any(p in {"node_modules", ".git", "__pycache__", ".venv", "venv", "build", "dist", "target", ".idea", ".vscode"} for p in parts):
            continue

        for f in files:
            fl = f.lower()
            if fl == "package-lock.json":
                folders_with_lockfile.add(root)
            if fl in ("package.json", "package-lock.json", "pom.xml", "requirements.txt") or fnmatch.fnmatch(fl, "requirements-*.txt"):
                manifest_files_by_folder.setdefault(root, []).append(f)

    for folder, files in manifest_files_by_folder.items():
        has_lock = folder in folders_with_lockfile

        for f in sorted(files):
            fl = f.lower()
            # If package.json and lockfile is present in same folder, skip package.json
            if fl == "package.json" and has_lock:
                continue

            full_path = os.path.join(folder, f)
            rel_path = os.path.relpath(full_path, project_dir).replace("\\", "/")

            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception as e:
                all_warnings.append(f"Failed to read manifest {rel_path}: {e}")
                continue

            if fl == "requirements.txt" or fnmatch.fnmatch(fl, "requirements-*.txt"):
                deps, unres, warns = parse_requirements_txt(content, rel_path)
            elif fl == "package-lock.json":
                deps, unres, warns = parse_package_lock_json(content, rel_path)
            elif fl == "package.json":
                deps, unres, warns = parse_package_json(content, rel_path)
            elif fl == "pom.xml":
                deps, unres, warns = parse_pom_xml(content, rel_path)
            else:
                continue

            all_deps.extend(deps)
            all_unresolved.extend(unres)
            all_warnings.extend(warns)

    # Cap unique package dependencies per scan
    unique_keys = set()
    capped_deps: List[ParsedDependency] = []
    cap_hit = False

    for d in all_deps:
        key = (d.ecosystem, d.name, d.version)
        if key not in unique_keys:
            if len(unique_keys) >= PACKAGE_CAP:
                cap_hit = True
                break
            unique_keys.add(key)
        capped_deps.append(d)

    if cap_hit:
        all_warnings.append(f"Dependency package cap reached ({PACKAGE_CAP} packages). Remaining dependencies skipped.")

    return capped_deps, all_unresolved, all_warnings
