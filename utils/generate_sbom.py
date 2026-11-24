"""Generate an SPDX 2.3 (JSON) Software Bill of Materials for ni-grpc-device.

Native dependencies of the server are vendored as git submodules, which package-manifest
based SBOM tools do not detect. This script records:

* the ni-grpc-device-server package (version from CMakeLists.txt),
* every git submodule pinned by the repository (URL + exact commit), and, when the submodules
  are initialized, their nested submodules (for example gRPC's abseil, protobuf, BoringSSL,
  zlib, c-ares and re2),
* Python build tooling from python_build_requirements.txt (as build tools).

Usage:
    python utils/generate_sbom.py -o ni-grpc-device.spdx.json
"""

import argparse
import configparser
import datetime
import json
import pathlib
import re
import subprocess
import sys
import uuid
from typing import Dict, List, Optional

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PROJECT_URL = "https://github.com/ni/grpc-device"
ROOT_ID = "SPDXRef-Package-ni-grpc-device-server"


def _git(args: List[str], cwd: pathlib.Path) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return result.stdout.strip()


def _spdx_id(name: str) -> str:
    return "SPDXRef-Package-" + re.sub(r"[^A-Za-z0-9.\-]", "-", name)


def _project_version() -> str:
    cmake = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    match = re.search(r"project\(ni_grpc_device_server[\s\S]*?VERSION\s+([0-9.]+)", cmake)
    return match.group(1) if match else "NOASSERTION"


def _normalize_url(url: str) -> str:
    url = url.strip()
    if url.startswith("git@github.com:"):
        url = "https://github.com/" + url[len("git@github.com:") :]
    return url[:-4] if url.endswith(".git") else url


def _purl(url: str, commit: str) -> Optional[str]:
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)$", url)
    if not match:
        return None
    return f"pkg:github/{match.group(1)}/{match.group(2)}@{commit}"


def _purl_ref(purl: str) -> dict:
    return {
        "referenceCategory": "PACKAGE-MANAGER",
        "referenceType": "purl",
        "referenceLocator": purl,
    }


def _relationship(element: str, relationship_type: str, related: str) -> dict:
    return {
        "spdxElementId": element,
        "relationshipType": relationship_type,
        "relatedSpdxElement": related,
    }


def _read_gitmodules(repo: pathlib.Path) -> Dict[str, str]:
    """Return {submodule path: url} declared in repo/.gitmodules."""
    gitmodules = repo / ".gitmodules"
    if not gitmodules.exists():
        return {}
    parser = configparser.ConfigParser()
    parser.read(gitmodules, encoding="utf-8")
    modules = {}
    for section in parser.sections():
        path = parser.get(section, "path", fallback=None)
        url = parser.get(section, "url", fallback=None)
        if path and url:
            modules[path] = url
    return modules


def _pinned_commit(repo: pathlib.Path, path: str) -> Optional[str]:
    """Return the commit the superproject pins for a submodule (works without init)."""
    output = _git(["ls-tree", "HEAD", path], repo)
    if not output:
        return None
    parts = output.split()
    return parts[2] if len(parts) >= 3 and parts[1] == "commit" else None


def _collect_submodules(
    repo: pathlib.Path, prefix: str, parent_id: str, packages: list, relationships: list
) -> None:
    for path, url in sorted(_read_gitmodules(repo).items()):
        commit = _pinned_commit(repo, path)
        if not commit:
            continue
        url = _normalize_url(url)
        full_path = f"{prefix}{path}"
        name = url.rsplit("/", 1)[-1]
        package_id = _spdx_id(full_path)
        package = {
            "SPDXID": package_id,
            "name": name,
            "versionInfo": commit,
            "downloadLocation": f"git+{url}.git@{commit}",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "comment": f"Git submodule at {full_path}",
        }
        purl = _purl(url, commit)
        if purl:
            package["externalRefs"] = [_purl_ref(purl)]
        packages.append(package)
        relationships.append(_relationship(parent_id, "DEPENDS_ON", package_id))
        submodule_dir = repo / path
        if (submodule_dir / ".git").exists():
            _collect_submodules(submodule_dir, f"{full_path}/", package_id, packages, relationships)


def _collect_python_build_tools(packages: list, relationships: list) -> None:
    requirements = REPO_ROOT / "python_build_requirements.txt"
    if not requirements.exists():
        return
    for line in requirements.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|~=|>=)?\s*([^\s;]+)?", line)
        if not match:
            continue
        name, operator, version = match.groups()
        pinned = operator == "==" and version
        package_id = _spdx_id(f"pypi-{name}")
        package = {
            "SPDXID": package_id,
            "name": name,
            "versionInfo": version if pinned else "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "comment": f"Python build tool; requirement: {line}",
            "externalRefs": [
                _purl_ref(f"pkg:pypi/{name.lower()}" + (f"@{version}" if pinned else ""))
            ],
        }
        packages.append(package)
        relationships.append(_relationship(package_id, "BUILD_TOOL_OF", ROOT_ID))


def generate() -> dict:
    """Build the SPDX document as a dictionary."""
    version = _project_version()
    commit = _git(["rev-parse", "HEAD"], REPO_ROOT) or "NOASSERTION"
    root = {
        "SPDXID": ROOT_ID,
        "name": "ni-grpc-device-server",
        "versionInfo": version,
        "supplier": "Organization: NI",
        "downloadLocation": f"git+{PROJECT_URL}.git@{commit}",
        "homepage": PROJECT_URL,
        "filesAnalyzed": False,
        "licenseConcluded": "MIT",
        "licenseDeclared": "MIT",
        "copyrightText": "Copyright (c) 2022, National Instruments Corp.",
        "comment": f"Built from commit {commit}",
    }
    packages = [root]
    relationships = [_relationship("SPDXRef-DOCUMENT", "DESCRIBES", ROOT_ID)]
    _collect_submodules(REPO_ROOT, "", ROOT_ID, packages, relationships)
    _collect_python_build_tools(packages, relationships)

    created = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"ni-grpc-device-server-{version}",
        "documentNamespace": f"{PROJECT_URL}/spdx/{version}-{commit}-{uuid.uuid4()}",
        "creationInfo": {
            "created": created,
            "creators": ["Organization: NI", "Tool: ni-grpc-device-generate_sbom.py"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def main() -> int:
    """Parse arguments and write the SBOM."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-o", "--output", type=pathlib.Path, help="Output file (default: stdout)")
    args = parser.parse_args()

    document = json.dumps(generate(), indent=2) + "\n"
    if args.output:
        args.output.write_text(document, encoding="utf-8")
        print(f"Wrote {args.output} ({len(json.loads(document)['packages'])} packages)")
    else:
        sys.stdout.write(document)
    return 0


if __name__ == "__main__":
    sys.exit(main())
