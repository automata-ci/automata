#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repo_root

# The embedded Python must remain literal; shell expansion would corrupt it.
# shellcheck disable=SC2016
cargo metadata --manifest-path "$repo_root/Cargo.toml" --locked --no-deps --format-version 1 \
  | python3 -c '
import json
import pathlib
import re
import sys

metadata = json.load(sys.stdin)
repository_root = pathlib.Path(sys.argv[1]).resolve()
image_helper_marker = {"artifact-role": "image-helper"}
actual = []
image_helpers = []
publishable_image_helpers = []
for package in metadata["packages"]:
    package_name = package["name"]
    package_metadata = package["metadata"]
    if package_metadata is not None and not isinstance(package_metadata, dict):
        print(f"error: {package_name} has malformed package metadata", file=sys.stderr)
        raise SystemExit(1)
    role = (package_metadata or {}).get("automata-ci")
    binaries = [
        (package["name"], target["name"])
        for target in package["targets"]
        if "bin" in target["kind"]
    ]
    if role is None:
        actual.extend(binaries)
        continue
    if role != image_helper_marker:
        print(
            f"error: {package_name} has malformed or ambiguous Automata artifact metadata",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if len(binaries) != 1:
        print(
            f"error: image helper {package_name} must expose exactly one binary",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if package["publish"] == []:
        image_helpers.extend(binaries)
    elif package["publish"] == ["crates-io"]:
        publishable_image_helpers.extend(binaries)
    else:
        print(
            f"error: image helper {package_name} has an invalid publication policy",
            file=sys.stderr,
        )
        raise SystemExit(1)

actual.sort()
image_helpers.sort()
publishable_image_helpers.sort()
expected = [
    ("automata-ci", "automata"),
    ("automata-ci-runner", "automata-runner"),
]
expected_image_helpers = [
    ("automata-ci-service-proxy", "automata-ci-service-proxy"),
]
expected_publishable_image_helpers = [
    ("automata-ci-sandbox-guest", "automata-ci-sandbox-guest"),
]

if actual != expected:
    print(f"error: expected exactly two product binaries {expected}, found {actual}", file=sys.stderr)
    raise SystemExit(1)
if image_helpers != expected_image_helpers:
    print(
        f"error: expected exact image-only helpers {expected_image_helpers}, found {image_helpers}",
        file=sys.stderr,
    )
    raise SystemExit(1)
if publishable_image_helpers != expected_publishable_image_helpers:
    print(
        "error: expected exact publishable image helpers "
        f"{expected_publishable_image_helpers}, found {publishable_image_helpers}",
        file=sys.stderr,
    )
    raise SystemExit(1)

packages_by_id = {package["id"]: package["name"] for package in metadata["packages"]}
default_members = sorted(packages_by_id[member] for member in metadata["workspace_default_members"])
expected_default_members = ["automata-ci", "automata-ci-runner"]
if default_members != expected_default_members:
    print(
        "error: default members must remain the two public product packages; "
        f"expected {expected_default_members}, found {default_members}",
        file=sys.stderr,
    )
    raise SystemExit(1)

canonical_license = (repository_root / "LICENSE").read_bytes()
for package in metadata["packages"]:
    package_name = package["name"]
    if package["license"] != "MIT" or package["license_file"] is not None:
        print(
            f"error: {package_name} must use the canonical MIT SPDX metadata",
            file=sys.stderr,
        )
        raise SystemExit(1)
    package_license = pathlib.Path(package["manifest_path"]).parent / "LICENSE"
    if package_license.is_symlink() or not package_license.is_file():
        print(
            f"error: {package_name} LICENSE must be a regular physical file",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        package_license_bytes = package_license.read_bytes()
    except OSError:
        print(f"error: {package_name} does not ship LICENSE", file=sys.stderr)
        raise SystemExit(1)
    if package_license_bytes != canonical_license:
        print(
            f"error: {package_name} LICENSE differs from the repository license",
            file=sys.stderr,
        )
        raise SystemExit(1)

workspace_versions = {package["version"] for package in metadata["packages"]}
if len(workspace_versions) != 1:
    print(
        f"error: workspace packages do not share one release version: {sorted(workspace_versions)}",
        file=sys.stderr,
    )
    raise SystemExit(1)
version = workspace_versions.pop()
runner_package = next(
    package for package in metadata["packages"] if package["name"] == "automata-ci-runner"
)
if runner_package["description"] != (
    "Automata workflow runner for Linux and trusted native Windows/macOS hosts"
):
    print(
        "error: runner package description must match its Linux and trusted native host support boundary",
        file=sys.stderr,
    )
    raise SystemExit(1)

# Remote registries are intentionally not queried from ordinary CI. Keep the
# release state conservative until a reviewed post-publication change can point
# to externally verified artifacts without making a pre-publication commit lie.
publication_state = "unpublished"
if publication_state != "unpublished":
    print(
        "error: add and review the published-documentation policy before changing publication state",
        file=sys.stderr,
    )
    raise SystemExit(1)

for package_readme in sorted((repository_root / "crates").glob("*/README.md")):
    text = package_readme.read_text(encoding="utf-8")
    if re.search(r"https://docs\.rs/automata-ci(?:[-/]|\b)", text):
        print(
            f"error: {package_readme.relative_to(repository_root)} links to unpublished docs.rs API documentation",
            file=sys.stderr,
        )
        raise SystemExit(1)

documentation = {
    relative_path: (repository_root / relative_path).read_text(encoding="utf-8")
    for relative_path in ("README.md", "docs/getting-started.md")
}
for relative_path, text in documentation.items():
    if len(re.findall(r"No public release has been published\b", text)) != 1:
        print(
            f"error: {relative_path} must state the unpublished release status once",
            file=sys.stderr,
        )
        raise SystemExit(1)

readme = documentation["README.md"]
getting_started = documentation["docs/getting-started.md"]
pages_url = "https://automata-ci.github.io/automata/"
for relative_path, text in documentation.items():
    if pages_url not in text:
        print(
            f"error: {relative_path} must link to the hosted UI demo",
            file=sys.stderr,
        )
        raise SystemExit(1)
    demo_boundary = text[text.index(pages_url) : text.index(pages_url) + 600]
    if re.search(r"(?is)(?:cannot|does not).{0,80}(?:execute|run)\s+workflows", demo_boundary) is None:
        print(
            f"error: {relative_path} must state that the hosted UI demo cannot execute workflows",
            file=sys.stderr,
        )
        raise SystemExit(1)
if "## Future release channels" not in getting_started:
    print(
        "error: docs/getting-started.md must keep future distribution channels conditional",
        file=sys.stderr,
    )
    raise SystemExit(1)
if "cargo run --locked --bin automata -- preview" not in readme:
    print("error: README.md must retain the local source preview command", file=sys.stderr)
    raise SystemExit(1)
for package_path in ("crates/automata-ci", "crates/automata-ci-runner"):
    source_install = rf"^cargo install --path {re.escape(package_path)} --locked$"
    if re.search(source_install, getting_started, flags=re.MULTILINE) is None:
        print(
            f"error: docs/getting-started.md lacks the source install for {package_path}",
            file=sys.stderr,
        )
        raise SystemExit(1)

launch_ahead_patterns = {
    "release version assignment": r"(?m)^\s*AUTOMATA_VERSION\s*=",
    "workspace release version": rf"(?<![0-9.]){re.escape(version)}(?![0-9.])",
    "tagged raw installer URL": r"raw\.githubusercontent\.com/automata-ci/automata/[^\s\"`]+/scripts/install\.sh",
    "direct registry install command": r"(?m)^\s*cargo install automata-ci(?:-runner)?(?:\s|$)",
    "versioned product image": r"ghcr\.io/automata-ci/automata(?:-runner)?:[^\s`]+",
    "present-tense prebuilt availability claim": r"(?i)\bprebuilt releases currently\b",
    "registry-version fallback instruction": r"(?i)\buse a matching crates\.io version\b",
}
for relative_path, text in documentation.items():
    for label, pattern in launch_ahead_patterns.items():
        if re.search(pattern, text):
            print(
                f"error: {relative_path} contains unpublished {label}",
                file=sys.stderr,
            )
            raise SystemExit(1)
    if "/main/scripts/install.sh" in text or re.search(
        r"install\.sh\s*\|\s*(?:ba)?sh\b", text
    ):
        print(
            f"error: {relative_path} must not execute a moving installer through a shell pipe",
            file=sys.stderr,
        )
        raise SystemExit(1)

compatibility = (repository_root / "docs/compatibility.md").read_text(
    encoding="utf-8"
)
for unsupported_claim in (
    r"Automata therefore reports\s+GitHub Check Runs",
    r"is proxied to GitHub using a\s+job-scoped token",
):
    if re.search(unsupported_claim, compatibility):
        print(
            "error: compatibility documentation claims an uncomposed GitHub surface",
            file=sys.stderr,
        )
        raise SystemExit(1)
if "## v0.1 implementation status" not in compatibility:
    print(
        "error: compatibility documentation lacks the v0.1 support matrix",
        file=sys.stderr,
    )
    raise SystemExit(1)

print("product binaries and package license payloads verified")
' "$repo_root"

python3 "$repo_root/scripts/ci/publish-crates.py" --list-publishable >/dev/null
python3 "$repo_root/scripts/ci/tests/publish-crates.test.py"
python3 "$repo_root/scripts/ci/verify-documentation.py"
"$repo_root/scripts/dev/create-integration-snapshot.test.sh"
