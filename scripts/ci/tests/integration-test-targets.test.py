#!/usr/bin/env python3
"""Verify that aggregate integration targets own every Rust test source."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]

# A reviewed entry prevents either implicit targets or an unreviewed aggregate
# rename from silently changing the workspace test topology.
AGGREGATES = {
    "automata-ci-blob-s3": "blob_s3",
    "automata-ci-control": "control",
    "automata-ci-core": "core",
    "automata-ci-credential": "credential",
    "automata-ci-execution": "execution",
    "automata-ci-expression-github": "expression_github",
    "automata-ci-github-delivery": "github_delivery",
    "automata-ci-github-runtime": "github_runtime",
    "automata-ci-key-management": "key_management",
    "automata-ci-metrics": "metrics",
    "automata-ci-postgres": "postgres",
    "automata-ci-protocol": "protocol",
    "automata-ci-runner": "runner",
    "automata-ci-runner-crypto": "runner_crypto",
    "automata-ci-sandbox-kubernetes": "sandbox_kubernetes",
    "automata-ci-secret": "secret",
    "automata-ci-store": "store_contracts",
    "automata-ci-ui-renderer": "ui_renderer",
}

MODULE = re.compile(
    r"(?m)(?P<attrs>(?:^[ \t]*#\[[^\n]*\][ \t]*\n)*)"
    r"^[ \t]*(?:pub(?:\([^\n)]*\))?[ \t]+)?"
    r"mod[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t]*;"
)
PATH = re.compile(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]')


def fail(message: str) -> None:
    raise SystemExit(message)


def display(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def children(source: Path, root: Path, tests_dir: Path) -> list[Path]:
    module_dir = (
        source.parent
        if source == root or source.name == "mod.rs"
        else source.parent / source.stem
    )
    found = []
    for declaration in MODULE.finditer(source.read_text(encoding="utf-8")):
        name = declaration.group("name")
        paths = PATH.findall(declaration.group("attrs"))
        if len(paths) > 1:
            fail(f"multiple path attributes for {name} in {display(source)}")
        if paths:
            candidates = [source.parent / paths[0]]
        else:
            candidates = [module_dir / f"{name}.rs", module_dir / name / "mod.rs"]
        existing = [candidate.resolve() for candidate in candidates if candidate.is_file()]
        if len(existing) != 1:
            fail(
                f"{name} in {display(source)} resolves to {len(existing)} files; "
                f"candidates={[display(path) for path in candidates]}"
            )
        child = existing[0]
        if not child.is_relative_to(tests_dir.resolve()):
            fail(f"{name} in {display(source)} escapes {display(tests_dir)}")
        found.append(child)
    return found


def owned_sources(root: Path, tests_dir: Path) -> set[Path]:
    owned: set[Path] = set()
    pending = [root.resolve()]
    while pending:
        source = pending.pop()
        if source not in owned:
            owned.add(source)
            pending.extend(children(source, root.resolve(), tests_dir))
    return owned


def main() -> None:
    manifests = {}
    configured = set()
    for manifest in sorted((ROOT / "crates").glob("*/Cargo.toml")):
        cargo = tomllib.loads(manifest.read_text(encoding="utf-8"))
        package = cargo.get("package", {})
        name = package.get("name")
        if not isinstance(name, str):
            fail(f"missing package name in {display(manifest)}")
        manifests[name] = (manifest, cargo)
        if package.get("autotests") is False:
            configured.add(name)

    reviewed = set(AGGREGATES)
    if configured != reviewed:
        fail(
            "reviewed aggregate set changed; "
            f"added={sorted(configured - reviewed)}, removed={sorted(reviewed - configured)}"
        )

    source_count = 0
    for package, target_name in AGGREGATES.items():
        manifest, cargo = manifests[package]
        target_path = f"tests/{target_name}.rs"
        targets = cargo.get("test", [])
        expected = [(target_name, target_path)]
        actual = [(target.get("name"), target.get("path")) for target in targets]
        if actual != expected:
            fail(f"{package} integration targets changed: {actual!r} != {expected!r}")

        tests_dir = manifest.parent / "tests"
        root = (manifest.parent / target_path).resolve()
        if not root.is_file():
            fail(f"{package} aggregate root is missing: {display(root)}")
        owned = owned_sources(root, tests_dir)
        inventory = {source.resolve() for source in tests_dir.rglob("*.rs")}
        if owned != inventory:
            fail(
                f"{package} has unowned test sources: "
                f"{sorted(display(path) for path in inventory - owned)}"
            )
        source_count += len(inventory)

    print(
        f"verified {len(AGGREGATES)} aggregate integration targets "
        f"own {source_count} Rust test source files"
    )


if __name__ == "__main__":
    main()
