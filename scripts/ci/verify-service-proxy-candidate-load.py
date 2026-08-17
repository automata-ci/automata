#!/usr/bin/env python3
"""Prove the candidate's exact local tag and content identity in Docker."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from typing import NoReturn


SCRIPT_DIRECTORY = pathlib.Path(__file__).resolve().parent
PUBLICATION_SCRIPT = SCRIPT_DIRECTORY / "service-proxy-publication.py"
PUBLICATION_SPEC = importlib.util.spec_from_file_location(
    "automata_service_proxy_load_publication", PUBLICATION_SCRIPT
)
if PUBLICATION_SPEC is None or PUBLICATION_SPEC.loader is None:
    raise RuntimeError(f"could not load {PUBLICATION_SCRIPT}")
publication = importlib.util.module_from_spec(PUBLICATION_SPEC)
sys.modules[PUBLICATION_SPEC.name] = publication
PUBLICATION_SPEC.loader.exec_module(publication)
candidate = publication.candidate


def fail(message: str) -> NoReturn:
    raise SystemExit(f"service-proxy-candidate-load: {message}")


def docker_command(binary: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [binary, *arguments],
            check=False,
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail(f"Docker command did not complete: {' '.join(arguments)}")


def inspect_optional(binary: str, reference: str) -> dict | None:
    result = docker_command(binary, "image", "inspect", reference)
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError:
        fail(f"Docker image inspection is invalid JSON: {reference}")
    if result.returncode == 1:
        expected_error = f"Error response from daemon: No such image: {reference}\n"
        if document == [] and result.stderr == expected_error:
            return None
        fail(f"Docker could not prove image absence: {reference}")
    if result.returncode != 0 or result.stderr:
        fail(f"Docker could not inspect the image: {reference}")
    if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
        fail(f"Docker image inspection is not singular: {reference}")
    return document[0]


def require_absent(binary: str, reference: str) -> None:
    if inspect_optional(binary, reference) is not None:
        fail(f"refusing to replace a pre-existing image: {reference}")


def inspect_image(binary: str, reference: str) -> dict:
    document = inspect_optional(binary, reference)
    if document is None:
        fail(f"Docker cannot inspect the imported image: {reference}")
    return document


def remove_imported(binary: str, references: tuple[str, ...]) -> None:
    for reference in references:
        if inspect_optional(binary, reference) is None:
            continue
        removed = docker_command(binary, "image", "rm", reference)
        if removed.returncode != 0:
            fail(f"Docker could not remove the imported image: {reference}")
    for reference in references:
        require_absent(binary, reference)


def verify_imported(
    binary: str,
    reference: str,
    digest_reference: str,
    manifest_digest: str,
    config_digest: str,
) -> None:
    by_tag = inspect_image(binary, reference)
    imported_id = by_tag.get("Id")
    if imported_id not in {manifest_digest, config_digest}:
        fail("Docker imported image identity differs")
    if by_tag.get("RepoTags") != [reference]:
        fail("Docker imported image tags differ")
    by_id = inspect_image(binary, imported_id)
    if by_tag != by_id:
        fail("Docker tag and image-ID inspections differ")
    other_id = config_digest if imported_id == manifest_digest else manifest_digest
    require_absent(binary, other_id)
    repository_digests = by_tag.get("RepoDigests")
    by_digest = inspect_optional(binary, digest_reference)
    if imported_id == config_digest:
        if repository_digests != []:
            fail("classic Docker imported image digests differ")
        if by_digest is not None:
            fail("classic Docker exposed a repository digest")
    else:
        if repository_digests != [digest_reference]:
            fail("containerd Docker imported image digests differ")
        if by_digest != by_tag:
            fail("Docker tag and digest inspections differ")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True, type=pathlib.Path)
    parser.add_argument("--source-directory", required=True, type=pathlib.Path)
    parser.add_argument("--expected-commit", required=True)
    arguments = parser.parse_args()

    docker = shutil.which("docker")
    if docker is None:
        fail("Docker is required")
    docker = str(pathlib.Path(docker).resolve())
    members, source, identity, _, _ = publication.load_candidate_archive(
        arguments.candidate,
        arguments.source_directory,
        arguments.expected_commit,
    )
    manifest_digest = identity["image"]["manifest_digest"]
    reference = candidate.local_reference(manifest_digest)
    digest_reference = f"{candidate.LOCAL_IMAGE_NAME}@{manifest_digest}"
    load_archive, expected_config_digest = candidate.docker_load_archive(
        members[candidate.IMAGE_ARCHIVE_NAME],
        manifest_digest,
        source["release"]["source_date_epoch"],
    )
    exact_references = (
        reference,
        digest_reference,
        manifest_digest,
        expected_config_digest,
    )

    for exact_reference in exact_references:
        require_absent(docker, exact_reference)
    load_attempted = False
    try:
        with tempfile.NamedTemporaryFile(
            prefix="automata-service-proxy-", suffix=".docker.tar"
        ) as archive:
            archive.write(load_archive)
            archive.flush()
            os.fsync(archive.fileno())
            load_attempted = True
            result = docker_command(docker, "load", "--input", archive.name)
            if result.returncode != 0:
                fail("Docker rejected the derived candidate load archive")
        verify_imported(
            docker,
            reference,
            digest_reference,
            manifest_digest,
            expected_config_digest,
        )
    finally:
        if load_attempted:
            remove_imported(docker, exact_references)
    print("Service-proxy candidate Docker load identity verified")


if __name__ == "__main__":
    main()
