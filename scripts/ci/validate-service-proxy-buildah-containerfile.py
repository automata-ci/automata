#!/usr/bin/env python3
"""Admit the exact non-executing Containerfile used by Buildah chroot CI."""

from __future__ import annotations

import pathlib
import sys
from typing import NoReturn


EXPECTED_INSTRUCTIONS = (
    "FROM scratch",
    "ARG AUTOMATA_CREATED",
    "ARG AUTOMATA_REVISION",
    "ARG AUTOMATA_SERVICE_PROXY_BINARY_SHA256",
    "ARG AUTOMATA_SERVICE_PROXY_SBOM_SHA256",
    "ARG AUTOMATA_SERVICE_PROXY_SOURCE_SHA256",
    "ARG AUTOMATA_VERSION",
    (
        'LABEL org.opencontainers.image.title="Automata CI service proxy" '
        'org.opencontainers.image.description="Namespace-local bounded TCP and UDP proxy '
        'for job service containers" '
        'org.opencontainers.image.source="https://github.com/automata-ci/automata" '
        'org.opencontainers.image.licenses="MIT" '
        'org.opencontainers.image.created="${AUTOMATA_CREATED}" '
        'org.opencontainers.image.revision="${AUTOMATA_REVISION}" '
        'org.opencontainers.image.version="${AUTOMATA_VERSION}" '
        'io.automata.service-proxy.protocol-version="1" '
        'io.automata.service-proxy.binary.sha256='
        '"${AUTOMATA_SERVICE_PROXY_BINARY_SHA256}" '
        'io.automata.service-proxy.sbom.sha256='
        '"${AUTOMATA_SERVICE_PROXY_SBOM_SHA256}" '
        'io.automata.service-proxy.source.sha256='
        '"${AUTOMATA_SERVICE_PROXY_SOURCE_SHA256}"'
    ),
    (
        "COPY --chmod=0555 automata-ci-service-proxy "
        "/usr/libexec/automata-ci-service-proxy"
    ),
    (
        "COPY --chmod=0444 LICENSE "
        "/usr/share/licenses/automata-ci-service-proxy/LICENSE"
    ),
    (
        "COPY --chmod=0444 THIRD_PARTY_LICENSES.txt "
        "/usr/share/licenses/automata-ci-service-proxy/THIRD_PARTY_LICENSES.txt"
    ),
    (
        "COPY --chmod=0444 THIRD_PARTY_NOTICES.txt "
        "/usr/share/licenses/automata-ci-service-proxy/THIRD_PARTY_NOTICES.txt"
    ),
    (
        "COPY --chmod=0444 VERSION "
        "/usr/share/doc/automata-ci-service-proxy/VERSION"
    ),
    (
        "COPY --chmod=0444 source-provenance.json "
        "/usr/share/doc/automata-ci-service-proxy/source-provenance.json"
    ),
    (
        "COPY --chmod=0444 sbom/automata-ci-service-proxy.cdx.json "
        "/usr/share/sbom/automata-ci-service-proxy.cdx.json"
    ),
    "WORKDIR /",
    "USER 65532:65532",
    'ENTRYPOINT ["/usr/libexec/automata-ci-service-proxy"]',
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"service-proxy-buildah-containerfile: {message}")


def logical_instructions(contents: bytes) -> tuple[str, ...]:
    if any(byte != 0x0A and not 0x20 <= byte <= 0x7E for byte in contents):
        fail("Containerfile contains non-ASCII or control bytes")
    text = contents.decode("ascii")
    if not text.endswith("\n"):
        fail("Containerfile must end with one LF")

    instructions: list[str] = []
    fragments: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            if fragments:
                fail(f"line {line_number} interrupts a continued instruction")
            continue
        if line != line.rstrip() or "\t" in line:
            fail(f"line {line_number} contains unsupported whitespace")
        if "#" in line:
            fail(f"line {line_number} contains an unsupported comment")
        if fragments:
            if not line.startswith(" "):
                fail(f"line {line_number} is not an indented continuation")
        elif line.startswith(" "):
            fail(f"line {line_number} has unexpected indentation")
        if "\\" in line[:-1]:
            fail(f"line {line_number} contains an unsupported escape")

        continued = line.endswith("\\")
        fragment = line[:-1] if continued else line
        fragment = fragment.strip()
        if not fragment:
            fail(f"line {line_number} is an empty instruction fragment")
        fragments.append(fragment)
        if not continued:
            instructions.append(" ".join(fragments))
            fragments = []

    if fragments:
        fail("Containerfile ends inside a continued instruction")
    return tuple(instructions)


def validate(path: pathlib.Path) -> None:
    if path.is_symlink() or not path.is_file():
        fail("Containerfile must be a regular file")
    try:
        contents = path.read_bytes()
    except OSError as error:
        fail(f"could not read Containerfile: {error}")
    if logical_instructions(contents) != EXPECTED_INSTRUCTIONS:
        fail("instructions differ from the reviewed non-executing policy")


def main(arguments: list[str]) -> int:
    if len(arguments) != 1:
        fail("usage: validate-service-proxy-buildah-containerfile.py CONTAINERFILE")
    validate(pathlib.Path(arguments[0]))
    print("Service-proxy Buildah Containerfile policy verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
