#!/usr/bin/env python3
"""Stamp and verify the renderer WIT digest in a WebAssembly custom section."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys


MAGIC_AND_COMPONENT_VERSION = b"\x00asm\x0d\x00\x01\x00"
SECTION_NAME = b"automata.renderer.wit-sha256"
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


def encode_uleb128(value: int) -> bytes:
    if value < 0:
        raise ValueError("ULEB128 values must be non-negative")
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        encoded.append(byte)
        if not value:
            return bytes(encoded)


def decode_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if offset >= len(data) or shift >= 64:
            raise ValueError("invalid ULEB128 value")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7


def custom_sections(component: bytes) -> list[tuple[bytes, bytes]]:
    if not component.startswith(MAGIC_AND_COMPONENT_VERSION):
        raise ValueError("input is not a WebAssembly component")

    sections: list[tuple[bytes, bytes]] = []
    offset = len(MAGIC_AND_COMPONENT_VERSION)
    while offset < len(component):
        section_id = component[offset]
        payload_size, payload_offset = decode_uleb128(component, offset + 1)
        payload_end = payload_offset + payload_size
        if payload_end > len(component):
            raise ValueError("WebAssembly section extends beyond end of input")
        if section_id == 0:
            name_size, name_offset = decode_uleb128(component, payload_offset)
            name_end = name_offset + name_size
            if name_end > payload_end:
                raise ValueError("WebAssembly custom-section name is truncated")
            sections.append(
                (component[name_offset:name_end], component[name_end:payload_end])
            )
        offset = payload_end

    if offset != len(component):
        raise ValueError("WebAssembly component has trailing partial data")
    return sections


def validate_digest(value: str) -> bytes:
    if SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError("WIT digest must be a lowercase SHA-256 value")
    return value.encode("ascii")


def stamp(input_path: pathlib.Path, output_path: pathlib.Path, digest: str) -> None:
    component = input_path.read_bytes()
    if any(name == SECTION_NAME for name, _ in custom_sections(component)):
        raise ValueError(f"component already contains {SECTION_NAME.decode()}")

    digest_bytes = validate_digest(digest)
    payload = encode_uleb128(len(SECTION_NAME)) + SECTION_NAME + digest_bytes
    section = b"\x00" + encode_uleb128(len(payload)) + payload
    output_path.write_bytes(component + section)


def verify(component_path: pathlib.Path, digest: str) -> None:
    expected = validate_digest(digest)
    matches = [
        payload
        for name, payload in custom_sections(component_path.read_bytes())
        if name == SECTION_NAME
    ]
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one {SECTION_NAME.decode()} custom section; found {len(matches)}"
        )
    if matches[0] != expected:
        found = matches[0].decode("ascii", "replace")
        raise ValueError(f"component WIT digest mismatch: expected {digest}, found {found}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)

    stamp_parser = subparsers.add_parser("stamp")
    stamp_parser.add_argument("component", type=pathlib.Path)
    stamp_parser.add_argument("output", type=pathlib.Path)
    stamp_parser.add_argument("wit_sha256")

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("component", type=pathlib.Path)
    verify_parser.add_argument("wit_sha256")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.operation == "stamp":
            stamp(arguments.component, arguments.output, arguments.wit_sha256)
        else:
            verify(arguments.component, arguments.wit_sha256)
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
