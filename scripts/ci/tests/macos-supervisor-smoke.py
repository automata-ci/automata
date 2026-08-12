#!/usr/bin/env python3
"""Exercise the shipped runner's private macOS supervisor protocol."""

import json
import pathlib
import struct
import subprocess
import sys

REQUEST_MAGIC = b"AMSQ"
RESPONSE_MAGIC = b"AMSR"


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: macos-supervisor-smoke.py <automata-runner>")
    runner = pathlib.Path(sys.argv[1]).resolve(strict=True)
    request = json.dumps(
        {
            "program": "/bin/sh",
            "arguments": ["-c", "printf macos-supervisor-smoke"],
            "working_directory": "/",
            "environment": [],
            "timeout_millis": 5000,
            "output_limit": 4096,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    frame = REQUEST_MAGIC + struct.pack("<I", len(request)) + request
    process = subprocess.Popen(
        [str(runner), "__macos-job-supervisor"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    process.stdin.write(frame)
    process.stdin.flush()
    try:
        response = read_response(process.stdout)
    finally:
        process.stdin.close()
    stderr = process.stderr.read() if process.stderr is not None else b""
    return_code = process.wait(timeout=15)
    if return_code != 0:
        raise RuntimeError("shipped macOS supervisor exited unsuccessfully")
    if stderr:
        raise RuntimeError("shipped macOS supervisor emitted diagnostics")
    verify_response(response)
    return 0


def read_response(stream) -> bytes:
    header = read_exact(stream, 14)
    record_count = struct.unpack_from("<I", header, 10)[0]
    response = bytearray(header)
    for _ in range(record_count):
        record_header = read_exact(stream, 6)
        response.extend(record_header)
        length = struct.unpack_from("<I", record_header, 2)[0]
        response.extend(read_exact(stream, length))
    return bytes(response)


def read_exact(stream, length: int) -> bytes:
    if stream is None:
        raise RuntimeError("macOS supervisor output pipe is unavailable")
    result = bytearray()
    while len(result) < length:
        chunk = stream.read(length - len(result))
        if not chunk:
            raise RuntimeError("truncated macOS supervisor response")
        result.extend(chunk)
    return bytes(result)


def verify_response(response: bytes) -> None:
    if len(response) < 14 or response[:4] != RESPONSE_MAGIC:
        raise RuntimeError("invalid macOS supervisor response header")
    termination, truncated = response[4:6]
    exit_code, record_count = struct.unpack_from("<iI", response, 6)
    if termination != 0 or truncated != 0 or exit_code != 0:
        raise RuntimeError("unexpected macOS supervisor termination")
    offset = 14
    stdout = bytearray()
    ended = set()
    for _ in range(record_count):
        if offset + 6 > len(response):
            raise RuntimeError("truncated macOS supervisor output record")
        stream, end = response[offset : offset + 2]
        length = struct.unpack_from("<I", response, offset + 2)[0]
        offset += 6
        if offset + length > len(response):
            raise RuntimeError("truncated macOS supervisor output bytes")
        content = response[offset : offset + length]
        offset += length
        if end:
            if content:
                raise RuntimeError("end-of-stream record carried data")
            ended.add(stream)
        elif stream == 0:
            stdout.extend(content)
    if offset != len(response) or ended != {0, 1}:
        raise RuntimeError("invalid macOS supervisor response tail")
    if bytes(stdout) != b"macos-supervisor-smoke":
        raise RuntimeError("macOS supervisor did not preserve stdout")


if __name__ == "__main__":
    raise SystemExit(main())
