#!/usr/bin/env python3
"""Bounded, read-only smart HTTP transport for local dogfood Git snapshots."""

from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import BinaryIO
from urllib.parse import urlsplit


MAX_REQUEST_LINE_BYTES = 8 * 1024
MAX_HEADER_COUNT = 64
MAX_HEADER_BYTES = 32 * 1024
MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024
MAX_CGI_HEADER_COUNT = 64
MAX_CGI_HEADER_BYTES = 32 * 1024
MAX_CGI_HEADER_LINE_BYTES = 8 * 1024
MAX_CONCURRENT_REQUESTS = 8
SOCKET_TIMEOUT_SECONDS = 30
BACKEND_EXIT_TIMEOUT_SECONDS = 5
STREAM_CHUNK_BYTES = 64 * 1024
RFC1918_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)

COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
STATUS = re.compile(r"([1-5][0-9][0-9])(?:[ \t].*)?\Z")
PASSTHROUGH_HEADERS = frozenset(
    {"cache-control", "content-type", "expires", "pragma"}
)


@dataclass(frozen=True)
class ServerConfig:
    project_root: Path
    scratch_directory: Path
    git_http_backend: Path
    listen_address: str


@dataclass(frozen=True)
class Route:
    path_info: str
    query: str


class BoundedGitHttpServer(ThreadingHTTPServer):
    """Threaded HTTP server with a hard concurrent-request ceiling."""

    address_family = socket.AF_INET
    daemon_threads = True
    request_queue_size = MAX_CONCURRENT_REQUESTS
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], config: ServerConfig) -> None:
        self.config = config
        self._request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        super().__init__(address, GitHttpRequestHandler)

    def process_request(
        self, request: socket.socket, client_address: tuple[str, int]
    ) -> None:
        if not self._request_slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.0 503 Service Unavailable\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: 17\r\n"
                    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
                    b"request rejected\n"
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(
        self, request: socket.socket, client_address: tuple[str, int]
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()

    def handle_error(
        self, request: socket.socket, client_address: tuple[str, int]
    ) -> None:
        del request, client_address
        print("git-http: request failed", file=sys.stderr, flush=True)


class GitHttpRequestHandler(BaseHTTPRequestHandler):
    """Strict CGI bridge exposing only Git's read-only smart HTTP endpoints."""

    protocol_version = "HTTP/1.0"
    server_version = "automata-git-http"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(SOCKET_TIMEOUT_SECONDS)

    def handle_one_request(self) -> None:
        try:
            self.raw_requestline = self.rfile.readline(MAX_REQUEST_LINE_BYTES + 1)
            if len(self.raw_requestline) > MAX_REQUEST_LINE_BYTES:
                self.requestline = ""
                self.request_version = "HTTP/1.0"
                self.command = ""
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                return
            if self.command not in {"GET", "HEAD", "POST"}:
                self._method_not_allowed()
                return
            method = getattr(self, f"do_{self.command}")
            method()
            self.wfile.flush()
        except TimeoutError:
            self.close_connection = True
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def parse_request(self) -> bool:
        if not super().parse_request():
            return False
        self.close_connection = True
        if self.request_version not in {"HTTP/1.0", "HTTP/1.1"}:
            self.send_error(505)
            return False
        fields = list(self.headers.raw_items())
        aggregate = sum(len(name) + len(value) + 4 for name, value in fields)
        if len(fields) > MAX_HEADER_COUNT or aggregate > MAX_HEADER_BYTES:
            self.send_error(431)
            return False
        if any(
            not HEADER_NAME.fullmatch(name)
            or any(ord(character) < 32 and character != "\t" for character in value)
            or "\r" in value
            or "\n" in value
            for name, value in fields
        ):
            self.send_error(400)
            return False
        hosts = self.headers.get_all("Host", [])
        if self.request_version == "HTTP/1.1" and len(hosts) != 1:
            self.send_error(400)
            return False
        return True

    def handle_expect_100(self) -> bool:
        self.send_error(417)
        return False

    def do_GET(self) -> None:
        self._serve_info_refs(head_only=False)

    def do_HEAD(self) -> None:
        self._serve_info_refs(head_only=True)

    def do_POST(self) -> None:
        route = self._route("git-upload-pack")
        if route is None or route.query:
            self.send_error(404)
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self.send_error(400)
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if content_type.lower() != "application/x-git-upload-pack-request":
            self.send_error(415)
            return
        length = self._content_length(required=True)
        if length is None:
            return
        self._run_backend(route, length, head_only=False, content_type=content_type)

    def _serve_info_refs(self, head_only: bool) -> None:
        route = self._route("info/refs")
        if route is None or route.query != "service=git-upload-pack":
            self.send_error(404)
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self.send_error(400)
            return
        length = self._content_length(required=False)
        if length is None:
            return
        if length != 0:
            self.send_error(400)
            return
        self._run_backend(route, 0, head_only=head_only, content_type="")

    def _route(self, expected_tail: str) -> Route | None:
        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or parsed.fragment or "%" in parsed.path:
            return None
        expected_components = expected_tail.split("/")
        components = parsed.path.split("/")
        if (
            len(components) != 3 + len(expected_components)
            or components[0] != ""
            or components[3:] != expected_components
        ):
            return None
        owner, repository = components[1:3]
        if not COMPONENT.fullmatch(owner) or not COMPONENT.fullmatch(repository):
            return None
        candidate = self._config.project_root / owner / repository
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            return None
        if resolved != candidate or not resolved.is_dir():
            return None
        head = resolved / "HEAD"
        objects = resolved / "objects"
        if (
            not head.is_file()
            or head.is_symlink()
            or not objects.is_dir()
            or objects.is_symlink()
        ):
            return None
        return Route(parsed.path, parsed.query)

    def _content_length(self, required: bool) -> int | None:
        values = self.headers.get_all("Content-Length", [])
        if not values:
            if required:
                self.send_error(411)
                return None
            return 0
        if len(values) != 1 or not values[0].isdigit():
            self.send_error(400)
            return None
        length = int(values[0], 10)
        if length > MAX_REQUEST_BODY_BYTES:
            self.send_error(413)
            return None
        return length

    def _run_backend(
        self, route: Route, content_length: int, head_only: bool, content_type: str
    ) -> None:
        process: subprocess.Popen[bytes] | None = None
        response_started = False
        try:
            self.connection.settimeout(SOCKET_TIMEOUT_SECONDS)
            process = subprocess.Popen(
                [str(self._config.git_http_backend)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=self._config.scratch_directory,
                env=self._backend_environment(route, content_length, content_type),
                close_fds=True,
                start_new_session=True,
            )
            assert process.stdin is not None
            assert process.stdout is not None
            remaining = content_length
            while remaining:
                chunk = self.rfile.read(min(STREAM_CHUNK_BYTES, remaining))
                if not chunk:
                    raise OSError("incomplete request body")
                process.stdin.write(chunk)
                remaining -= len(chunk)
            process.stdin.close()

            status, headers = read_cgi_headers(process.stdout)
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Connection", "close")
            self.end_headers()
            response_started = True

            while True:
                chunk = process.stdout.read(STREAM_CHUNK_BYTES)
                if not chunk:
                    break
                if not head_only:
                    self.wfile.write(chunk)
            process.stdout.close()
            return_code = process.wait(timeout=BACKEND_EXIT_TIMEOUT_SECONDS)
            if return_code != 0:
                self._redacted_failure()
        except (OSError, ValueError, subprocess.SubprocessError):
            if process is not None:
                stop_backend(process)
            if not response_started:
                self.send_error(502)
            self._redacted_failure()

    def _backend_environment(
        self, route: Route, content_length: int, content_type: str
    ) -> dict[str, str]:
        backend_directory = self._config.git_http_backend.parent
        environment = {
            "CONTENT_LENGTH": str(content_length),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_HTTP_EXPORT_ALL": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PROJECT_ROOT": str(self._config.project_root),
            "HOME": str(self._config.scratch_directory),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": f"{backend_directory}:/usr/bin:/bin",
            "PATH_INFO": route.path_info,
            "QUERY_STRING": route.query,
            "REMOTE_ADDR": self.client_address[0],
            "REQUEST_METHOD": self.command,
            "SCRIPT_NAME": "",
            "SERVER_NAME": self._config.listen_address,
            "SERVER_PORT": str(self.server.server_port),
            "SERVER_PROTOCOL": self.request_version,
            "SERVER_SOFTWARE": "automata-git-http",
            "TMPDIR": str(self._config.scratch_directory),
        }
        if content_type:
            environment["CONTENT_TYPE"] = content_type
        git_protocol = self.headers.get("Git-Protocol")
        if git_protocol is not None and len(git_protocol) <= 256:
            environment["HTTP_GIT_PROTOCOL"] = git_protocol
        return environment

    @property
    def _config(self) -> ServerConfig:
        return self.server.config

    def _method_not_allowed(self) -> None:
        self.send_response(405)
        self.send_header("Allow", "GET, HEAD, POST")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "17")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"request rejected\n")

    def send_error(
        self, code: int, message: str | None = None, explain: str | None = None
    ) -> None:
        del message, explain
        body = b"request rejected\n"
        self.send_response(code)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        if getattr(self, "command", "") != "HEAD":
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    @staticmethod
    def _redacted_failure() -> None:
        print("git-http: request failed", file=sys.stderr, flush=True)


def read_cgi_headers(stream: BinaryIO) -> tuple[int, list[tuple[str, str]]]:
    total = 0
    lines: list[bytes] = []
    while len(lines) < MAX_CGI_HEADER_COUNT:
        line = stream.readline(MAX_CGI_HEADER_LINE_BYTES + 1)
        if not line or len(line) > MAX_CGI_HEADER_LINE_BYTES:
            raise ValueError("invalid CGI response")
        total += len(line)
        if total > MAX_CGI_HEADER_BYTES:
            raise ValueError("invalid CGI response")
        if line in {b"\n", b"\r\n"}:
            break
        lines.append(line.rstrip(b"\r\n"))
    else:
        raise ValueError("invalid CGI response")

    status = 200
    response_headers: list[tuple[str, str]] = []
    seen: set[str] = set()
    for encoded in lines:
        try:
            name_bytes, value_bytes = encoded.split(b":", 1)
            name = name_bytes.decode("ascii")
            value = value_bytes.decode("latin-1").strip()
        except (ValueError, UnicodeDecodeError) as error:
            raise ValueError("invalid CGI response") from error
        normalized = name.lower()
        if not HEADER_NAME.fullmatch(name) or normalized in seen:
            raise ValueError("invalid CGI response")
        if any(ord(character) < 32 and character != "\t" for character in value):
            raise ValueError("invalid CGI response")
        seen.add(normalized)
        if normalized == "status":
            matched = STATUS.fullmatch(value)
            if matched is None:
                raise ValueError("invalid CGI response")
            status = int(matched.group(1), 10)
        elif normalized in PASSTHROUGH_HEADERS:
            response_headers.append((name, value))
    return status, response_headers


def stop_backend(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=BACKEND_EXIT_TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.wait(timeout=BACKEND_EXIT_TIMEOUT_SECONDS)
        except subprocess.SubprocessError:
            pass


def canonical_directory(value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise argparse.ArgumentTypeError("directory does not exist") from error
    if resolved != candidate or not resolved.is_dir() or candidate.is_symlink():
        raise argparse.ArgumentTypeError("directory must be exact and canonical")
    return resolved


def absolute_executable(value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        raise argparse.ArgumentTypeError("git-http-backend path must be absolute")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise argparse.ArgumentTypeError("git-http-backend does not exist") from error
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise argparse.ArgumentTypeError("git-http-backend is not executable")
    return resolved


def listen_address(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "listen address must be a canonical IPv4 address"
        ) from error
    if str(address) != value:
        raise argparse.ArgumentTypeError(
            "listen address must be a canonical IPv4 address"
        )
    if not address.is_loopback and not any(
        address in network for network in RFC1918_NETWORKS
    ):
        raise argparse.ArgumentTypeError(
            "listen address must be an exact RFC 1918 address"
        )
    return str(address)


def port(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be a canonical integer") from error
    if str(parsed) != value:
        raise argparse.ArgumentTypeError("port must be a canonical integer")
    if parsed != 0 and not 1024 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("port must be zero or an unprivileged TCP port")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="serve local bare Git repositories over bounded smart HTTP"
    )
    parser.add_argument("--project-root", required=True, type=canonical_directory)
    parser.add_argument("--scratch-directory", required=True, type=canonical_directory)
    parser.add_argument("--git-http-backend", required=True, type=absolute_executable)
    parser.add_argument("--listen-address", required=True, type=listen_address)
    parser.add_argument("--port", required=True, type=port)
    parser.add_argument(
        "--allow-loopback-test-listener",
        action="store_true",
        help="allow a loopback address and ephemeral port for isolated contract tests",
    )
    arguments = parser.parse_args()
    address = ipaddress.IPv4Address(arguments.listen_address)
    if address.is_loopback and not arguments.allow_loopback_test_listener:
        parser.error("loopback listeners require --allow-loopback-test-listener")
    if arguments.allow_loopback_test_listener and not address.is_loopback:
        parser.error("--allow-loopback-test-listener requires a loopback address")
    if arguments.port == 0 and not arguments.allow_loopback_test_listener:
        parser.error("port zero requires --allow-loopback-test-listener")
    return arguments


def main() -> int:
    arguments = parse_args()
    project_root: Path = arguments.project_root
    scratch_directory: Path = arguments.scratch_directory
    if (
        project_root == scratch_directory
        or project_root in scratch_directory.parents
        or scratch_directory in project_root.parents
    ):
        print("git-http: project and scratch directories must be disjoint", file=sys.stderr)
        return 2
    config = ServerConfig(
        project_root=project_root,
        scratch_directory=scratch_directory,
        git_http_backend=arguments.git_http_backend,
        listen_address=arguments.listen_address,
    )
    try:
        server = BoundedGitHttpServer(
            (arguments.listen_address, arguments.port), config
        )
    except OSError:
        print("git-http: startup failed", file=sys.stderr)
        return 1

    def request_shutdown(_signal: int, _frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, request_shutdown)
    print(
        f"listening=http://{arguments.listen_address}:{server.server_port}/",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
