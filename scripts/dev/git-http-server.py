#!/usr/bin/env python3
"""Bounded, read-only smart HTTP transport for local integration Git snapshots."""

from __future__ import annotations

import argparse
import ipaddress
import math
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import BinaryIO, cast
from urllib.parse import urlsplit


MAX_REQUEST_LINE_BYTES = 8 * 1024
MAX_HEADER_COUNT = 64
MAX_HEADER_BYTES = 32 * 1024
MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024
MAX_CGI_HEADER_COUNT = 64
MAX_CGI_HEADER_BYTES = 32 * 1024
MAX_CGI_HEADER_LINE_BYTES = 8 * 1024
MAX_CONCURRENT_REQUESTS = 8
MAX_BACKEND_RESPONSE_BYTES = 512 * 1024 * 1024
DEFAULT_REQUEST_DEADLINE_SECONDS = 30.0
MIN_TEST_REQUEST_DEADLINE_SECONDS = 0.25
BACKEND_TERMINATION_GRACE_SECONDS = 1.0
BACKEND_KILL_WAIT_SECONDS = 1.0
BACKEND_CLEANUP_WAIT_SECONDS = 3.0
BACKEND_POLL_INTERVAL_SECONDS = 0.01
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
BACKEND_LAUNCHER = """\
import os
import signal
import sys

os.chdir(sys.argv[1])
os.setsid()
for signal_name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ"):
    requested_signal = getattr(signal, signal_name, None)
    if requested_signal is not None:
        signal.signal(requested_signal, signal.SIG_DFL)
os.execve(sys.argv[2], [sys.argv[2]], dict(os.environ))
"""
PROC_ROOT = Path("/proc")


@dataclass(frozen=True)
class ServerConfig:
    project_root: Path
    scratch_directory: Path
    git_http_backend: Path
    listen_address: str
    request_deadline_seconds: float


@dataclass(frozen=True)
class Route:
    path_info: str
    query: str


@dataclass(eq=False)
class ManagedBackend:
    process: subprocess.Popen[bytes]
    process_group: int
    stopped: threading.Event = field(default_factory=threading.Event, repr=False)


@dataclass
class ActiveRequest:
    deadline: float
    deadline_cancelled: threading.Event = field(
        default_factory=threading.Event, repr=False
    )
    deadline_worker: threading.Thread | None = field(default=None, repr=False)
    backend: ManagedBackend | None = None
    expired: bool = False


class ServerShutdownRequested(Exception):
    """Stop the serve loop after a signal-safe shutdown request."""


class BoundedGitHttpServer(ThreadingHTTPServer):
    """Threaded HTTP server with a hard concurrent-request ceiling."""

    address_family = socket.AF_INET
    daemon_threads = False
    block_on_close = True
    request_queue_size = MAX_CONCURRENT_REQUESTS
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], config: ServerConfig) -> None:
        self.config = config
        self._request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        self._lifecycle_lock = threading.Lock()
        self._accepting_requests = True
        self._shutdown_requested = False
        self._active_requests: dict[socket.socket, ActiveRequest] = {}
        self._cleanup_failed = False
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
            state = self._register_request(request)
            if state is None:
                self._request_slots.release()
                self.shutdown_request(request)
                return
            assert state.deadline_worker is not None
            state.deadline_worker.start()
            super().process_request(request, client_address)
        except BaseException:
            self._complete_request(request)
            self._request_slots.release()
            raise

    def process_request_thread(
        self, request: socket.socket, client_address: tuple[str, int]
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._complete_request(request)
            self._request_slots.release()

    def _register_request(self, request: socket.socket) -> ActiveRequest | None:
        state = ActiveRequest(
            deadline=time.monotonic() + self.config.request_deadline_seconds
        )
        state.deadline_worker = threading.Thread(
            target=self._wait_for_request_deadline,
            args=(request, state),
            name="git-http-request-deadline",
            daemon=True,
        )
        with self._lifecycle_lock:
            if self._shutdown_requested or not self._accepting_requests:
                return None
            self._active_requests[request] = state
            if self._shutdown_requested:
                del self._active_requests[request]
                return None
        return state

    def _wait_for_request_deadline(
        self, request: socket.socket, state: ActiveRequest
    ) -> None:
        remaining = max(0.0, state.deadline - time.monotonic())
        if not state.deadline_cancelled.wait(remaining):
            self._expire_request(request)

    def _complete_request(self, request: socket.socket) -> None:
        with self._lifecycle_lock:
            state = self._active_requests.pop(request, None)
        if state is not None:
            state.deadline_cancelled.set()
            worker = state.deadline_worker
            if worker is not None and worker.ident is not None:
                worker.join(BACKEND_CLEANUP_WAIT_SECONDS)
                if worker.is_alive():
                    self._record_cleanup_failure()

    def request_deadline(self, request: socket.socket) -> float:
        with self._lifecycle_lock:
            state = self._active_requests.get(request)
            if state is None:
                return time.monotonic()
            return state.deadline

    def request_expired(self, request: socket.socket) -> bool:
        with self._lifecycle_lock:
            state = self._active_requests.get(request)
            if state is None:
                return True
            if not state.expired and time.monotonic() >= state.deadline:
                state.expired = True
            return state.expired

    def register_backend(
        self, request: socket.socket, backend: ManagedBackend
    ) -> bool:
        with self._lifecycle_lock:
            state = self._active_requests.get(request)
            if (
                self._shutdown_requested
                or not self._accepting_requests
                or state is None
                or state.expired
                or state.backend is not None
            ):
                return False
            state.backend = backend
            if (
                self._shutdown_requested
                or state.expired
                or time.monotonic() >= state.deadline
            ):
                state.backend = None
                state.expired = True
                return False
            return True

    def release_backend(
        self, request: socket.socket, backend: ManagedBackend
    ) -> int | None:
        owns_cleanup = False
        with self._lifecycle_lock:
            state = self._active_requests.get(request)
            if state is not None and state.backend is backend:
                state.backend = None
                owns_cleanup = True
        if owns_cleanup:
            self._stop_backends([backend], graceful=False)
        elif not backend.stopped.wait(BACKEND_CLEANUP_WAIT_SECONDS):
            self._record_cleanup_failure()
        return backend.process.returncode

    def stop_unregistered_backend(self, backend: ManagedBackend) -> None:
        self._stop_backends([backend], graceful=False)

    def _expire_request(self, request: socket.socket) -> None:
        backend: ManagedBackend | None = None
        with self._lifecycle_lock:
            state = self._active_requests.get(request)
            if state is None or state.expired:
                return
            state.expired = True
            backend = state.backend
            state.backend = None
        self._interrupt_request(request)
        if backend is not None:
            self._stop_backends([backend], graceful=False)

    def begin_shutdown(self) -> bool:
        with self._lifecycle_lock:
            first_request = not self._shutdown_requested
            self._shutdown_requested = True
            self._accepting_requests = False
            return first_request

    def request_signal_shutdown(self) -> None:
        self._shutdown_requested = True

    def service_actions(self) -> None:
        if self._shutdown_requested:
            raise ServerShutdownRequested

    def abort_active_requests(self) -> None:
        backends: list[ManagedBackend] = []
        requests: list[socket.socket] = []
        with self._lifecycle_lock:
            self._accepting_requests = False
            for request, state in self._active_requests.items():
                state.expired = True
                state.deadline_cancelled.set()
                requests.append(request)
                if state.backend is not None:
                    backends.append(state.backend)
                    state.backend = None
        for request in requests:
            self._interrupt_request(request)
        if backends:
            self._stop_backends(backends, graceful=True)

    def _stop_backends(
        self, backends: list[ManagedBackend], *, graceful: bool
    ) -> None:
        cleanup_succeeded = False
        try:
            try:
                cleanup_succeeded = terminate_backends(
                    backends, graceful=graceful
                )
            except (AttributeError, OSError, subprocess.SubprocessError):
                pass
        finally:
            try:
                if not cleanup_succeeded:
                    self._record_cleanup_failure()
            finally:
                for backend in backends:
                    backend.stopped.set()

    @staticmethod
    def _interrupt_request(request: socket.socket) -> None:
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _record_cleanup_failure(self) -> None:
        with self._lifecycle_lock:
            first_failure = not self._cleanup_failed
            self._cleanup_failed = True
        if first_failure:
            try:
                print("git-http: backend cleanup failed", file=sys.stderr, flush=True)
            except OSError:
                pass

    @property
    def cleanup_failed(self) -> bool:
        with self._lifecycle_lock:
            return self._cleanup_failed

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
        self._deadline = self._bounded_server.request_deadline(self.request)
        self._set_socket_deadline()

    def handle_one_request(self) -> None:
        try:
            self._set_socket_deadline()
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
            self._set_socket_deadline()
            method = getattr(self, f"do_{self.command}")
            method()
            self._set_socket_deadline()
            self.wfile.flush()
        except OSError:
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
        backend: ManagedBackend | None = None
        process: subprocess.Popen[bytes] | None = None
        backend_return_code: int | None = None
        response_started = False
        response_completed = False
        try:
            self._set_socket_deadline()
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    BACKEND_LAUNCHER,
                    str(self._config.scratch_directory),
                    str(self._config.git_http_backend),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self._backend_environment(route, content_length, content_type),
                close_fds=True,
            )
            backend = ManagedBackend(process=process, process_group=process.pid)
            if not self._bounded_server.register_backend(self.request, backend):
                self._bounded_server.stop_unregistered_backend(backend)
                backend = None
                raise TimeoutError("request ended before backend registration")
            assert process.stdin is not None
            assert process.stdout is not None
            remaining = content_length
            while remaining:
                self._set_socket_deadline()
                chunk = self.rfile.read(min(STREAM_CHUNK_BYTES, remaining))
                if not chunk:
                    raise OSError("incomplete request body")
                process.stdin.write(chunk)
                remaining -= len(chunk)
            process.stdin.close()

            status, headers = read_cgi_headers(process.stdout)
            self._set_socket_deadline()
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Connection", "close")
            self.end_headers()
            response_started = True

            response_bytes = 0
            while True:
                chunk = process.stdout.read(STREAM_CHUNK_BYTES)
                if not chunk:
                    break
                response_bytes += len(chunk)
                if response_bytes > MAX_BACKEND_RESPONSE_BYTES:
                    raise ValueError("CGI response exceeds the byte limit")
                if not head_only:
                    self._set_socket_deadline()
                    self.wfile.write(chunk)
            process.stdout.close()
            if wait_for_backend_leaders(
                [backend], time.monotonic() + self._remaining_seconds()
            ):
                raise TimeoutError("backend did not exit before the request deadline")
            response_completed = True
        except (OSError, ValueError, subprocess.SubprocessError):
            if (
                not response_started
                and not self._bounded_server.request_expired(self.request)
            ):
                try:
                    self.send_error(502)
                except OSError:
                    pass
            if not self._bounded_server.request_expired(self.request):
                self._redacted_failure()
        finally:
            if backend is not None:
                backend_return_code = self._bounded_server.release_backend(
                    self.request, backend
                )
            if process is not None:
                for stream in (process.stdin, process.stdout):
                    if stream is not None and not stream.closed:
                        try:
                            stream.close()
                        except OSError:
                            pass
        if (
            response_completed
            and backend_return_code != 0
            and not self._bounded_server.request_expired(self.request)
        ):
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
        return self._bounded_server.config

    @property
    def _bounded_server(self) -> BoundedGitHttpServer:
        return cast(BoundedGitHttpServer, self.server)

    def _remaining_seconds(self) -> float:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request deadline exceeded")
        return remaining

    def _set_socket_deadline(self) -> None:
        self.connection.settimeout(self._remaining_seconds())

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


def signal_process_group(backend: ManagedBackend, requested_signal: int) -> bool:
    try:
        os.killpg(backend.process_group, requested_signal)
        return True
    except ProcessLookupError:
        # The trusted launcher is registered before it calls setsid(). If
        # cleanup wins that short race, signaling its still-reserved PID stops
        # it before it can create the backend process group.
        try:
            os.kill(backend.process.pid, requested_signal)
            return True
        except ProcessLookupError:
            return True
        except OSError:
            return False
    except OSError:
        return False


def backend_leader_has_exited(backend: ManagedBackend) -> bool:
    try:
        result = os.waitid(
            os.P_PID,
            backend.process.pid,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
    except ChildProcessError:
        return backend.process.returncode is not None
    return result is not None


def wait_for_backend_leaders(
    backends: list[ManagedBackend], deadline: float
) -> list[ManagedBackend]:
    while True:
        remaining = [
            backend for backend in backends if not backend_leader_has_exited(backend)
        ]
        if not remaining:
            return []
        delay = min(BACKEND_POLL_INTERVAL_SECONDS, deadline - time.monotonic())
        if delay <= 0:
            return remaining
        time.sleep(delay)


def proc_process_group_and_state(pid: int) -> tuple[int, str] | None:
    try:
        encoded = (PROC_ROOT / str(pid) / "stat").read_text(encoding="ascii")
        fields = encoded[encoded.rfind(")") + 2 :].split()
        return int(fields[2], 10), fields[0]
    except (IndexError, OSError, UnicodeDecodeError, ValueError):
        return None


def backend_group_has_live_members(backend: ManagedBackend) -> bool:
    if not backend_leader_has_exited(backend):
        return True
    try:
        entries = PROC_ROOT.iterdir()
        for entry in entries:
            if not entry.name.isdigit() or int(entry.name, 10) == backend.process.pid:
                continue
            identity = proc_process_group_and_state(int(entry.name, 10))
            if identity is not None:
                process_group, state = identity
                if process_group == backend.process_group and state != "Z":
                    return True
    except OSError:
        return True
    return False


def wait_for_backend_groups(
    backends: list[ManagedBackend], deadline: float
) -> list[ManagedBackend]:
    while True:
        remaining = [
            backend for backend in backends if backend_group_has_live_members(backend)
        ]
        if not remaining:
            return []
        for backend in remaining:
            signal_process_group(backend, signal.SIGKILL)
        delay = min(BACKEND_POLL_INTERVAL_SECONDS, deadline - time.monotonic())
        if delay <= 0:
            return remaining
        time.sleep(delay)


def terminate_backends(
    backends: list[ManagedBackend], *, graceful: bool
) -> bool:
    pending = [backend for backend in backends if not backend.stopped.is_set()]
    if not pending:
        return True

    cleanup_ok = True
    if graceful:
        for backend in pending:
            cleanup_ok = signal_process_group(backend, signal.SIGTERM) and cleanup_ok
        wait_for_backend_leaders(
            pending, time.monotonic() + BACKEND_TERMINATION_GRACE_SECONDS
        )

    # The unreaped session leader reserves the numeric process-group identity.
    # Signal every group before reaping its leader so a recycled PGID can never
    # direct cleanup at an unrelated process group. SIGKILL also removes any
    # descendants left behind by a backend that exited on its own.
    for backend in pending:
        cleanup_ok = signal_process_group(backend, signal.SIGKILL) and cleanup_ok
    final_deadline = time.monotonic() + BACKEND_KILL_WAIT_SECONDS
    survivors = wait_for_backend_groups(pending, final_deadline)
    if survivors:
        cleanup_ok = False

    for backend in pending:
        try:
            backend.process.wait(timeout=max(0.0, final_deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            cleanup_ok = False
    return cleanup_ok


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


def request_deadline_seconds(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "request deadline must be a finite number of seconds"
        ) from error
    if (
        not math.isfinite(parsed)
        or parsed < MIN_TEST_REQUEST_DEADLINE_SECONDS
        or parsed > DEFAULT_REQUEST_DEADLINE_SECONDS
    ):
        raise argparse.ArgumentTypeError(
            "request deadline is outside the supported test range"
        )
    return parsed


def backend_lifecycle_supported() -> bool:
    required_os_features = ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT", "waitid")
    return (
        all(hasattr(os, feature) for feature in required_os_features)
        and Path(sys.executable).is_absolute()
        and os.access(sys.executable, os.X_OK)
        and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
        and proc_process_group_and_state(os.getpid()) is not None
    )


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
        "--request-deadline-seconds",
        type=request_deadline_seconds,
        default=None,
        help=argparse.SUPPRESS,
    )
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
    if (
        arguments.request_deadline_seconds is not None
        and not arguments.allow_loopback_test_listener
    ):
        parser.error("request deadline overrides require a loopback test listener")
    return arguments


def main() -> int:
    arguments = parse_args()
    if not backend_lifecycle_supported():
        print("git-http: required process lifecycle support is unavailable", file=sys.stderr)
        return 2
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
        request_deadline_seconds=(
            arguments.request_deadline_seconds or DEFAULT_REQUEST_DEADLINE_SECONDS
        ),
    )
    try:
        server = BoundedGitHttpServer(
            (arguments.listen_address, arguments.port), config
        )
    except OSError:
        print("git-http: startup failed", file=sys.stderr)
        return 1

    def request_shutdown(_signal: int, _frame: object) -> None:
        server.request_signal_shutdown()

    previous_sigterm_handler = signal.signal(signal.SIGTERM, request_shutdown)
    try:
        print(
            f"listening=http://{arguments.listen_address}:{server.server_port}/",
            flush=True,
        )
        try:
            server.serve_forever(poll_interval=0.1)
        except (KeyboardInterrupt, ServerShutdownRequested):
            pass
    finally:
        server.begin_shutdown()
        server.abort_active_requests()
        server.server_close()
        signal.signal(signal.SIGTERM, previous_sigterm_handler)
    return 1 if server.cleanup_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
