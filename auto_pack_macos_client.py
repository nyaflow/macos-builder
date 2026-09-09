#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
from http.client import HTTPConnection, HTTPSConnection, HTTPException
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from threading import Event, Lock, Thread, current_thread
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import zipfile


DEFAULT_TIMEOUT = 30.0
UPLOAD_CHUNK_SIZE = 10 * 1024 * 1024
SERVER_ENV = "BUILD_SERVER"
TOKEN_ENV = "BUILD_TOKEN"
SOURCE_ROUTE = "/source"
LOG_ROUTE = "/logs"
DIST_ROUTE = "/dist"
SESSION_HEADER = "X-Build-Session"
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WEBSOCKET_HEARTBEAT_INTERVAL = 20.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="工作目录；默认使用临时目录，构建结束后自动删除",
    )
    parser.add_argument(
        "--keep-workdir",
        action="store_true",
        help="使用临时目录时保留工作目录，便于检查失败现场",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"单次 HTTP 请求超时时间（秒，默认：{DEFAULT_TIMEOUT}；不限制构建过程）",
    )
    return parser.parse_args()


def normalized_server_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"{SERVER_ENV} 必须是带 http:// 或 https:// 的 URL")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{SERVER_ENV} 不得包含 query 或 fragment")
    return value.rstrip("/")


def required_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"缺少环境变量: {name}")
    return value


def route_url(server: str, route: str) -> str:
    return f"{server}{route}"


def download_source(server: str, token: str, destination: Path, timeout: float) -> str:
    request = Request(
        route_url(server, SOURCE_ROUTE),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/zip"},
        method="GET",
    )
    with urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            detail = response.read(4096).decode("utf-8", errors="replace")
            raise RuntimeError(f"源码下载失败，HTTP {response.status}: {detail}")
        session_token = response.headers.get(SESSION_HEADER)
        if not session_token:
            raise RuntimeError(f"源码下载响应缺少 {SESSION_HEADER} header")
        with destination.open("wb") as file:
            shutil.copyfileobj(response, file, length=1024 * 1024)
    if destination.stat().st_size == 0:
        raise RuntimeError("服务端返回了空源码包")
    return session_token


def is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def safe_member_path(root: Path, name: str) -> Path:
    if not name or "\x00" in name:
        raise ValueError("ZIP 包包含非法文件名")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"ZIP 包包含路径穿越条目: {name!r}")
    destination = (root / Path(*path.parts)).resolve(strict=False)
    try:
        destination.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"ZIP 包条目超出工作目录: {name!r}") from exc
    return destination


def extract_source(archive: Path, root: Path) -> None:
    root_resolved = root.resolve()
    with zipfile.ZipFile(archive) as source_zip:
        members = source_zip.infolist()
        for info in members:
            if is_symlink(info):
                raise ValueError(f"ZIP 包不允许包含符号链接: {info.filename!r}")
            destination = safe_member_path(root_resolved, info.filename)
            if info.is_dir() or info.filename.endswith("/"):
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with source_zip.open(info, "r") as source_file, destination.open("wb") as target_file:
                shutil.copyfileobj(source_file, target_file, length=1024 * 1024)
            mode = (info.external_attr >> 16) & 0o777
            if mode:
                destination.chmod(mode)


class WebSocketLogClient:
    """使用标准库发送带掩码的 WebSocket 文本帧。"""

    def __init__(self, server: str, token: str, timeout: float) -> None:
        self._url = urlsplit(route_url(server, LOG_ROUTE))
        self._token = token
        self._timeout = timeout
        self._socket = None
        self._send_lock = Lock()
        self._stop_event = Event()
        self._reader_thread: Thread | None = None
        self._heartbeat_thread: Thread | None = None
        self._disconnect_error: BaseException | None = None

    def connect(self) -> None:
        if self._url.hostname is None:
            raise ValueError("日志 WebSocket URL 缺少主机名")
        port = self._url.port or (443 if self._url.scheme == "https" else 80)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        target = self._url.path or LOG_ROUTE
        if self._url.query:
            target += f"?{self._url.query}"
        host = self._url.hostname
        host_header = host if self._url.port is None else f"{host}:{port}"
        connection = socket.create_connection((host, port), timeout=self._timeout)
        try:
            if self._url.scheme == "https":
                connection = ssl.create_default_context().wrap_socket(connection, server_hostname=host)
            request = (
                f"GET {target} HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                f"Authorization: Bearer {self._token}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "\r\n"
            ).encode("ascii")
            connection.sendall(request)
            response_lines: list[bytes] = []
            while True:
                line = bytearray()
                while not line.endswith(b"\r\n"):
                    byte = connection.recv(1)
                    if not byte:
                        raise ConnectionError("日志 WebSocket 握手连接被服务器关闭")
                    line.extend(byte)
                if line == b"\r\n":
                    break
                response_lines.append(bytes(line[:-2]))
            if not response_lines:
                raise RuntimeError("日志 WebSocket 握手响应为空")
            try:
                _, status, _ = response_lines[0].decode("ascii").split(" ", 2)
                headers = {
                    name.strip().lower(): value.strip()
                    for line in response_lines[1:]
                    for name, value in [line.decode("iso-8859-1").split(":", 1)]
                }
            except (UnicodeDecodeError, ValueError) as exc:
                raise RuntimeError("日志 WebSocket 握手响应无效") from exc
            expected_accept = base64.b64encode(
                hashlib.sha1((key + WEBSOCKET_GUID).encode("ascii")).digest()
            ).decode("ascii")
            if (
                status != "101"
                or headers.get("upgrade", "").lower() != "websocket"
                or headers.get("sec-websocket-accept") != expected_accept
            ):
                raise RuntimeError(f"日志 WebSocket 连接失败，HTTP {status}")
            connection.settimeout(None)
            self._socket = connection
            self._reader_thread = Thread(target=self._read_server_frames, name="macos-log-websocket-reader", daemon=True)
            self._heartbeat_thread = Thread(target=self._send_heartbeats, name="macos-log-websocket-heartbeat", daemon=True)
            self._reader_thread.start()
            self._heartbeat_thread.start()
        except Exception:
            connection.close()
            raise

    def send_log(self, stream: str, line: str) -> None:
        payload = json.dumps(
            {"stream": stream, "line": line}, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        with self._send_lock:
            if self._socket is None:
                if self._disconnect_error is not None:
                    raise ConnectionError(f"日志 WebSocket 已断开: {self._disconnect_error}")
                raise ConnectionError("日志 WebSocket 未连接")
            self._send_frame(0x01, payload)

    def _read_websocket_bytes(self, size: int) -> bytes:
        if self._socket is None:
            raise ConnectionError("日志 WebSocket 未连接")
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = self._socket.recv(remaining)
            if not chunk:
                raise ConnectionError("日志 WebSocket 被服务器关闭")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _read_server_frame(self) -> tuple[bool, int, bytes]:
        header = self._read_websocket_bytes(2)
        final = bool(header[0] & 0x80)
        opcode = header[0] & 0x0F
        if header[0] & 0x70 or header[1] & 0x80:
            raise ValueError("服务端 WebSocket 帧无效")
        length = header[1] & 0x7F
        if length == 126:
            length = int.from_bytes(self._read_websocket_bytes(2), "big")
        elif length == 127:
            length_bytes = self._read_websocket_bytes(8)
            if length_bytes[0] & 0x80:
                raise ValueError("服务端 WebSocket payload 长度无效")
            length = int.from_bytes(length_bytes, "big")
        if opcode >= 0x08 and (not final or length > 125):
            raise ValueError("服务端 WebSocket 控制帧无效")
        return final, opcode, self._read_websocket_bytes(length)

    def _read_server_frames(self) -> None:
        """Drain server frames, replying to pings so both directions remain usable."""

        try:
            while not self._stop_event.is_set():
                final, opcode, payload = self._read_server_frame()
                if opcode == 0x08:
                    if not self._stop_event.is_set():
                        with self._send_lock:
                            self._send_frame(0x08, payload)
                    raise ConnectionError("日志 WebSocket 收到服务器关闭帧")
                if opcode == 0x09:
                    with self._send_lock:
                        self._send_frame(0x0A, payload)
                elif opcode not in (0x0A, 0x01, 0x02, 0x00) or not final:
                    raise ValueError("服务端 WebSocket 帧类型无效")
        except (OSError, ValueError, ConnectionError) as exc:
            if not self._stop_event.is_set():
                self._disconnect_error = exc
                self._stop_event.set()

    def _send_heartbeats(self) -> None:
        """Application-level traffic prevents idle HTTP/NAT/SSH tunnel expiry."""

        while not self._stop_event.wait(WEBSOCKET_HEARTBEAT_INTERVAL):
            try:
                with self._send_lock:
                    self._send_frame(0x09, b"log-keepalive")
            except (OSError, ConnectionError) as exc:
                self._disconnect_error = exc
                self._stop_event.set()
                return

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        if self._socket is None:
            raise ConnectionError("日志 WebSocket 未连接")
        length = len(payload)
        header = bytearray((0x80 | opcode,))
        if length < 126:
            header.append(0x80 | length)
        elif length < 2**16:
            header.extend((0x80 | 126,))
            header.extend(length.to_bytes(2, "big"))
        else:
            header.extend((0x80 | 127,))
            header.extend(length.to_bytes(8, "big"))
        mask = os.urandom(4)
        masked_payload = bytearray(payload)
        for index, value in enumerate(masked_payload):
            masked_payload[index] = value ^ mask[index % len(mask)]
        self._socket.sendall(header + mask + masked_payload)

    def close(self) -> None:
        self._stop_event.set()
        with self._send_lock:
            if self._socket is not None:
                try:
                    self._send_frame(0x08, (1000).to_bytes(2, "big"))
                except OSError:
                    pass
                try:
                    self._socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self._socket.close()
            self._socket = None
        for thread in (self._reader_thread, self._heartbeat_thread):
            if thread is not None and thread is not current_thread():
                thread.join(timeout=1)


def report_status(log_client: WebSocketLogClient, message: str) -> bool:
    """Send client status to the server without echoing it locally."""

    try:
        log_client.send_log("stdout", message)
        return True
    except Exception:
        # Before this point the client deliberately has no local output. If the
        # status channel itself fails, retain a minimal diagnostic so a stalled
        # remote build is not completely silent on the client machine.
        print("⚠️ 无法将客户端状态上传到 server。", file=sys.stderr, flush=True)
        return False


def report_client_failure(
    log_client: WebSocketLogClient,
    phase: str,
    exc: BaseException,
    secrets_to_redact: tuple[str, ...],
) -> bool:
    """Report a useful, token-safe client exception through the build log."""

    detail = str(exc) or "无异常说明"
    for secret in secrets_to_redact:
        if secret:
            detail = detail.replace(secret, "***")
    detail = detail.replace("\x00", "\\0")[:4096]
    return report_status(
        log_client,
        f"❌ macOS 客户端异常（阶段: {phase}）: {type(exc).__name__}: {detail}",
    )


def forward_output(pipe, stream: str, log_client: WebSocketLogClient, errors: list[str]) -> None:
    """Forward one child stream without echoing it on the client."""

    try:
        for raw_line in iter(pipe.readline, b""):
            line = raw_line.decode("utf-8", errors="replace")
            try:
                log_client.send_log(stream, line)
            except Exception as exc:  # Keep draining the child process on network errors.
                errors.append(f"{stream}: {exc}")
        pipe.close()
    except Exception as exc:
        errors.append(f"读取 {stream} 失败: {exc}")


def create_dist_archive(dist: Path, destination: Path) -> None:
    if not dist.is_dir():
        raise RuntimeError(f"构建成功但 dist 目录不存在: {dist}")
    entries = list(dist.iterdir())
    if not entries:
        raise RuntimeError(f"构建成功但 dist 目录为空: {dist}")
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=3) as archive:
        for path in sorted(dist.rglob("*")):
            if path.is_symlink():
                raise RuntimeError(f"dist 包含不支持上传的符号链接: {path}")
            if path.is_dir():
                continue
            archive.write(path, Path("dist") / path.relative_to(dist))


def upload_dist(server: str, token: str, archive: Path, timeout: float) -> None:
    parsed = urlsplit(route_url(server, DIST_ROUTE))
    connection_type = HTTPSConnection if parsed.scheme == "https" else HTTPConnection
    connection = connection_type(parsed.hostname, parsed.port, timeout=timeout)
    archive_size = archive.stat().st_size
    sent_size = 0
    try:
        connection.putrequest("POST", parsed.path or DIST_ROUTE)
        connection.putheader("Authorization", f"Bearer {token}")
        connection.putheader("Content-Type", "application/zip")
        connection.putheader("Content-Length", str(archive_size))
        connection.endheaders()
        with archive.open("rb") as file:
            while chunk := file.read(UPLOAD_CHUNK_SIZE):
                connection.send(chunk)
                sent_size += len(chunk)
        response = connection.getresponse()
        detail = response.read(4096).decode("utf-8", errors="replace")
        if response.status != 200:
            raise RuntimeError(f"dist 上传失败，HTTP {response.status}: {detail}")
    except (HTTPException, OSError) as exc:
        raise RuntimeError(
            "dist 上传网络错误"
            f"（已发送 {sent_size}/{archive_size} bytes，上传块 {UPLOAD_CHUNK_SIZE} bytes）: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    finally:
        connection.close()


def run_build(work_dir: Path, log_client: WebSocketLogClient) -> tuple[int, list[str]]:
    pack_script = work_dir / "pack_macos.sh"
    config = work_dir / "pack-input.json"
    if not pack_script.is_file() or not config.is_file():
        raise RuntimeError("源码包根目录缺少 pack_macos.sh 或 pack-input.json")

    process = subprocess.Popen(
        ["bash", str(pack_script), "--config", str(config)],
        cwd=work_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    upload_errors: list[str] = []
    threads = [
        Thread(
            target=forward_output,
            args=(process.stdout, "stdout", log_client, upload_errors),
            name="macos-build-stdout",
        ),
        Thread(
            target=forward_output,
            args=(process.stderr, "stderr", log_client, upload_errors),
            name="macos-build-stderr",
        ),
    ]
    for thread in threads:
        thread.start()
    return_code = process.wait()
    for thread in threads:
        thread.join()
    return return_code, upload_errors


def main() -> int:
    args = parse_args()
    server = normalized_server_url(required_environment(SERVER_ENV))
    token = required_environment(TOKEN_ENV)
    if args.timeout <= 0:
        raise ValueError("--timeout 必须大于 0")
    if args.work_dir is not None and args.keep_workdir:
        raise ValueError("--keep-workdir 只能与默认临时工作目录一起使用")

    temporary_directory: Path | None = None
    if args.work_dir is None:
        temporary_directory = Path(tempfile.mkdtemp(prefix="autopack-macos-"))
        work_dir = temporary_directory / "project"
    else:
        work_dir = args.work_dir.expanduser().resolve(strict=False)
    work_dir.mkdir(parents=True, exist_ok=True)

    archive_root: Path | None = None
    log_client: WebSocketLogClient | None = None
    session_token: str | None = None
    phase = "下载源码"
    build_completed = False
    try:
        # Keep the downloaded archive outside the extraction root. This also
        # prevents a ZIP member from replacing the archive while it is open.
        archive_root = work_dir.parent / f".autopack-{time.time_ns()}"
        archive_root.mkdir(parents=True, exist_ok=False)
        source_archive = archive_root / "src.zip"
        session_token = download_source(server, token, source_archive, args.timeout)
        log_client = WebSocketLogClient(server, session_token, args.timeout)
        phase = "连接日志通道"
        log_client.connect()
        report_status(log_client, "==> macOS 客户端已下载源码，开始准备构建。")
        phase = "解压源码"
        extract_source(source_archive, work_dir)
        shutil.rmtree(archive_root)

        report_status(log_client, "==> macOS 客户端开始执行 pack_macos.sh。")
        phase = "执行 macOS 打包"
        return_code, upload_errors = run_build(work_dir, log_client)
        if upload_errors:
            for error in sorted(set(upload_errors)):
                report_status(log_client, f"⚠️ 日志上传异常: {error}")
        if return_code != 0:
            report_status(log_client, f"❌ macOS 打包失败，退出码: {return_code}")
            return return_code
        if upload_errors:
            raise RuntimeError("构建完成，但部分日志未能上传")

        build_completed = True
        dist_archive = work_dir / "dist-upload.zip"
        phase = "创建 dist 上传压缩包"
        create_dist_archive(work_dir / "dist", dist_archive)
        report_status(log_client, "==> macOS 打包完成，开始上传 dist 产物。")
        phase = "上传 dist 产物"
        upload_dist(server, session_token, dist_archive, args.timeout)
        report_status(log_client, "==> macOS 构建和产物上传完成。")
        return 0
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        if log_client is not None:
            failure_phase = f"打包完成后：{phase}" if build_completed else phase
            report_client_failure(log_client, failure_phase, exc, (server, token, session_token or ""))
        raise
    finally:
        if archive_root is not None:
            shutil.rmtree(archive_root, ignore_errors=True)
        if temporary_directory is not None:
            if args.keep_workdir:
                if log_client is not None:
                    report_status(log_client, f"==> 已保留工作目录: {temporary_directory}")
                else:
                    print(f"⚠️ 已保留工作目录: {temporary_directory}", file=sys.stderr, flush=True)
            else:
                shutil.rmtree(temporary_directory, ignore_errors=True)
        if log_client is not None:
            log_client.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        # Error messages are deliberately sanitized: never echo the server URL
        # or either bearer token to the local terminal.
        if isinstance(exc, ValueError) and str(exc).startswith("缺少环境变量:"):
            print(f"❌ 错误: {exc}", file=sys.stderr)
        else:
            print(f"❌ 错误: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(1) from exc
