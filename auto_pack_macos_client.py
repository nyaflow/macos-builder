#!/usr/bin/env python3
from __future__ import annotations

import argparse
from http.client import HTTPConnection, HTTPSConnection
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from threading import Thread
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import zipfile


DEFAULT_TIMEOUT = 30.0
SERVER_ENV = "BUILD_SERVER"
TOKEN_ENV = "BUILD_TOKEN"
SOURCE_ROUTE = "/source"
LOG_ROUTE = "/logs"
DIST_ROUTE = "/dist"
SESSION_HEADER = "X-Build-Session"


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


def post_log(server: str, token: str, stream: str, line: str, timeout: float) -> None:
    body = json.dumps(
        {"stream": stream, "line": line}, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    request = Request(
        route_url(server, LOG_ROUTE),
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json; charset=utf-8",
            "Content-Length": str(len(body)),
        },
        method="POST",
    )
    with urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            detail = response.read(4096).decode("utf-8", errors="replace")
            raise RuntimeError(f"日志上传失败，HTTP {response.status}: {detail}")


def report_status(server: str, token: str, message: str, timeout: float) -> None:
    """Send client status to the server without echoing it locally."""

    try:
        post_log(server, token, "stdout", message, timeout)
    except Exception as exc:
        # Before this point the client deliberately has no local output. If the
        # status channel itself fails, retain a minimal diagnostic so a stalled
        # remote build is not completely silent on the client machine.
        print("⚠️ 无法将客户端状态上传到 server。", file=sys.stderr, flush=True)


def forward_output(
    pipe, stream: str, server: str, token: str, timeout: float, errors: list[str]
) -> None:
    """Forward one child stream without echoing it on the client."""

    try:
        for raw_line in iter(pipe.readline, b""):
            line = raw_line.decode("utf-8", errors="replace")
            try:
                post_log(server, token, stream, line, timeout)
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
    try:
        connection.putrequest("POST", parsed.path or DIST_ROUTE)
        connection.putheader("Authorization", f"Bearer {token}")
        connection.putheader("Content-Type", "application/zip")
        connection.putheader("Content-Length", str(archive.stat().st_size))
        connection.endheaders()
        with archive.open("rb") as file:
            while chunk := file.read(1024 * 1024):
                connection.send(chunk)
        response = connection.getresponse()
        detail = response.read(4096).decode("utf-8", errors="replace")
        if response.status != 200:
            raise RuntimeError(f"dist 上传失败，HTTP {response.status}: {detail}")
    finally:
        connection.close()


def run_build(work_dir: Path, server: str, token: str, timeout: float) -> tuple[int, list[str]]:
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
            args=(process.stdout, "stdout", server, token, timeout, upload_errors),
            name="macos-build-stdout",
        ),
        Thread(
            target=forward_output,
            args=(process.stderr, "stderr", server, token, timeout, upload_errors),
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
    try:
        # Keep the downloaded archive outside the extraction root. This also
        # prevents a ZIP member from replacing the archive while it is open.
        archive_root = work_dir.parent / f".autopack-{time.time_ns()}"
        archive_root.mkdir(parents=True, exist_ok=False)
        source_archive = archive_root / "src.zip"
        session_token = download_source(server, token, source_archive, args.timeout)
        report_status(server, session_token, "==> macOS 客户端已下载源码，开始准备构建。", args.timeout)
        extract_source(source_archive, work_dir)
        shutil.rmtree(archive_root)

        report_status(server, session_token, "==> macOS 客户端开始执行 pack_macos.sh。", args.timeout)
        return_code, upload_errors = run_build(work_dir, server, session_token, args.timeout)
        if upload_errors:
            for error in sorted(set(upload_errors)):
                report_status(server, session_token, f"⚠️ 日志上传异常: {error}", args.timeout)
        if return_code != 0:
            report_status(server, session_token, f"❌ macOS 打包失败，退出码: {return_code}", args.timeout)
            return return_code
        if upload_errors:
            raise RuntimeError("构建完成，但部分日志未能上传")

        dist_archive = work_dir / "dist-upload.zip"
        create_dist_archive(work_dir / "dist", dist_archive)
        report_status(server, session_token, "==> macOS 打包完成，开始上传 dist 产物。", args.timeout)
        upload_dist(server, session_token, dist_archive, args.timeout)
        report_status(server, session_token, "==> macOS 构建和产物上传完成。", args.timeout)
        return 0
    finally:
        if archive_root is not None:
            shutil.rmtree(archive_root, ignore_errors=True)
        if temporary_directory is not None:
            if args.keep_workdir:
                # The session token may not exist when download/extraction fails.
                if "session_token" in locals():
                    report_status(server, session_token, f"==> 已保留工作目录: {temporary_directory}", args.timeout)
                else:
                    print(f"⚠️ 已保留工作目录: {temporary_directory}", file=sys.stderr, flush=True)
            else:
                shutil.rmtree(temporary_directory, ignore_errors=True)


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
