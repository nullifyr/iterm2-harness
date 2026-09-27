"""Bounded regular-file operations through no-follow directory descriptors.

An allow-list is an API policy, not an OS sandbox. Root and parent descriptors
are walked without symlinks, so a path swap cannot redirect an open outside it.
"""
import base64
import os
import secrets
import stat
from collections import deque
from contextlib import contextmanager
from pathlib import Path

from .common import APIError, boolean, integer, text

MAX_FILE = 4 * 1024 * 1024
MAX_ENTRIES = 2000


class Files:
    def __init__(self, policy, protected=()):
        self.enabled = policy.get("enabled", False)
        self.roots = [os.path.realpath(p) for p in policy.get("allowed_paths", [])]
        self.protected = [os.path.realpath(str(p)) for p in protected]

    def path(self, raw):
        if not self.enabled or not self.roots:
            raise APIError(403, "files_disabled", "Enable file access and explicitly configure allowed_paths")
        raw = text(raw, "path", 4096)
        if not os.path.isabs(raw) or ".." in Path(raw).parts:
            raise APIError(400, "invalid_path", "Use an absolute path without '..'")
        path = os.path.normpath(raw)
        if not any(os.path.commonpath([path, root]) == root for root in self.roots):
            raise APIError(403, "path_denied", "Outside configured roots")
        if any(os.path.commonpath([path, root]) == root for root in self.protected):
            raise APIError(403, "protected_path", "Harness state and executable code are protected")
        return path

    @contextmanager
    def directory(self, path, mkdir=False):
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            current = "/"
            for part in Path(path).parts[1:]:
                current = os.path.join(current, part)
                # The configured root itself must already exist. mkdir may only
                # create descendants, never missing ancestors outside the grant.
                can_create = any(current != root and os.path.commonpath([current, root]) == root
                                 for root in self.roots)
                if mkdir and can_create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            yield fd
        except (OSError, ValueError):
            raise APIError(403, "unsafe_or_missing_path", "Path is inaccessible, missing, or contains a symlink")
        finally:
            os.close(fd)

    def read(self, query):
        path = self.path(query.get("path", ""))
        if query.get("grep_regex", "false").lower() == "true":
            raise APIError(400, "regex_disabled", "Untrusted backtracking regex is disabled; use substring grep")
        with self.directory(os.path.dirname(path)) as parent:
            try:
                fd = os.open(os.path.basename(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            except FileNotFoundError:
                raise APIError(404, "file_missing", "File does not exist")
            except OSError:
                raise APIError(403, "file_denied", "Cannot open file")
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise APIError(403, "not_regular_file", "Devices, FIFOs, and directories are not files")
                if info.st_size > MAX_FILE:
                    raise APIError(413, "file_too_large", "File read exceeds the 4 MiB budget")
                raw = stream.read(MAX_FILE + 1)
        if len(raw) > MAX_FILE:
            raise APIError(413, "file_grew", "File grew beyond the read budget")
        if query.get("base64", "false").lower() == "true":
            return {"path": path, "size": len(raw), "encoding": "base64", "content": base64.b64encode(raw).decode()}
        try:
            value = raw.decode("utf-8")
        except UnicodeError:
            raise APIError(415, "binary_file", "Use base64=true")
        lines = value.splitlines(keepends=True)
        count = integer(query.get("lines", 2000), "lines", 0, 10000)
        offset = integer(query.get("offset", 1), "offset", 1, 10000000)
        numbered = query.get("line_numbers", "false").lower() == "true"
        pattern = text(query.get("grep", ""), "grep", 1024, empty=True)
        if pattern:
            context = integer(query.get("grep_context", 0), "grep_context", 0, 20)
            chosen = set()
            for index, line in enumerate(lines):
                if pattern.lower() in line.lower():
                    chosen.update(range(max(0, index-context), min(len(lines), index+context+1)))
                    if len(chosen) > count:
                        break
            selected = [(i, lines[i]) for i in sorted(chosen)[:count]]
            numbered = True
            more = len(chosen) > count
        else:
            start = offset - 1
            if "tail" in query:
                tail = integer(query["tail"], "tail", 0, 10000)
                start = max(0, len(lines)-tail)
                count = min(count, tail)
            selected = list(enumerate(lines[start:start+count], start))
            more = start + len(selected) < len(lines)
        content = "".join(("%6d: " % (i+1) if numbered else "") + line for i, line in selected)
        return {"path": path, "size": len(raw), "encoding": "utf-8", "content": content,
                "returned_lines": len(selected), "total_lines": len(lines), "has_more": more,
                "offset": selected[0][0]+1 if selected else offset, "source": "local_host_filesystem"}

    def write(self, query, body):
        path = self.path(query.get("path", ""))
        content = text(body.get("content"), "content", MAX_FILE * 2, empty=True, controls=True)
        encoding = body.get("encoding", "utf-8")
        if encoding == "base64":
            try:
                data = base64.b64decode(content, validate=True)
            except (ValueError, UnicodeError):
                raise APIError(400, "invalid_base64", "Invalid base64 content")
        elif encoding == "utf-8":
            data = content.encode("utf-8")
        else:
            raise APIError(400, "invalid_encoding", "Use utf-8 or base64")
        if len(data) > MAX_FILE:
            raise APIError(413, "write_too_large", "Write exceeds the 4 MiB budget")
        append = boolean(body.get("append", False), "append")
        mkdir = boolean(body.get("mkdir", False), "mkdir")
        with self.directory(os.path.dirname(path), mkdir=mkdir) as parent:
            name = os.path.basename(path)
            previous = None
            try:
                previous = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISREG(previous.st_mode) or previous.st_nlink != 1:
                    raise APIError(403, "unsafe_target", "Write target must be a regular, single-link file")
            except FileNotFoundError:
                pass
            if append:
                fd = os.open(name, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                             0o600, dir_fd=parent)
                with os.fdopen(fd, "ab") as stream:
                    current = os.fstat(stream.fileno())
                    if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
                        raise APIError(403, "unsafe_target", "Target changed")
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            else:
                tmp = ".harness-" + secrets.token_hex(16)
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                try:
                    with os.fdopen(fd, "wb") as stream:
                        if previous:
                            os.fchmod(stream.fileno(), stat.S_IMODE(previous.st_mode))
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(tmp, name, src_dir_fd=parent, dst_dir_fd=parent)
                finally:
                    try:
                        os.unlink(tmp, dir_fd=parent)
                    except FileNotFoundError:
                        pass
        return {"path": path, "size": len(data), "created": previous is None, "append": append}

    def delete(self, query):
        path = self.path(query.get("path", ""))
        with self.directory(os.path.dirname(path)) as parent:
            name = os.path.basename(path)
            try:
                st = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                raise APIError(404, "file_missing", "File does not exist")
            if not stat.S_ISREG(st.st_mode):
                raise APIError(403, "not_regular_file", "Only regular files may be deleted")
            os.unlink(name, dir_fd=parent)
        return {"path": path, "deleted": True}

    def list(self, query):
        root = self.path(query.get("path", ""))
        recursive = query.get("recursive", "false").lower() == "true"
        pending, entries = deque([root]), []
        truncated = False
        while pending and not truncated:
            current = pending.popleft()
            with self.directory(current) as fd, os.scandir(fd) as scan:
                for item in scan:
                    if len(entries) >= MAX_ENTRIES:
                        truncated = True
                        break
                    full = os.path.join(current, item.name)
                    try:
                        self.path(full)  # Protected descendants stay invisible, too.
                    except APIError:
                        continue
                    st = item.stat(follow_symlinks=False)
                    kind = "link" if stat.S_ISLNK(st.st_mode) else ("dir" if stat.S_ISDIR(st.st_mode) else "file")
                    entries.append({"name": os.path.relpath(full, root), "type": kind,
                                    "size": st.st_size, "mtime": st.st_mtime})
                    if recursive and kind == "dir":
                        pending.append(full)
        entries.sort(key=lambda entry: entry["name"])
        return {"path": root, "entries": entries, "truncated": truncated,
                "limit": MAX_ENTRIES, "recursive": recursive, "source": "local_host_filesystem"}
