"""A deliberately small HTTP/1.x subset, with total deadlines and strict framing."""
import asyncio
import ipaddress
import json
import re
import urllib.parse
from http import HTTPStatus

from . import __version__
from .common import APIError, strict_json

MAX_BODY = 6 * 1024 * 1024
SMALL_BODY = 64 * 1024
TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


async def _line(reader, limit, status):
    try:
        raw = await reader.readline()
    except (ValueError, asyncio.LimitOverrunError):
        raise APIError(status, "line_too_long", "HTTP line limit exceeded")
    if len(raw) > limit:
        raise APIError(status, "line_too_long", "HTTP line limit exceeded")
    if not raw.endswith(b"\r\n"):
        raise APIError(400, "invalid_framing", "Truncated request or missing CRLF")
    return raw[:-2]


async def read_head(reader):
    try:
        return await asyncio.wait_for(_read_head(reader), 5)
    except asyncio.TimeoutError:
        raise APIError(408, "header_timeout", "Total header deadline exceeded")


async def _read_head(reader):
    first = await _line(reader, 8192, 414)
    try:
        method, target, version = first.decode("ascii").split(" ")
    except (ValueError, UnicodeError):
        raise APIError(400, "invalid_request_line", "Expected method, origin-form target, and HTTP version")
    if not TOKEN.fullmatch(method) or not target.startswith("/") or target.startswith("//"):
        raise APIError(400, "invalid_request_target", "Only origin-form targets are supported")
    if any(ord(c) <= 32 or ord(c) == 127 for c in target) or "#" in target:
        raise APIError(400, "invalid_request_target", "Invalid target")
    if version not in ("HTTP/1.0", "HTTP/1.1"):
        raise APIError(505, "http_version", "Supported versions: HTTP/1.0 and HTTP/1.1")
    headers, total = {}, 0
    for _ in range(65):
        line = await _line(reader, 8192, 431)
        total += len(line) + 2
        if total > 32768:
            raise APIError(431, "header_budget", "Headers exceed 32 KiB")
        if not line:
            break
        try:
            name, value = line.decode("iso-8859-1").split(":", 1)
        except ValueError:
            raise APIError(400, "invalid_header", "Malformed header")
        if not TOKEN.fullmatch(name) or any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in value):
            raise APIError(400, "invalid_header", "Invalid header name or value")
        name = name.lower()
        if name in headers:
            raise APIError(400, "duplicate_header", "Duplicate headers are not supported")
        headers[name] = value.strip(" \t")
    else:
        raise APIError(431, "header_count", "At most 64 headers are supported")
    if version == "HTTP/1.1" and "host" not in headers:
        raise APIError(400, "host_required", "HTTP/1.1 requires Host")
    if "transfer-encoding" in headers:
        raise APIError(400, "transfer_encoding", "Chunked request bodies are not supported")
    if "expect" in headers:
        raise APIError(417, "expectation_failed", "Expect is not supported")
    raw_length = headers.get("content-length", "0")
    if not re.fullmatch(r"[0-9]{1,10}", raw_length):
        raise APIError(400, "content_length", "Invalid Content-Length")
    length = int(raw_length)
    if length > MAX_BODY:
        raise APIError(413, "body_too_large", "Request exceeds the body budget")
    try:
        split = urllib.parse.urlsplit(target)
        if re.search(r"%(?![0-9A-Fa-f]{2})", target):
            raise ValueError("bad percent escape")
        path = urllib.parse.unquote(split.path, encoding="utf-8", errors="strict")
        items = urllib.parse.parse_qsl(split.query, keep_blank_values=True, encoding="utf-8", errors="strict", max_num_fields=32)
        query = dict(items)
        if len(query) != len(items) or any(ord(c) < 32 for c in path):
            raise ValueError("duplicate query or control character")
    except (ValueError, UnicodeError):
        raise APIError(400, "invalid_query", "Invalid or duplicate query parameters")
    if "token" in query or "access_token" in query:
        raise APIError(400, "token_in_url", "Credentials must not be placed in URLs")
    return method, path, query, headers, length


def check_origin(headers, config):
    if "origin" in headers:
        raise APIError(403, "browser_origin_denied", "Browser-origin requests are not supported")
    host = headers.get("host", "")
    if not host:
        return
    try:
        parsed = urllib.parse.urlsplit("http://" + host)
        name = parsed.hostname
        if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            raise ValueError("invalid host")
        parsed.port  # Validate malformed/out-of-range ports too.
        if name == "localhost":
            return
        address = ipaddress.ip_address(name)
        if address.is_loopback or (config["allow_remote"] and
                                   (config["host"] in ("0.0.0.0", "::") or name == config["host"])):
            return
    except (ValueError, TypeError):
        pass
    raise APIError(403, "host_denied", "Use the configured literal host or a loopback tunnel")


async def read_body(reader, headers, length, limit=SMALL_BODY):
    if length > limit:
        raise APIError(413, "body_too_large", "Endpoint body budget exceeded")
    if length == 0:
        return {}
    if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise APIError(415, "json_required", "Use application/json; multipart is not supported")
    try:
        body = await asyncio.wait_for(reader.readexactly(length), 15)
    except asyncio.TimeoutError:
        raise APIError(408, "body_timeout", "Request body deadline exceeded")
    except asyncio.IncompleteReadError:
        raise APIError(400, "short_body", "Body shorter than Content-Length")
    return strict_json(body)


def response(status, data, epoch=None, decorate=True):
    data = dict(data)
    if decorate:
        data["_version"] = __version__
        if epoch:
            data["epoch"] = epoch
    body = json.dumps(data, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
    reason = HTTPStatus(status).phrase
    head = ("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
            "Connection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n") % (status, reason, len(body))
    return head.encode() + body


async def flush(writer, payload):
    writer.write(payload)
    await asyncio.wait_for(writer.drain(), 5)
