"""Small, dependency-free validation and wire types."""
import hashlib
import json
import math
import re
from datetime import datetime, timezone


class APIError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message

    def payload(self):
        return {"error": self.code, "message": self.message}


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def integer(value, name, low, high):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise APIError(400, "invalid_integer", name)
    if isinstance(value, str) and not re.fullmatch(r"[0-9]+", value):
        raise APIError(400, "invalid_integer", name)
    try:
        value = int(value)
    except ValueError:
        raise APIError(400, "invalid_integer", name)
    if not low <= value <= high:
        raise APIError(400, "out_of_range", "%s must be %d..%d" % (name, low, high))
    return value


def boolean(value, name):
    if type(value) is not bool:
        raise APIError(400, "invalid_boolean", name + " must be a JSON boolean")
    return value


def text(value, name, maximum=4096, empty=False, controls=False):
    if not isinstance(value, str) or (not value and not empty):
        raise APIError(400, "invalid_string", name)
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise APIError(400, "invalid_unicode", name)
    if len(encoded) > maximum:
        raise APIError(413, "string_too_large", name)
    if not controls and any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise APIError(400, "control_characters", name)
    return value


def identifier(value):
    value = text(value, "identifier", 256)
    if value.lower() in ("all", "active") or not re.fullmatch(r"[A-Za-z0-9_.:~-]+", value):
        raise APIError(400, "invalid_identifier", "Use a concrete session ID, not a proxy")
    return value


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("non-finite number")

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("non-finite number")
        return number

    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite_float)
    except (ValueError, UnicodeError, RecursionError):
        raise APIError(400, "invalid_json", "Expected strict UTF-8 JSON")
    if not isinstance(value, dict):
        raise APIError(400, "invalid_json", "Body must be a JSON object")
    return value


def digest(value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode()).hexdigest()
