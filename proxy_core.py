"""HTTP client and payload checks for a private watermarks-remover MCP bridge."""
from __future__ import annotations
import base64
import binascii
import hashlib
import hmac
import json
import os
import urllib.error
import urllib.parse
import urllib.request

MAX_FILE_BYTES = 512 * 1024
ALLOWED_EXTENSIONS = {
    ".txt", ".md", ".html", ".png", ".jpg", ".jpeg", ".webp", ".pdf",
    ".docx", ".xlsx", ".pptx", ".odt", ".epub", ".svg", ".gif",
    ".heic", ".avif", ".bmp", ".tif", ".tiff", ".mp3", ".wav",
    ".flac", ".mp4", ".mov", ".m4v", ".m4a",
}

class ServiceError(RuntimeError):
    pass

def require_settings():
    url = os.environ.get("WATERMARKS_SERVICE_URL", "").rstrip("/")
    upstream_key = os.environ.get("WATERMARKS_SERVER_API_KEY", "")
    mcp_key = os.environ.get("MCP_BEARER_TOKEN", "")
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or not parsed.netloc or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")):
        raise RuntimeError("WATERMARKS_SERVICE_URL must be an HTTPS origin")
    if not upstream_key or not mcp_key:
        raise RuntimeError("WATERMARKS_SERVER_API_KEY and MCP_BEARER_TOKEN are required")
    return url, upstream_key, mcp_key

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ServiceError("Upstream redirect is forbidden")

def request_upstream(route, payload=None):
    if route not in ("/health", "/capabilities", "/inspect", "/clean"):
        raise ServiceError("Unsupported upstream endpoint")
    url, key, _ = require_settings()
    headers = {"Authorization": "Bearer " + key, "Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    data = json.dumps(payload, ensure_ascii=False).encode() if payload is not None else None
    req = urllib.request.Request(url + route, data=data, headers=headers,
                                 method="POST" if data is not None else "GET")
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=45) as response:
            body = response.read(3 * 1024 * 1024 + 1)
            if len(body) > 3 * 1024 * 1024:
                raise ServiceError("Upstream response too large")
            result = json.loads(body)
    except urllib.error.HTTPError as err:
        raise ServiceError(f"Upstream HTTP {err.code}") from err
    except (urllib.error.URLError, TimeoutError) as err:
        raise ServiceError("Upstream connection unavailable") from err
    if not isinstance(result, dict):
        raise ServiceError("Unexpected upstream response")
    return result

def check_file(name, file_b64):
    if not isinstance(name, str) or len(name) > 100 or not name:
        raise ServiceError("Filename is required (100 characters maximum)")
    if any(c in name for c in ("/", "\\", "\x00")) or name.startswith("."):
        raise ServiceError("Only a filename, without a path, is accepted")
    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise ServiceError("Unsupported file extension")
    try:
        content = base64.b64decode(file_b64, validate=True)
    except (ValueError, binascii.Error, TypeError) as err:
        raise ServiceError("Invalid base64 file content") from err
    if not content or len(content) > MAX_FILE_BYTES:
        raise ServiceError("File must contain between 1 and 524288 bytes")
    return content

def inspect_file(name, file_b64):
    content = check_file(name, file_b64)
    out = request_upstream("/inspect", {"name": name, "file": file_b64})
    return {
        "ok": out.get("ok", False), "name": name, "kind": out.get("kind"),
        "suspicious": out.get("suspicious"), "report": out.get("report"),
        "input_sha256": hashlib.sha256(content).hexdigest(),
    }

def clean_file(name, file_b64, strip_all_metadata=False):
    content = check_file(name, file_b64)
    out = request_upstream("/clean", {
        "name": name, "file": file_b64,
        "options": {"strip_all_metadata": strip_all_metadata},
    })
    encoded = out.get("cleaned")
    if out.get("ok") is not True or not isinstance(encoded, str):
        raise ServiceError("Upstream server did not return a cleaned file")
    try:
        cleaned = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as err:
        raise ServiceError("Invalid cleaned content") from err
    if len(cleaned) > MAX_FILE_BYTES:
        raise ServiceError("Cleaned output exceeds 512 KiB")
    return {
        "ok": True, "name": name, "kind": out.get("kind"),
        "report": out.get("report"), "cleaned_b64": encoded,
        "input_sha256": hashlib.sha256(content).hexdigest(),
        "output_sha256": hashlib.sha256(cleaned).hexdigest(),
    }

def authenticate(headers):
    _, _, expected = require_settings()
    values = [v for k, v in headers if k.lower() == b"authorization"]
    if len(values) != 1:
        return False
    try:
        authorization = values[0].decode("ascii")
    except UnicodeDecodeError:
        return False
    return (authorization.startswith("Bearer ") and
            hmac.compare_digest(authorization[7:], expected))
