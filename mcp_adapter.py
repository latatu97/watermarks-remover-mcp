"""Authenticated MCP wrapper for the user's own watermarks-remover engine."""
from __future__ import annotations
import json
import os
import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from proxy_core import ServiceError, authenticate, require_settings, request_upstream
from proxy_core import inspect_file as inspect_upstream, clean_file as clean_upstream

# Fail closed when secrets or service host have not been configured.
require_settings()
host = os.environ.get("MCP_PUBLIC_HOST", "").strip().lower()
if not host or any(c in host for c in "/:@"):
    raise RuntimeError("MCP_PUBLIC_HOST must be a hostname")

mcp = MCPServer("watermarks-remover-private",
                instructions="Inspect before cleaning. Never transfer sensitive files without explicit consent.",
                version="0.1.0")

@mcp.tool()
def check_engine() -> dict:
    """Check the upstream watermarks-remover engine availability."""
    return request_upstream("/health")

@mcp.tool()
def engine_capabilities() -> dict:
    """Report optional detector, file processing and image capabilities."""
    return request_upstream("/capabilities")

@mcp.tool()
def inspect_document(filename: str, file_b64: str, consent_to_send_file: bool) -> dict:
    """Inspect an owned file. file_b64 is its base64 encoding. Set consent only with user approval for remote transfer."""
    if not consent_to_send_file:
        raise ServiceError("Consent to transfer file is required")
    return inspect_upstream(filename, file_b64)

@mcp.tool()
def clean_document(filename: str, file_b64: str, consent_to_send_file: bool,
                   strip_all_metadata: bool = False) -> dict:
    """Clean a previously inspected file. Returns a base64 copy, not an overwrite; requires explicit remote transfer consent."""
    if not consent_to_send_file:
        raise ServiceError("Consent to transfer file is required")
    return clean_upstream(filename, file_b64, strip_all_metadata)

inner = mcp.streamable_http_app(
    host="0.0.0.0",
    json_response=True,
    stateless_http=True,
    max_request_body_size=1024 * 1024,
    transport_security=TransportSecuritySettings(
        allowed_hosts=[host, host+":*", "localhost:*", "127.0.0.1:*"],
        allowed_origins=[]
    )
)

class AuthenticatedApp:
    def __init__(self, wrapped):
        self.wrapped = wrapped

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.wrapped(scope, receive, send)
            return
        if scope.get("path") == "/health" and scope["method"] == "GET":
            data = b'{"ok":true,"service":"private-mcp-bridge"}'
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"application/json"),
                                    (b"content-length", str(len(data)).encode())]})
            await send({"type": "http.response.body", "body": data})
            return
        if not authenticate(scope.get("headers", [])):
            data = b'{"error":"Unauthorized"}'
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", b"application/json"),
                                    (b"www-authenticate", b"Bearer"),
                                    (b"content-length", str(len(data)).encode())]})
            await send({"type": "http.response.body", "body": data})
            return
        await self.wrapped(scope, receive, send)

app = AuthenticatedApp(inner)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "10000")),
                access_log=False, log_level="warning")
