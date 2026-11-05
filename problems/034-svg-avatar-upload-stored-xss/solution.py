"""Serve user-uploaded avatars so an uploaded file can never run script on the app origin.

The original upload handler accepted any file whose client-declared type
started with ``image/`` and served it back from the main site with a
Content-Type guessed from the uploaded file name. An ``.svg`` with a
``<script>`` (or an ``.html`` file labelled ``image/png``) was rendered as a
document on the app origin when opened, so its script ran with the viewer's
session: stored XSS through the upload feature.

The fix decides the type from the file's own magic bytes and accepts only
raster formats (PNG, JPEG, GIF, WebP), stores the file under a random name,
and serves it from a separate cookieless origin with ``nosniff``,
``Content-Disposition: attachment`` and a sandboxing CSP.
"""
from __future__ import annotations

import mimetypes
import secrets
from dataclasses import dataclass, field

APP_ORIGIN = "https://shop.example.test"
USER_CONTENT_ORIGIN = "https://usercontent.example-cdn.test"   # separate site, no cookies
MAX_AVATAR_BYTES = 1024 * 1024
AVATAR_ID_BYTES = 16

# Magic-byte prefix -> (content type, file extension). Raster formats only:
# none of them can carry script that a browser would run.
RASTER_SIGNATURES: dict[bytes, tuple[str, str]] = {
    b"\x89PNG\r\n\x1a\n": ("image/png", "png"),
    b"\xff\xd8\xff": ("image/jpeg", "jpg"),
    b"GIF87a": ("image/gif", "gif"),
    b"GIF89a": ("image/gif", "gif"),
}
WEBP_RIFF_MAGIC = b"RIFF"
WEBP_FORMAT_MAGIC = b"WEBP"

# Content types a browser renders as a document that can run script.
SCRIPTABLE_TYPES = {"text/html", "image/svg+xml", "application/xhtml+xml", "text/xml",
                    "application/xml"}
# Types for which a browser without "nosniff" may sniff the body as HTML.
SNIFFABLE_TYPES = {"", "text/plain", "application/octet-stream"}
SCRIPT_MARKERS = ("<script", "onload=", "onerror=", "javascript:")

SANDBOX_CSP = "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; sandbox"


class UploadRejected(ValueError):
    """Maps to HTTP 400: the file is not an accepted image."""


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    origin: str


# --- browser model ------------------------------------------------------
def looks_like_html(body: bytes) -> bool:
    """Rough MIME sniffing: does the body start with markup?"""
    return body.lstrip()[:1] == b"<"


def browser_runs_script(response: HttpResponse) -> bool:
    """Would a browser that opens this URL directly run script from the body?

    A simplified model of the browser rules that matter here: downloads are
    not rendered, a CSP ``sandbox`` blocks script, scriptable types render as
    documents, and without ``nosniff`` vague types may be sniffed as HTML.
    """
    if response.headers.get("Content-Disposition", "").startswith("attachment"):
        return False
    if "sandbox" in response.headers.get("Content-Security-Policy", ""):
        return False
    content_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
    renders_as_document = content_type in SCRIPTABLE_TYPES
    nosniff = response.headers.get("X-Content-Type-Options", "").lower() == "nosniff"
    if not nosniff and content_type in SNIFFABLE_TYPES and looks_like_html(response.body):
        renders_as_document = True
    if not renders_as_document:
        return False
    text = response.body.decode("utf-8", "replace").lower()
    return any(marker in text for marker in SCRIPT_MARKERS)


def script_runs_with_app_session(response: HttpResponse) -> bool:
    """The actual harm: script running on the origin that holds the session cookie."""
    return response.origin == APP_ORIGIN and browser_runs_script(response)


# --- original version ---------------------------------------------------
@dataclass
class NaiveAvatarStore:
    """The bug: trusts the client's type and file name, serves inline from the app origin."""

    files: dict[str, tuple[str, bytes]] = field(default_factory=dict)   # name -> (type, data)

    def upload(self, filename: str, declared_type: str, data: bytes) -> str:
        """Accept anything the client calls an image; keep the client's file name."""
        if not declared_type.startswith("image/"):
            raise UploadRejected("only images are allowed")
        guessed_type, _encoding = mimetypes.guess_type(filename)
        self.files[filename] = (guessed_type or declared_type, data)
        return f"{APP_ORIGIN}/media/avatars/{filename}"

    def serve(self, filename: str) -> HttpResponse:
        """Serve with the type guessed from the extension, no other headers."""
        content_type, data = self.files[filename]
        return HttpResponse(200, {"Content-Type": content_type}, data, APP_ORIGIN)


# --- fixed version ------------------------------------------------------
def detect_raster_type(data: bytes) -> tuple[str, str]:
    """Return (content type, extension) from magic bytes, or raise UploadRejected.

    The client's Content-Type and file name are ignored: both are attacker input.
    """
    for magic, detected in RASTER_SIGNATURES.items():
        if data.startswith(magic):
            return detected
    if data[:4] == WEBP_RIFF_MAGIC and data[8:12] == WEBP_FORMAT_MAGIC:
        return "image/webp", "webp"
    raise UploadRejected("avatar must be a PNG, JPEG, GIF or WebP image")


def validate_avatar(data: bytes) -> tuple[str, str]:
    """Size check, then type detection."""
    if not data:
        raise UploadRejected("empty file")
    if len(data) > MAX_AVATAR_BYTES:
        raise UploadRejected(f"avatar must be at most {MAX_AVATAR_BYTES} bytes")
    return detect_raster_type(data)


def safe_headers(content_type: str) -> dict[str, str]:
    """Headers that keep a stored file from ever becoming an active document."""
    return {
        "Content-Type": content_type,
        "X-Content-Type-Options": "nosniff",
        # <img> ignores Content-Disposition, so avatars still display; opening
        # the URL directly downloads the file instead of rendering it.
        "Content-Disposition": "attachment",
        "Content-Security-Policy": SANDBOX_CSP,
        "Cross-Origin-Resource-Policy": "cross-origin",
    }


@dataclass
class AvatarStore:
    """Validated uploads, random names, served from the user-content origin only."""

    files: dict[str, tuple[str, bytes]] = field(default_factory=dict)   # id.ext -> (type, data)

    def upload(self, filename: str, declared_type: str, data: bytes) -> str:
        """Store a validated avatar and return its public URL.

        ``filename`` and ``declared_type`` are accepted for API compatibility
        but never used: they cannot be trusted.
        """
        content_type, extension = validate_avatar(data)
        stored_name = f"{secrets.token_hex(AVATAR_ID_BYTES)}.{extension}"
        self.files[stored_name] = (content_type, data)
        return f"{USER_CONTENT_ORIGIN}/avatars/{stored_name}"

    def serve(self, stored_name: str) -> HttpResponse:
        """Serve a stored avatar (404 for unknown names) with the safe headers."""
        if stored_name not in self.files:
            return HttpResponse(404, {"Content-Type": "text/plain"}, b"not found", USER_CONTENT_ORIGIN)
        content_type, data = self.files[stored_name]
        return HttpResponse(200, safe_headers(content_type), data, USER_CONTENT_ORIGIN)
