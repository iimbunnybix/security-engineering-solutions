"""Stop the web server from publishing the .git folder and the .env file.

The marketing site was deployed by checking out the repository on the server
and pointing the web server's document root at the checkout. Every file in
it was public, including ``/.git/config`` (with a deploy token in the remote
URL), the whole ``.git`` history, and ``/.env`` with production API keys.
No traversal was needed: the files were inside the web root.

The fix has two layers. The deploy publishes only an allowlist of built
asset types and fails if a hidden or secret-looking file would be included.
The server, as a second line of defence, answers 404 for any path with a
hidden segment (except ``/.well-known/``), after percent-decoding.
"""
from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from urllib.parse import unquote

HTTP_OK = 200
HTTP_NOT_FOUND = 404
# The only hidden directory the web legitimately needs (ACME, security.txt).
WELL_KNOWN = ".well-known"
PUBLISHABLE_EXTENSIONS = {".html", ".css", ".js", ".png", ".jpg", ".svg", ".ico", ".woff2", ".txt"}
SECRET_LOOKING_NAMES = {"id_rsa", "credentials", "secrets.yml", "terraform.tfstate"}


def split_request_path(raw_path: str) -> list[str] | None:
    """Decode and normalise a URL path into segments; None if it is unsafe."""
    decoded = unquote(raw_path)
    if "\\" in decoded or "\x00" in decoded:
        return None
    normalised = posixpath.normpath("/" + decoded.lstrip("/"))
    segments = [segment for segment in normalised.split("/") if segment]
    if ".." in segments:
        return None
    return segments


# --- the original, buggy version ---------------------------------------------
def naive_serve(web_root: dict[str, bytes], raw_path: str) -> tuple[int, bytes]:
    """Original server: any file inside the web root is public."""
    segments = split_request_path(raw_path)
    if segments is None:
        return HTTP_NOT_FOUND, b""
    path = "/".join(segments) or "index.html"
    if path in web_root:
        return HTTP_OK, web_root[path]
    return HTTP_NOT_FOUND, b""


# --- fix, layer 1: publish only what the site needs ---------------------------------
@dataclass
class PublishPlan:
    published: dict[str, bytes] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)


def is_hidden(segments: list[str]) -> bool:
    """True if any segment starts with '.', apart from a leading .well-known."""
    for index, segment in enumerate(segments):
        if segment.startswith(".") and not (index == 0 and segment == WELL_KNOWN):
            return True
    return False


def looks_secret(segments: list[str]) -> bool:
    """Hidden files and well-known credential file names must never ship."""
    return is_hidden(segments) or segments[-1].lower() in SECRET_LOOKING_NAMES


def plan_publish(build_output: dict[str, bytes]) -> PublishPlan:
    """Choose which built files go to the web root, by extension allowlist."""
    plan = PublishPlan()
    for path in sorted(build_output):
        segments = path.split("/")
        if looks_secret(segments):
            plan.blocked.append(path)
        elif posixpath.splitext(path)[1].lower() in PUBLISHABLE_EXTENSIONS:
            plan.published[path] = build_output[path]
        else:
            plan.skipped.append(path)
    return plan


class UnsafeDeploy(Exception):
    """The build output contains files that must not become public."""


def publish(build_output: dict[str, bytes]) -> dict[str, bytes]:
    """Fail the deploy loudly instead of silently shipping secrets."""
    plan = plan_publish(build_output)
    if plan.blocked:
        raise UnsafeDeploy(f"refusing to publish: {plan.blocked}")
    return plan.published


# --- fix, layer 2: the server refuses hidden paths anyway -------------------------
def serve(web_root: dict[str, bytes], raw_path: str) -> tuple[int, bytes]:
    """Fixed server: hidden paths get the same 404 as missing files."""
    segments = split_request_path(raw_path)
    # 404 rather than 403, so a scanner cannot tell that /.git exists.
    if segments is None or is_hidden(segments):
        return HTTP_NOT_FOUND, b""
    path = "/".join(segments) or "index.html"
    if path in web_root:
        return HTTP_OK, web_root[path]
    return HTTP_NOT_FOUND, b""
