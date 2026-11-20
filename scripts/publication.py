"""Keep policy state behind repository authentication and deliver one Gist file."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.parse
import uuid


STATE_FILES = re.compile(r"source-[0-9a-f]{64}\.yaml\Z")
DELIVERY_FILE = "mihomo-alive.yaml"
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_APPLIED_ROUNDS = 512


class PublicationError(Exception):
    """Carry a fixed category only; remote bodies and URLs may contain secrets."""


def encode_json(value):
    """Encode a JSON value deterministically; return UTF-8 bytes."""
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


def is_state_file(name):
    """Return whether a filename belongs to the private publication state."""
    return name in {DELIVERY_FILE, "manifest.json"} or bool(STATE_FILES.fullmatch(name))


def validate_token(token):
    """Validate an environment token and return it without surrounding whitespace."""
    value = str(token or "").strip()
    if not value or any(character.isspace() for character in value):
        raise PublicationError("publication_config_invalid")
    return value


def github_headers(token):
    """Build authenticated GitHub API headers from a validated token."""
    return {"Authorization": "Bearer " + validate_token(token),
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"}


class PrivateStateStore:
    """One versioned JSON bundle in a private GitHub repository, with SHA CAS."""

    def __init__(self, repository, token, transport, branch="main", path="probe/state.json"):
        """Validate repository settings; retain an injected HTTP transport."""
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository or ""):
            raise PublicationError("state_config_invalid")
        for value in (branch, path):
            if (not value or not re.fullmatch(r"[A-Za-z0-9_./-]+", value)
                    or value.startswith(("/", "-"))
                    or any(part in {"", ".", ".."} for part in value.split("/"))):
                raise PublicationError("state_config_invalid")
        self.repository_url = "https://api.github.com/repos/" + repository
        self.url = self.repository_url + "/contents/" + path
        self.branch = branch
        self.headers = github_headers(token)
        self.transport = transport
        self.round_id = uuid.uuid4().hex
        self.applied_rounds = []

    def verify(self):
        """Require an existing private repository and branch before reading state."""
        raw, _ = self.transport("GET", self.repository_url, self.headers)
        if json.loads(raw).get("private") is not True:
            raise PublicationError("state_not_private")
        self.transport("GET", self.repository_url + "/git/ref/heads/"
                       + urllib.parse.quote(self.branch, safe=""), self.headers)

    def current(self):
        """Return (managed files, blob SHA); a missing file is an empty baseline."""
        self.verify()
        self.applied_rounds = []
        try:
            headers = dict(self.headers, Accept="application/vnd.github.object+json")
            raw, _ = self.transport("GET", self.url + "?ref="
                                    + urllib.parse.quote(self.branch, safe=""), headers)
        except Exception as error:
            if str(error) == "http_404":
                return {}, None
            raise
        entry = json.loads(raw)
        version = entry.get("sha", "")
        if entry.get("type") != "file" or not re.fullmatch(r"[0-9a-f]{40}", version):
            raise PublicationError("state_invalid")
        if entry.get("size", MAX_STATE_BYTES + 1) > MAX_STATE_BYTES:
            raise PublicationError("state_too_large")
        if entry.get("encoding") != "base64":
            raw, _ = self.transport("GET", self.repository_url + "/git/blobs/" + version,
                                    self.headers)
            entry = json.loads(raw)
        return self._decode(entry, version), version

    def _decode(self, entry, version):
        """Validate a base64 Git blob and return its managed-file map."""
        try:
            if entry.get("encoding") != "base64":
                raise ValueError
            content = base64.b64decode("".join(entry["content"].split()), validate=True)
            if len(content) > MAX_STATE_BYTES:
                raise ValueError
            blob = b"blob " + str(len(content)).encode() + b"\0" + content
            if hashlib.sha1(blob).hexdigest() != version:
                raise ValueError
            bundle = json.loads(content)
            files = bundle["files"]
            if bundle.get("version") != 1 or not isinstance(files, dict):
                raise ValueError
            if not all(isinstance(name, str) and is_state_file(name)
                       and isinstance(text, str) for name, text in files.items()):
                raise ValueError
            history = bundle.get("applied_rounds", [])
            latest = bundle.get("round_id")
            if latest is not None and not re.fullmatch(r"[0-9a-f]{32}", latest):
                raise ValueError
            if (not isinstance(history, list) or len(history) > MAX_APPLIED_ROUNDS
                    or not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value)
                               for value in history)):
                raise ValueError
            # The latest marker also recognizes bundles written before the ledger.
            self.applied_rounds = list(dict.fromkeys(history + ([latest] if latest else [])))
            self.applied_rounds = self.applied_rounds[-MAX_APPLIED_ROUNDS:]
            return files
        except (KeyError, TypeError, ValueError, AttributeError):
            raise PublicationError("state_invalid") from None

    def save(self, files, version):
        """CAS-write managed files against a blob SHA; return no subscription data."""
        if not all(isinstance(name, str) and is_state_file(name)
                   and isinstance(text, str) for name, text in files.items()):
            raise PublicationError("state_invalid")
        history = [value for value in self.applied_rounds if value != self.round_id]
        history = (history + [self.round_id])[-MAX_APPLIED_ROUNDS:]
        content = encode_json({"version": 1, "files": files, "round_id": self.round_id,
                               "applied_rounds": history})
        if len(content) > MAX_STATE_BYTES:
            raise PublicationError("state_too_large")
        body = {"message": "Update private probe state", "branch": self.branch,
                "content": base64.b64encode(content).decode("ascii")}
        if version:
            body["sha"] = version
        # Verify privacy again immediately before a credential-bearing write.
        self.verify()
        try:
            headers = dict(self.headers, **{"Content-Type": "application/json"})
            self.transport("PUT", self.url, headers, encode_json(body))
        except Exception as error:
            if str(error) in {"http_409", "http_422"}:
                raise PublicationError("state_conflict") from None
            raise


class DeliveryGist:
    """An unlisted Gist containing only a usable merged subscription."""

    def __init__(self, gist_id, token, transport):
        """Validate a Gist locator/token and retain an injected HTTP transport."""
        gist_id = str(gist_id or "").strip()
        if not re.fullmatch(r"[0-9a-fA-F]{5,64}", gist_id):
            raise PublicationError("delivery_config_invalid")
        self.url = "https://api.github.com/gists/" + gist_id
        self.headers = github_headers(token)
        self.transport = transport

    def current(self):
        """Require an unlisted, single-file Gist and return its merged YAML."""
        raw, _ = self.transport("GET", self.url, self.headers)
        document = json.loads(raw)
        if document.get("public") is not False:
            raise PublicationError("delivery_not_unlisted")
        files = document.get("files")
        if not isinstance(files, dict) or set(files) != {DELIVERY_FILE}:
            raise PublicationError("delivery_gist_mixed")
        entry = files[DELIVERY_FILE]
        if not entry.get("truncated") and isinstance(entry.get("content"), str):
            return entry["content"]
        parts = urllib.parse.urlsplit(entry.get("raw_url", ""))
        if (parts.scheme != "https" or parts.hostname != "gist.githubusercontent.com"
                or parts.port not in (None, 443) or parts.username):
            raise PublicationError("delivery_raw_invalid")
        raw, _ = self.transport("GET", parts.geturl(), self.headers)
        return raw.decode("utf-8")

    def publish(self, content):
        """Publish one merged YAML only, without policy state or source files."""
        if self.current() == content:
            return "no_change"
        headers = dict(self.headers, **{"Content-Type": "application/json"})
        self.transport("PATCH", self.url, headers,
                       encode_json({"files": {DELIVERY_FILE: {"content": content}}}))
        return "published"
