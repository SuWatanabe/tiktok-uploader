#!/usr/bin/env python3
"""tiktok_upload.py — personal TikTok inbox uploader for @shutten_data_lab.

Implements, with the Python standard library only:

  * Login Kit for Desktop authorization (OAuth 2.0 + mandatory PKCE,
    loopback redirect on 127.0.0.1), exchanging the code at TikTok's token
    endpoint and storing the tokens locally.
  * Content Posting API "Upload" flow: initialize an inbox upload
    (POST /v2/post/publish/inbox/video/init/), PUT the file in chunks,
    then poll POST /v2/post/publish/status/fetch/ until the draft reaches
    the creator's inbox (SEND_TO_USER_INBOX).

Behavior follows the official TikTok for Developers documentation; see
demo-video-plan.md in the estat-business repo
(workflow/jobs/xplat-005-tiktok-api/) for the cited implementation brief.

Usage:
    python3 tiktok_upload.py [--env-file PATH] [--dry-run] auth
    python3 tiktok_upload.py [--env-file PATH] [--dry-run] upload VIDEO.mp4

Configuration is read from a local .env-style file (default: tools/.env,
see tools/.env.example). The client secret and tokens are never printed.
Which environment you talk to (Sandbox vs Production) is decided entirely
by which app's client key/secret pair is configured.

Run this on the computer whose browser you will use to authorize the
TikTok account (the loopback redirect must reach this machine).
"""

import argparse
import hashlib
import json
import math
import mimetypes
import os
import secrets
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

AUTH_URL = "https://www.tiktok.com/v2/auth/authorize/"
TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/"
INIT_URL = "https://open.tiktokapis.com/v2/post/publish/inbox/video/init/"
STATUS_URL = "https://open.tiktokapis.com/v2/post/publish/status/fetch/"

MB = 1024 * 1024
MIN_CHUNK = 5 * MB            # Media Transfer Guide: chunks are 5 MB .. 64 MB
MAX_CHUNK = 64 * MB
MAX_FINAL_CHUNK = 128 * MB    # final chunk may exceed chunk_size up to 128 MB
MAX_CHUNKS = 1000
DEFAULT_CHUNK = 10 * MB
MAX_VIDEO_SIZE = 4 * 1024 * MB  # 4 GB

DEFAULT_SCOPES = "user.info.basic,video.upload"
DEFAULT_REDIRECT_URI = "http://127.0.0.1:8080/callback/"

TOOLS_DIR = Path(__file__).resolve().parent
DEFAULT_ENV_FILE = TOOLS_DIR / ".env"
DEFAULT_TOKEN_FILE = TOOLS_DIR / ".tiktok_token.json"


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

class Config:
    def __init__(self, env_file: Path):
        self.env_file = env_file
        self.values = {}
        if env_file.is_file():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                self.values[key.strip()] = value.strip().strip('"').strip("'")
        self.client_key = self.values.get("TIKTOK_CLIENT_KEY", "")
        self.client_secret = self.values.get("TIKTOK_CLIENT_SECRET", "")
        self.redirect_uri = self.values.get("TIKTOK_REDIRECT_URI",
                                            DEFAULT_REDIRECT_URI)
        self.scopes = self.values.get("TIKTOK_SCOPES", DEFAULT_SCOPES)
        token_file = self.values.get("TIKTOK_TOKEN_FILE", "")
        self.token_file = Path(token_file) if token_file else DEFAULT_TOKEN_FILE

    def problems(self):
        probs = []
        if not self.env_file.is_file():
            probs.append(f"env file not found: {self.env_file} "
                         f"(copy tools/.env.example to tools/.env and fill it in)")
        if not self.client_key:
            probs.append("TIKTOK_CLIENT_KEY is empty")
        if not self.client_secret:
            probs.append("TIKTOK_CLIENT_SECRET is empty")
        parsed = urllib.parse.urlparse(self.redirect_uri)
        if parsed.hostname not in ("127.0.0.1", "localhost") or not parsed.port:
            probs.append("TIKTOK_REDIRECT_URI must be a loopback URI with a port "
                         "(Desktop Login Kit rule), e.g. http://127.0.0.1:8080/callback/")
        return probs


# --------------------------------------------------------------------------
# Small HTTP helpers (stdlib only)
# --------------------------------------------------------------------------

def http_json(url, payload, access_token=None):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json; charset=UTF-8")
    if access_token:
        req.add_header("Authorization", f"Bearer {access_token}")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        raise SystemExit(f"HTTP {e.code} from {url}: {body}")


def http_form(url, fields):
    data = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Cache-Control", "no-cache")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        raise SystemExit(f"HTTP {e.code} from {url}: {body}")


def check_error(resp, what):
    err = resp.get("error") or {}
    code = err.get("code", "ok")
    if code != "ok":
        raise SystemExit(f"{what} failed: error={code} message={err.get('message', '')} "
                         f"log_id={err.get('log_id', '')}")
    return resp.get("data") or {}


# --------------------------------------------------------------------------
# OAuth (Login Kit for Desktop, PKCE mandatory)
# --------------------------------------------------------------------------

def make_pkce():
    alphabet = string.ascii_letters + string.digits + "-._~"
    verifier = "".join(secrets.choice(alphabet) for _ in range(64))
    # TikTok quirk (per Login Kit for Desktop docs): the challenge is the
    # HEX-encoded SHA-256 of the verifier, not the RFC 7636 base64url form.
    challenge = hashlib.sha256(verifier.encode("ascii")).hexdigest()
    return verifier, challenge


def build_authorize_url(cfg, state, challenge):
    params = {
        "client_key": cfg.client_key,
        "response_type": "code",
        "scope": cfg.scopes,
        "redirect_uri": cfg.redirect_uri,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return AUTH_URL + "?" + urllib.parse.urlencode(params)


class _CallbackHandler(BaseHTTPRequestHandler):
    result = None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        expected = urllib.parse.urlparse(self.server.redirect_uri).path
        if parsed.path != expected:
            self.send_response(404)
            self.end_headers()
            return
        query = urllib.parse.parse_qs(parsed.query)
        _CallbackHandler.result = {k: v[0] for k, v in query.items()}
        ok = "code" in _CallbackHandler.result
        body = ("Authorization received. You can close this tab and return "
                "to the terminal." if ok else
                "Authorization failed. Return to the terminal for details.")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, *args):
        pass


def wait_for_callback(cfg, timeout):
    parsed = urllib.parse.urlparse(cfg.redirect_uri)
    server = HTTPServer(("127.0.0.1", parsed.port), _CallbackHandler)
    server.redirect_uri = cfg.redirect_uri
    server.timeout = 1.0
    deadline = time.time() + timeout
    while _CallbackHandler.result is None and time.time() < deadline:
        server.handle_request()
    server.server_close()
    if _CallbackHandler.result is None:
        raise SystemExit("Timed out waiting for the authorization callback.")
    return _CallbackHandler.result


def save_token(cfg, token_resp):
    record = dict(token_resp)
    now = int(time.time())
    record["obtained_at"] = now
    record["access_expires_at"] = now + int(token_resp.get("expires_in", 0))
    record["refresh_expires_at"] = now + int(token_resp.get("refresh_expires_in", 0))
    cfg.token_file.write_text(json.dumps(record, indent=2), encoding="utf-8")
    try:
        os.chmod(cfg.token_file, 0o600)
    except OSError:
        pass
    return record


def load_token(cfg):
    if not cfg.token_file.is_file():
        raise SystemExit(f"No stored token at {cfg.token_file}. Run `auth` first.")
    return json.loads(cfg.token_file.read_text(encoding="utf-8"))


def refresh_token(cfg, token):
    resp = http_form(TOKEN_URL, {
        "client_key": cfg.client_key,
        "client_secret": cfg.client_secret,
        "grant_type": "refresh_token",
        "refresh_token": token["refresh_token"],
    })
    if "error" in resp and "access_token" not in resp:
        raise SystemExit(f"Token refresh failed: {resp.get('error')}: "
                         f"{resp.get('error_description', '')}. Run `auth` again.")
    # Refresh tokens rotate: always persist the newly returned one.
    return save_token(cfg, resp)


def get_valid_token(cfg):
    token = load_token(cfg)
    if int(time.time()) >= int(token.get("access_expires_at", 0)) - 60:
        print("Access token expired (or about to); refreshing...")
        token = refresh_token(cfg, token)
    return token


def cmd_auth(cfg, args):
    verifier, challenge = make_pkce()
    state = secrets.token_urlsafe(24)
    url = build_authorize_url(cfg, state, challenge)
    if args.dry_run:
        print("[dry-run] Would start a loopback server for redirect URI:",
              cfg.redirect_uri)
        print("[dry-run] Would open this authorization URL in the browser:")
        print(" ", url)
        print(f"[dry-run] Would then POST the returned code to {TOKEN_URL} with "
              "grant_type=authorization_code, redirect_uri and the PKCE "
              "code_verifier, and store the token in", cfg.token_file)
        return
    print("Opening TikTok authorization page in your browser...")
    print("If it does not open, visit this URL manually:\n ", url)
    webbrowser.open(url)
    result = wait_for_callback(cfg, args.timeout)
    if "error" in result:
        raise SystemExit(f"Authorization failed: {result['error']}: "
                         f"{result.get('error_description', '')}")
    if result.get("state") != state:
        raise SystemExit("State mismatch in the callback; aborting (possible CSRF).")
    code = result["code"]  # parse_qs already URL-decoded it, as the docs require
    resp = http_form(TOKEN_URL, {
        "client_key": cfg.client_key,
        "client_secret": cfg.client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": cfg.redirect_uri,
        "code_verifier": verifier,
    })
    if "access_token" not in resp:
        raise SystemExit(f"Token exchange failed: {resp}")
    record = save_token(cfg, resp)
    open_id = record.get("open_id", "")
    masked = (open_id[:4] + "..." + open_id[-4:]) if len(open_id) > 8 else "(set)"
    print(f"Authorized. open_id={masked} scopes={record.get('scope', '')}")
    print(f"Token stored in {cfg.token_file} (access token valid "
          f"{record.get('expires_in', 0)}s, refresh token "
          f"{record.get('refresh_expires_in', 0)}s).")


# --------------------------------------------------------------------------
# Upload (Content Posting API, inbox flow)
# --------------------------------------------------------------------------

def plan_chunks(video_size, target_chunk=DEFAULT_CHUNK):
    """Return (chunk_size, total_chunk_count) per the Media Transfer Guide.

    Rules: total_chunk_count = floor(video_size / chunk_size); chunks are
    5 MB..64 MB except the final chunk, which may exceed chunk_size up to
    128 MB; files < 5 MB go whole (chunk_size = video_size); files > 64 MB
    must be chunked; 1..1000 chunks.
    """
    if video_size <= 0:
        raise SystemExit("Video file is empty.")
    if video_size > MAX_VIDEO_SIZE:
        raise SystemExit(f"Video is {video_size} bytes; the API maximum is 4 GB.")
    if video_size < MIN_CHUNK:
        return video_size, 1
    if video_size <= MAX_CHUNK:
        return video_size, 1
    chunk = target_chunk
    count = video_size // chunk
    if count > MAX_CHUNKS:
        chunk = math.ceil(video_size / MAX_CHUNKS)
        count = video_size // chunk
    final_size = video_size - (count - 1) * chunk
    if not (chunk <= final_size <= MAX_FINAL_CHUNK):
        raise SystemExit(f"Internal chunk-plan error: chunk={chunk}, "
                         f"final={final_size}.")
    return chunk, count


def cmd_upload(cfg, args):
    path = Path(args.video)
    if not path.is_file():
        raise SystemExit(f"Video file not found: {path}")
    video_size = path.stat().st_size
    chunk_size, total_chunks = plan_chunks(video_size)
    mime = mimetypes.guess_type(path.name)[0] or "video/mp4"
    if args.dry_run:
        print(f"[dry-run] File: {path} ({video_size} bytes, {mime})")
        print(f"[dry-run] Chunk plan: chunk_size={chunk_size}, "
              f"total_chunk_count={total_chunks}")
        print(f"[dry-run] Would POST {INIT_URL} with source_info "
              f"FILE_UPLOAD (requires a stored token from `auth`).")
        print("[dry-run] Would PUT each chunk to the returned upload_url "
              "sequentially, then poll", STATUS_URL,
              "until SEND_TO_USER_INBOX / PUBLISH_COMPLETE / FAILED.")
        return

    token = get_valid_token(cfg)
    access_token = token["access_token"]

    print(f"Initializing inbox upload for {path.name} ({video_size} bytes, "
          f"{total_chunks} chunk(s) of {chunk_size})...")
    resp = http_json(INIT_URL, {
        "source_info": {
            "source": "FILE_UPLOAD",
            "video_size": video_size,
            "chunk_size": chunk_size,
            "total_chunk_count": total_chunks,
        }
    }, access_token)
    data = check_error(resp, "Upload init")
    publish_id = data["publish_id"]
    upload_url = data["upload_url"]
    print(f"publish_id={publish_id}")

    with path.open("rb") as fh:
        for i in range(total_chunks):
            start = i * chunk_size
            if i == total_chunks - 1:
                blob = fh.read()
            else:
                blob = fh.read(chunk_size)
            end = start + len(blob) - 1
            req = urllib.request.Request(upload_url, data=blob, method="PUT")
            req.add_header("Content-Type", mime)
            req.add_header("Content-Length", str(len(blob)))
            req.add_header("Content-Range", f"bytes {start}-{end}/{video_size}")
            try:
                with urllib.request.urlopen(req) as r:
                    status = r.status
            except urllib.error.HTTPError as e:
                if e.code >= 500:  # docs: 5xx chunk errors are retryable
                    raise SystemExit(f"Chunk {i + 1}/{total_chunks} failed with "
                                     f"HTTP {e.code}; re-run the upload to retry.")
                raise SystemExit(f"Chunk {i + 1}/{total_chunks} failed: "
                                 f"HTTP {e.code} {e.read().decode('utf-8', 'replace')}")
            expected = 201 if i == total_chunks - 1 else 206
            print(f"  chunk {i + 1}/{total_chunks}: HTTP {status} "
                  f"(expected {expected})")
            if status != expected:
                raise SystemExit(f"Unexpected status for chunk {i + 1}: {status}")

    print("Upload complete. Waiting for TikTok to deliver the draft...")
    deadline = time.time() + args.status_timeout
    while time.time() < deadline:
        resp = http_json(STATUS_URL, {"publish_id": publish_id}, access_token)
        data = check_error(resp, "Status fetch")
        status = data.get("status", "")
        print(f"  status: {status}")
        if status == "SEND_TO_USER_INBOX":
            print("Done: the video is in the creator's TikTok inbox as a draft. "
                  "Open the TikTok app, tap the inbox notification, and finish "
                  "the post there.")
            return
        if status == "PUBLISH_COMPLETE":
            print("Done: the post is published.")
            return
        if status == "FAILED":
            raise SystemExit(f"Posting failed: {data.get('fail_reason', 'unknown')}")
        time.sleep(args.poll_interval)
    raise SystemExit("Timed out waiting for the final status; check the "
                     "TikTok app inbox — the draft may still arrive.")


# --------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Upload videos to the owner's TikTok inbox via the "
                    "Content Posting API (Login Kit desktop OAuth + PKCE).")
    parser.add_argument("--env-file", default=str(DEFAULT_ENV_FILE),
                        help="path to the .env-style config (default: tools/.env)")
    parser.add_argument("--dry-run", action="store_true",
                        help="validate config and arguments, print the plan, "
                             "and make no network calls")
    sub = parser.add_subparsers(dest="command", required=True)

    p_auth = sub.add_parser("auth", help="authorize the TikTok account (OAuth)")
    p_auth.add_argument("--timeout", type=int, default=300,
                        help="seconds to wait for the browser callback")

    p_up = sub.add_parser("upload", help="upload one mp4 to the TikTok inbox")
    p_up.add_argument("video", help="path to the video file")
    p_up.add_argument("--poll-interval", type=int, default=10,
                      help="seconds between status checks (limit: 30/min)")
    p_up.add_argument("--status-timeout", type=int, default=600,
                      help="max seconds to wait for the final status")

    args = parser.parse_args(argv)
    cfg = Config(Path(args.env_file))

    if args.dry_run:
        probs = [p for p in cfg.problems()
                 if "not found" not in p and "empty" not in p]
        if probs:
            for p in probs:
                print(f"config problem: {p}", file=sys.stderr)
            return 2
        if cfg.problems():
            print("[dry-run] note: credentials are not configured yet; "
                  "that is fine for a dry run.")
    else:
        probs = cfg.problems()
        if probs:
            for p in probs:
                print(f"config problem: {p}", file=sys.stderr)
            return 2

    if args.command == "auth":
        cmd_auth(cfg, args)
    elif args.command == "upload":
        cmd_upload(cfg, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
