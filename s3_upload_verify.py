#!/usr/bin/env python3
"""s3-upload-verify: checks that a local folder arrived complete in Amazon S3.

Run it with no arguments and it opens the window. From a terminal:

    # 1. On the machine with the data, write a manifest of sizes and hashes.
    python3 s3_upload_verify.py manifest /path/to/dir -o manifest.jsonl

    # 2. Anywhere with read access to the bucket, compare the manifest with S3.
    python3 s3_upload_verify.py check --manifest manifest.jsonl --bucket my-bucket --prefix some/dir/

    # Or both at once, on a machine with the data and access to S3:
    python3 s3_upload_verify.py check --dir /path/to/dir --bucket my-bucket --prefix some/dir/

It only needs the Python 3.8+ standard library. It only reads from S3:
ListBuckets, ListObjectsV2, HeadObject, and a HEAD on the bucket to find its region.

Why not a plain MD5 compare: S3 keeps the MD5 as ETag only for single-part
uploads without SSE-KMS/SSE-C. A multipart ETag is the MD5 of the part MD5s, so
it depends on the part size the upload tool used. I compute it for the usual
part sizes, or for the exact part size of each object when there is access to
S3, and I also use the CRC32, CRC64NVME and SHA-256 checksums that S3 can keep.

Copyright (C) 2026 millaguie. License: GPL-3.0-or-later.
"""

import argparse
import base64
import concurrent.futures
import configparser
import datetime
import hashlib
import hmac
import json
import math
import os
import queue
import shlex
import ssl
import stat
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zlib

if sys.version_info < (3, 8):
    sys.exit("ERROR: this tool needs Python 3.8 or newer.")

__version__ = "1.0.1"
MANIFEST_VERSION = 2
MiB = 1024 * 1024
# Part sizes that common S3 upload clients use by default.
DEFAULT_PART_SIZES_MIB = [5, 8, 10, 15, 16]
AWS_CLI_PART_SIZE = 8 * MiB
MAX_PARTS = 10000
MAX_PART_SIZE = 5 * 1024 * MiB
READ_SIZE = 1 * MiB
JUNK_NAMES = {".DS_Store", "Thumbs.db", "desktop.ini"}
CRC64_SPEED = "about 13 MB/s"

SEVERITY = ["HASH_MISMATCH", "SIZE_MISMATCH", "MISSING", "NO_ACCESS", "SIZE_ONLY", "UNHASHED_SYMLINK",
            "OK_CRC32", "OK_CRC64NVME", "OK_SHA256", "OK", "EXTRA"]
FAIL = {"HASH_MISMATCH", "SIZE_MISMATCH", "MISSING", "NO_ACCESS"}
WARN = {"SIZE_ONLY", "UNHASHED_SYMLINK"}
STATUS_HELP = {
    "HASH_MISMATCH": "size matches, content differs: corrupt or a different file",
    "SIZE_MISMATCH": "size differs",
    "MISSING": "local file not found in S3",
    "NO_ACCESS": "could not read the object metadata (HeadObject needs s3:GetObject)",
    "SIZE_ONLY": "size matches, but no hash could be compared",
    "UNHASHED_SYMLINK": "in S3 under a path skipped locally as a symlink",
    "OK_CRC32": "size and S3 CRC32 match (32-bit check)",
    "OK_CRC64NVME": "size and S3 CRC64NVME match",
    "OK_SHA256": "size and S3 SHA-256 match",
    "OK": "size and ETag (MD5) match",
    "EXTRA": "in S3, not in the local list (informational)",
}


class Cancelled(Exception):
    pass


class S3Error(RuntimeError):
    pass


def noop_progress(*_args):
    pass


# ---------------------------------------------------------------- hashing

CRC64_POLY = 0x9A6C9329AC4BC9B5  # CRC-64/NVME, reflected
CRC64_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ CRC64_POLY if _c & 1 else _c >> 1
    CRC64_TABLE.append(_c)


def crc64nvme_update(crc, data):
    t = CRC64_TABLE
    for b in data:
        crc = t[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc


def aws_cli_part_size(size):
    # Some clients double the 8 MiB part size until the upload fits in 10,000 parts.
    ps = AWS_CLI_PART_SIZE
    while math.ceil(size / ps) > MAX_PARTS:
        ps *= 2
    return ps


def part_sizes_for(size, base_sizes, extra=()):
    sizes = {ps for ps in base_sizes if math.ceil(size / ps) <= MAX_PARTS}
    sizes.add(min(aws_cli_part_size(size), MAX_PART_SIZE))
    sizes.update(extra)
    # One part means no multipart ETag to compute (the checker derives "-1" from the MD5).
    return sorted(ps for ps in sizes if size > ps)


def part_key(ps):
    """Key of a multipart ETag in the manifest: MiB when whole, else bytes with a B."""
    return str(ps // MiB) if ps % MiB == 0 else "%dB" % ps


def key_bytes(key):
    return int(key[:-1]) if key.endswith("B") else int(key) * MiB


def hash_file(path, part_sizes, with_crc64=False, cancel=None, on_bytes=None):
    full_md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    crc32 = 0
    crc64 = 0xFFFFFFFFFFFFFFFF
    parts = {ps: {"cur": hashlib.md5(), "fill": 0, "digests": []} for ps in part_sizes}
    size = 0
    with open(path, "rb") as f:
        while True:
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            buf = f.read(READ_SIZE)
            if not buf:
                break
            size += len(buf)
            full_md5.update(buf)
            sha256.update(buf)
            crc32 = zlib.crc32(buf, crc32)
            if with_crc64:
                crc64 = crc64nvme_update(crc64, buf)
            for ps, st in parts.items():
                view = memoryview(buf)
                while view:
                    take = min(len(view), ps - st["fill"])
                    st["cur"].update(view[:take])
                    st["fill"] += take
                    view = view[take:]
                    if st["fill"] == ps:
                        st["digests"].append(st["cur"].digest())
                        st["cur"] = hashlib.md5()
                        st["fill"] = 0
            if on_bytes:
                on_bytes(len(buf))
    etags = {}
    for ps, st in parts.items():
        digests = list(st["digests"])
        if st["fill"]:
            digests.append(st["cur"].digest())
        if len(digests) > 1:
            etags[part_key(ps)] = "%s-%d" % (hashlib.md5(b"".join(digests)).hexdigest(), len(digests))
    rec = {"size": size, "md5": full_md5.hexdigest(), "sha256": sha256.hexdigest(),
           "crc32": "%08x" % (crc32 & 0xFFFFFFFF), "etags": etags}
    if with_crc64:
        rec["crc64nvme"] = "%016x" % (crc64 ^ 0xFFFFFFFFFFFFFFFF)
    return rec


# ---------------------------------------------------------------- manifest

def long_path(p):
    # Windows refuses paths over 260 characters unless they use the \\?\ prefix.
    if os.name != "nt" or p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):
        return "\\\\?\\UNC\\" + p[2:]
    return "\\\\?\\" + p


def plain_path(p):
    if p.startswith("\\\\?\\UNC\\"):
        return "\\\\" + p[8:]
    if p.startswith("\\\\?\\"):
        return p[4:]
    return p


def parse_part_sizes(text):
    try:
        values = [int(x) for x in str(text).split(",") if x.strip()]
    except ValueError:
        raise ValueError("part sizes must be whole numbers of MiB, e.g. 5,8,16")
    if not values or any(v < 5 or v > 5 * 1024 for v in values):
        raise ValueError("part sizes must be between 5 and 5120 MiB (S3 limits)")
    return sorted({v * MiB for v in values})


def read_path_list(path):
    # The checker writes one JSON string per line, plain paths work too.
    wanted = set()
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except ValueError:
                value = line
            wanted.add(value if isinstance(value, str) else line)
    return wanted


def fmt_bytes(n):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return "%d B" % n if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def scan(root, exclude_hidden=False, follow_symlinks=False, only=None, exclude_files=(), cancel=None):
    """Walk root. Return (files, records): files is [(full, rel, size)], records
    holds 'error' and 'skipped' entries."""
    root_io = long_path(os.path.abspath(root))
    exclude = {plain_path(os.path.realpath(p)) for p in exclude_files}
    records, files = [], []
    ancestors = {}  # real paths of each walked directory and its parents (symlink loops)

    def rel_of(p):
        return os.path.relpath(p, root_io).replace(os.sep, "/")

    def on_walk_error(e):
        records.append({"type": "error", "path": rel_of(e.filename) if e.filename else "?", "error": str(e)})

    for dirpath, dirnames, filenames in os.walk(root_io, onerror=on_walk_error, followlinks=follow_symlinks):
        if cancel is not None and cancel.is_set():
            raise Cancelled()
        if follow_symlinks:
            real = os.path.realpath(dirpath)
            parent = ancestors.get(os.path.dirname(dirpath), frozenset())
            if real in parent:
                dirnames[:] = []
                records.append({"type": "skipped", "path": rel_of(dirpath), "reason": "symlink loop", "dir": True})
                continue
            ancestors[dirpath] = parent | {real}
        kept = []
        for d in sorted(dirnames):
            full = os.path.join(dirpath, d)
            if exclude_hidden and d.startswith("."):
                continue
            if os.path.islink(full) and not follow_symlinks:
                records.append({"type": "skipped", "path": rel_of(full), "reason": "symlink", "dir": True})
                continue
            kept.append(d)
        dirnames[:] = kept
        for name in sorted(filenames):
            if name in JUNK_NAMES or (exclude_hidden and name.startswith(".")):
                continue
            full = os.path.join(dirpath, name)
            rel = rel_of(full)
            if only is not None and rel not in only:
                continue
            try:
                st = os.stat(full) if follow_symlinks else os.lstat(full)
            except OSError as e:
                records.append({"type": "error", "path": rel, "error": str(e)})
                continue
            if stat.S_ISLNK(st.st_mode):
                records.append({"type": "skipped", "path": rel, "reason": "symlink", "dir": False})
                continue
            if not stat.S_ISREG(st.st_mode):
                records.append({"type": "skipped", "path": rel, "reason": "not a regular file"})
                continue
            if plain_path(os.path.realpath(full)) in exclude:
                continue
            files.append((full, rel, st.st_size))
    if only is not None:
        found = {rel for _, rel, _ in files}
        for rel in sorted(only - found):
            records.append({"type": "error", "path": rel, "error": "listed in --only but not found"})
    return files, records


def hash_files(files, part_sizes, with_crc64=False, extra_part_sizes=None, progress=noop_progress, cancel=None):
    """Yield one 'file' or 'error' record per file. extra_part_sizes maps rel -> part size."""
    total = sum(size for _, _, size in files)
    done = [0]
    start = time.time()

    def on_bytes(n):
        done[0] += n

    for i, (full, rel, size) in enumerate(files, 1):
        elapsed = time.time() - start
        eta = (total - done[0]) * elapsed / done[0] if done[0] else 0
        progress("hash", done[0], total, "[%d/%d ETA %dm] %s" % (i, len(files), eta // 60, rel))
        extra = [extra_part_sizes[rel]] if extra_part_sizes and rel in extra_part_sizes else ()
        before = done[0]
        try:
            rec = hash_file(full, part_sizes_for(size, part_sizes, extra), with_crc64, cancel, on_bytes)
        except OSError as e:
            done[0] = before + size
            yield {"type": "error", "path": rel, "error": str(e)}
            continue
        yield dict({"type": "file", "path": rel}, **rec)
    progress("hash", total, total, "hashed %d files" % len(files))


def write_manifest(root, output, part_sizes, exclude_hidden=False, follow_symlinks=False,
                   only=None, with_crc64=False, progress=noop_progress, cancel=None):
    """Write the manifest file. Return (files_written, errors)."""
    partial = output + ".partial"
    progress("scan", 0, 0, "Scanning %s ..." % root)
    files, records = scan(root, exclude_hidden, follow_symlinks, only, exclude_files=(output, partial), cancel=cancel)
    errors = sum(1 for r in records if r["type"] == "error")
    total = sum(s for _, _, s in files)
    progress("scan", 0, 0, "Found %d files, %s." % (len(files), fmt_bytes(total)))
    written = 0
    with open(partial, "w", encoding="utf-8") as out:
        out.write(json.dumps({
            "type": "header", "version": MANIFEST_VERSION, "tool": "s3-upload-verify " + __version__,
            "root": os.path.basename(os.path.abspath(root)),
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "files": len(files) + errors, "bytes": total, "only": only is not None,
            "part_sizes_mib": [ps // MiB for ps in part_sizes], "crc64nvme": with_crc64,
        }) + "\n")
        for r in records:
            out.write(json.dumps(r) + "\n")
        for rec in hash_files(files, part_sizes, with_crc64, progress=progress, cancel=cancel):
            out.write(json.dumps(rec) + "\n")
            out.flush()
            if rec["type"] == "error":
                errors += 1
            else:
                written += 1
        out.write(json.dumps({"type": "end", "files": written, "errors": errors}) + "\n")
    os.replace(partial, output)
    return written, errors


class Inventory:
    """What we know about the local side: hashed files, skipped paths, read errors."""

    def __init__(self):
        self.entries, self.skipped, self.read_errors, self.headers = {}, {}, {}, []

    def add(self, rec):
        t = rec.get("type")
        if t == "file":
            old = self.entries.get(rec["path"])
            if old and old["size"] == rec["size"] and old["md5"] == rec["md5"]:
                # Same file hashed again (second round): keep everything both runs computed,
                # so the order of the manifests does not matter.
                merged = dict(old, **{k: v for k, v in rec.items() if k != "etags"})
                merged["etags"] = dict(old.get("etags", {}), **rec.get("etags", {}))
                if "crc64nvme" in old and "crc64nvme" not in rec:
                    merged["crc64nvme"] = old["crc64nvme"]
                rec = merged
            self.entries[rec["path"]] = rec
            self.read_errors.pop(rec["path"], None)
        elif t == "error":
            self.read_errors[rec["path"]] = rec["error"]
        elif t == "skipped":
            self.skipped[rec["path"]] = rec


def load_manifests(paths):
    inv = Inventory()
    for path in paths:
        header, end, n_files, n_errors = None, None, 0, 0
        with open(path, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    raise ValueError("%s line %d is not valid JSON: the manifest is damaged or cut" % (path, lineno))
                t = rec.get("type")
                if t == "header":
                    header = rec
                elif t == "end":
                    end = rec
                else:
                    inv.add(rec)
                    n_files += t == "file"
                    n_errors += t == "error"
        if not header or header.get("version") != MANIFEST_VERSION:
            raise ValueError("%s has no header or an unsupported version (need %d). "
                             "Make a new manifest with this tool." % (path, MANIFEST_VERSION))
        if not end:
            raise ValueError("%s has no end record: the manifest run did not finish. Run it again." % path)
        if not isinstance(header.get("files"), int) or not isinstance(end.get("files"), int):
            raise ValueError("%s has a malformed header or end record" % path)
        if header["files"] != n_files + n_errors or end["files"] != n_files or end.get("errors") != n_errors:
            raise ValueError("%s is inconsistent (header says %d files, found %d files + %d errors)"
                             % (path, header["files"], n_files, n_errors))
        inv.headers.append((path, header))
    if not inv.entries:
        raise ValueError("the manifest lists no files")
    if all(h.get("only") for _, h in inv.headers):
        raise ValueError("only --only manifests given. Pass the full manifest first, then the second-round ones.")
    return inv


# ---------------------------------------------------------------- credentials

class Credentials:
    def __init__(self, access_key, secret_key, token=None, source=""):
        self.access_key, self.secret_key, self.token, self.source = access_key, secret_key, token or None, source


def aws_config_files():
    creds = os.environ.get("AWS_SHARED_CREDENTIALS_FILE") or os.path.join(os.path.expanduser("~"), ".aws", "credentials")
    config = os.environ.get("AWS_CONFIG_FILE") or os.path.join(os.path.expanduser("~"), ".aws", "config")
    return creds, config


def list_profiles():
    creds_file, config_file = aws_config_files()
    names = set()
    for path, is_config in ((creds_file, False), (config_file, True)):
        cp = configparser.RawConfigParser()
        try:
            cp.read(path, encoding="utf-8")
        except (configparser.Error, OSError):
            continue
        for s in cp.sections():
            if is_config:
                s = s[len("profile "):] if s.startswith("profile ") else s
                if s.startswith(("sso-session ", "services ")):
                    continue
            names.add(s)
    return sorted(names)


def _profile_section(profile):
    creds_file, config_file = aws_config_files()
    out = {}
    cp = configparser.RawConfigParser()
    try:
        cp.read(config_file, encoding="utf-8")
        section = "default" if profile == "default" else "profile " + profile
        if cp.has_section(section):
            out.update(cp.items(section))
    except (configparser.Error, OSError):
        pass
    cp = configparser.RawConfigParser()
    try:
        cp.read(creds_file, encoding="utf-8")
        if cp.has_section(profile):
            out.update(cp.items(profile))
    except (configparser.Error, OSError):
        pass
    return out


def resolve_credentials(profile=None, access_key=None, secret_key=None, token=None):
    """Return (Credentials, region_from_profile_or_None)."""
    if access_key or secret_key:
        if not (access_key and secret_key):
            raise S3Error("give both the access key ID and the secret access key")
        return Credentials(access_key.strip(), secret_key.strip(), (token or "").strip(), "typed in"), None
    if not profile and os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
        return Credentials(os.environ["AWS_ACCESS_KEY_ID"], os.environ["AWS_SECRET_ACCESS_KEY"],
                           os.environ.get("AWS_SESSION_TOKEN"), "environment"), os.environ.get("AWS_REGION")
    profile = profile or os.environ.get("AWS_PROFILE") or "default"
    section = _profile_section(profile)
    region = section.get("region")
    if section.get("aws_access_key_id") and section.get("aws_secret_access_key"):
        return Credentials(section["aws_access_key_id"], section["aws_secret_access_key"],
                           section.get("aws_session_token"), "profile " + profile), region
    if section.get("credential_process"):
        cmd = section["credential_process"]
        return _from_process(cmd if os.name == "nt" else shlex.split(cmd), source="credential_process"), region
    # SSO, assumed roles and the rest: let AWS CLI v2 resolve them.
    try:
        return _from_process(["aws", "configure", "export-credentials", "--profile", profile, "--format", "process"],
                             source="aws CLI profile " + profile), region
    except S3Error as e:
        raise S3Error("no usable credentials for profile '%s' (%s). Type an access key, or use a profile "
                      "with static keys, or install AWS CLI v2 for SSO/role profiles." % (profile, e))


def _from_process(cmd, source):
    env = dict(os.environ)
    if sys.platform == "darwin":
        # Apps started from Finder get a minimal PATH without the usual aws locations.
        env["PATH"] = os.pathsep.join([env.get("PATH", ""), "/usr/local/bin", "/opt/homebrew/bin"])
    extra = {"creationflags": 0x08000000} if os.name == "nt" else {}  # CREATE_NO_WINDOW
    try:
        res = subprocess.run(cmd, capture_output=True, stdin=subprocess.DEVNULL, encoding="utf-8",
                             errors="replace", timeout=120, env=env, **extra)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise S3Error(str(e))
    if res.returncode != 0:
        raise S3Error((res.stderr.strip().splitlines() or ["exit %d" % res.returncode])[-1])
    try:
        data = json.loads(res.stdout)
        return Credentials(data["AccessKeyId"], data["SecretAccessKey"], data.get("SessionToken"), source)
    except (ValueError, KeyError):
        raise S3Error("credential command did not return the expected JSON")


# ---------------------------------------------------------------- S3 client (read-only, SigV4)

S3_NS = ""  # parse_xml drops namespaces, some S3-compatible servers don't send the AWS one


def parse_xml(body):
    root = ET.fromstring(body)
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root
HEAD_FIELDS = {
    "x-amz-server-side-encryption": "ServerSideEncryption",
    "x-amz-server-side-encryption-customer-algorithm": "SSECustomerAlgorithm",
    "x-amz-checksum-type": "ChecksumType",
    "x-amz-checksum-sha256": "ChecksumSHA256",
    "x-amz-checksum-sha1": "ChecksumSHA1",
    "x-amz-checksum-crc32": "ChecksumCRC32",
    "x-amz-checksum-crc32c": "ChecksumCRC32C",
    "x-amz-checksum-crc64nvme": "ChecksumCRC64NVME",
    "x-amz-mp-parts-count": "PartsCount",
}
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


_SSL_CONTEXT = []


def ssl_context():
    """Default TLS context. Frozen builds carry certifi, the bundled OpenSSL can't find the system CAs."""
    if not _SSL_CONTEXT:
        ctx = None
        if getattr(sys, "frozen", False):
            try:
                import certifi
                ctx = ssl.create_default_context(cafile=certifi.where())
            except ImportError:
                pass
        _SSL_CONTEXT.append(ctx or ssl.create_default_context())
    return _SSL_CONTEXT[0]


def uri_encode(s, safe="-_.~"):
    return urllib.parse.quote(s, safe=safe)


def sigv4_headers(method, url, region, creds, extra_headers=None, now=None, service="s3"):
    """Return the headers that sign this request (AWS Signature Version 4, empty body)."""
    parts = urllib.parse.urlsplit(url)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    headers = {"host": parts.netloc, "x-amz-date": amz_date, "x-amz-content-sha256": EMPTY_SHA256}
    if creds.token:
        headers["x-amz-security-token"] = creds.token
    for k, v in (extra_headers or {}).items():
        headers[k.lower()] = v
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    canonical_query = "&".join("%s=%s" % (uri_encode(k), uri_encode(v)) for k, v in sorted(query))
    signed = sorted(headers)
    canonical_headers = "".join("%s:%s\n" % (k, " ".join(str(headers[k]).split())) for k in signed)
    canonical = "\n".join([method, parts.path or "/", canonical_query, canonical_headers,
                           ";".join(signed), headers["x-amz-content-sha256"]])
    scope = "%s/%s/%s/aws4_request" % (datestamp, region, service)
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ("AWS4" + creds.secret_key).encode()
    for msg in (datestamp, region, service, "aws4_request"):
        key = hmac.new(key, msg.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (
        creds.access_key, scope, ";".join(signed), signature)
    del headers["host"]
    return headers


class S3Client:
    def __init__(self, bucket, creds, region=None, endpoint=None, timeout=60, region_hint=None, trust_etags=None):
        self.bucket, self.creds, self.endpoint, self.timeout = bucket, creds, endpoint, timeout
        # Other S3-compatible storage may build plain ETags that are not MD5s.
        self.trust_etags = (endpoint is None) if trust_etags is None else trust_etags
        if region:
            self.region = region
        elif endpoint:
            self.region = region_hint or "us-east-1"
        else:
            try:
                self.region = self.discover_region()
            except S3Error:
                if not region_hint:
                    raise
                self.region = region_hint

    def _base(self):
        if self.endpoint:
            return self.endpoint.rstrip("/") + "/" + uri_encode(self.bucket)
        if "." in self.bucket:  # dots break the TLS wildcard certificate
            return "https://s3.%s.amazonaws.com/%s" % (self.region, uri_encode(self.bucket))
        return "https://%s.s3.%s.amazonaws.com" % (self.bucket, self.region)

    def discover_region(self):
        req = urllib.request.Request("https://s3.amazonaws.com/" + uri_encode(self.bucket), method="HEAD")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context()) as r:
                region = r.headers.get("x-amz-bucket-region")
        except urllib.error.HTTPError as e:
            region = e.headers.get("x-amz-bucket-region")
            if e.code == 404 and not region:
                raise S3Error("bucket '%s' does not exist" % self.bucket)
        except urllib.error.URLError as e:
            raise S3Error("cannot reach S3: %s" % e.reason)
        if not region:
            raise S3Error("could not find the region of bucket '%s', set it by hand" % self.bucket)
        return region

    def _request(self, method, path, query=None, headers=None):
        url = self._base() + path
        if query:
            url += "?" + "&".join("%s=%s" % (uri_encode(k), uri_encode(v)) for k, v in sorted(query.items()))
        last = None
        for attempt in range(5):
            req = urllib.request.Request(url, method=method,
                                         headers=sigv4_headers(method, url, self.region, self.creds, headers))
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context()) as r:
                    return r.status, dict((k.lower(), v) for k, v in r.headers.items()), r.read()
            except urllib.error.HTTPError as e:
                body = e.read() if method != "HEAD" else b""
                if e.code in (500, 502, 503, 504) and attempt < 4:
                    last = e
                    time.sleep(0.5 * 2 ** attempt)
                    continue
                raise S3Error(self._error_text(e, body))
            except (urllib.error.URLError, OSError) as e:
                last = e
                if attempt < 4:
                    time.sleep(0.5 * 2 ** attempt)
                    continue
        raise S3Error("request failed after retries: %s" % last)

    @staticmethod
    def _error_text(e, body):
        code, msg = "", ""
        try:
            root = parse_xml(body)
            code, msg = root.findtext("Code") or "", root.findtext("Message") or ""
        except ET.ParseError:
            pass
        hints = {403: "access denied (check the keys and that they can read this bucket)",
                 404: "not found", 400: "bad request (SSE-C object, or wrong region)",
                 301: "wrong region"}
        return "HTTP %d %s %s" % (e.code, code or hints.get(e.code, ""), msg)

    def list_objects(self, prefix, progress=noop_progress, cancel=None):
        objs, token = {}, None
        while True:
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            q = {"list-type": "2", "prefix": prefix, "encoding-type": "url"}
            if token:
                q["continuation-token"] = token
            _, _, body = self._request("GET", "/", q)
            root = parse_xml(body)
            for c in root.iter(S3_NS + "Contents"):
                key = urllib.parse.unquote_plus(c.findtext(S3_NS + "Key"))
                objs[key] = {"size": int(c.findtext(S3_NS + "Size")),
                             "etag": (c.findtext(S3_NS + "ETag") or "").strip('"')}
            progress("list", len(objs), 0, "Listed %d objects ..." % len(objs))
            if root.findtext(S3_NS + "IsTruncated") != "true":
                return objs
            token = root.findtext(S3_NS + "NextContinuationToken")
            if not token:
                raise S3Error("listing is truncated but S3 gave no continuation token")

    def list_folders(self, prefix, max_pages=10):
        """One level of the bucket under prefix: (sub-prefixes, number of objects, truncated)."""
        folders, n_objects, token = [], 0, None
        for _page in range(max_pages):
            q = {"list-type": "2", "prefix": prefix, "delimiter": "/", "encoding-type": "url"}
            if token:
                q["continuation-token"] = token
            _, _, body = self._request("GET", "/", q)
            root = parse_xml(body)
            for cp in root.iter(S3_NS + "CommonPrefixes"):
                folders.append(urllib.parse.unquote_plus(cp.findtext(S3_NS + "Prefix") or ""))
            n_objects += sum(1 for c in root.iter(S3_NS + "Contents")
                             if urllib.parse.unquote_plus(c.findtext(S3_NS + "Key") or "") != prefix)
            truncated = root.findtext(S3_NS + "IsTruncated") == "true"
            token = root.findtext(S3_NS + "NextContinuationToken")
            if not truncated or not token:
                return folders, n_objects, False
        return folders, n_objects, True

    def head(self, key, part_number=None):
        q = {"partNumber": str(part_number)} if part_number else None
        _, h, _ = self._request("HEAD", "/" + uri_encode(key, safe="/-_.~"), q, {"x-amz-checksum-mode": "ENABLED"})
        out = {"ContentLength": int(h.get("content-length", 0)), "ETag": h.get("etag", "").strip('"')}
        for header, field in HEAD_FIELDS.items():
            if header in h:
                out[field] = h[header]
        return out


def list_buckets(creds, endpoint=None, timeout=60):
    """Names of the buckets these credentials can see (needs s3:ListAllMyBuckets)."""
    url = (endpoint.rstrip("/") if endpoint else "https://s3.amazonaws.com") + "/"
    req = urllib.request.Request(url, headers=sigv4_headers("GET", url, "us-east-1", creds))
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context()) as r:
            body = r.read()
    except urllib.error.HTTPError as e:
        raise S3Error(S3Client._error_text(e, e.read()))
    except (urllib.error.URLError, OSError) as e:
        raise S3Error("cannot reach S3: %s" % getattr(e, "reason", e))
    root = parse_xml(body)
    return sorted(b.findtext(S3_NS + "Name") or "" for b in root.iter(S3_NS + "Bucket"))


# ---------------------------------------------------------------- check engine

def b64(hexstr):
    return base64.b64encode(bytes.fromhex(hexstr)).decode()


def etag_check(etag, entry):
    """True = the ETag proves the content, None = it cannot tell."""
    if "-" not in etag:
        return True if etag == entry["md5"] else None
    if etag.endswith("-1"):
        # Multipart upload with a single part: MD5 of the part MD5.
        return True if etag == hashlib.md5(bytes.fromhex(entry["md5"])).hexdigest() + "-1" else None
    if etag in entry.get("etags", {}).values():
        return True
    # A different value proves nothing by itself: another part size can give the same
    # part count, and with SSE-KMS/SSE-C the ETag is not an MD5 of the content.
    return None


def parts_are_uniform(s3, key, ps, n, size, max_parts=64):
    """True if parts 2..n have the sizes a uniform ps upload gives, False if not, None if too many to ask."""
    if n > max_parts:
        return None
    for i in range(2, n + 1):
        expected = ps if i < n else size - (n - 1) * ps
        if s3.head(key, part_number=i).get("ContentLength") != expected:
            return False
    return True


def head_check(s3, key, obj, entry, deep):
    """Settle a file whose ETag proved nothing. Return (status, detail, hints)."""
    try:
        head = s3.head(key)
    except S3Error as e:
        return "NO_ACCESS", "head-object failed: %s" % e, []
    sse = head.get("ServerSideEncryption")
    ssec = head.get("SSECustomerAlgorithm")
    ctype = head.get("ChecksumType")
    etag = obj["etag"]
    hints = []

    def full_object(value):
        if ctype:
            return ctype == "FULL_OBJECT"
        # No type given (older APIs, emulators): only a single-part upload is surely
        # full-object, a multipart checksum can be composite (checksum of the part checksums).
        return "-" not in value and "-" not in etag

    for field, local_key, status in (("ChecksumSHA256", "sha256", "OK_SHA256"),
                                     ("ChecksumCRC64NVME", "crc64nvme", "OK_CRC64NVME"),
                                     ("ChecksumCRC32", "crc32", "OK_CRC32")):
        value = head.get(field)
        if not value or not full_object(value):
            continue
        if local_key not in entry:
            if local_key == "crc64nvme":
                hints.append("crc64nvme")
            continue
        if value == b64(entry[local_key]):
            return status, "%s sse=%s" % (field, sse or "none"), []
        return "HASH_MISMATCH", "%s differs (S3 %s, local %s)" % (field, value, b64(entry[local_key])), []

    # The ETag is built from MD5s of the content only without KMS/SSE-C, and only on AWS
    # unless the user says the endpoint does the same.
    md5_etag = sse in (None, "AES256") and not ssec and getattr(s3, "trust_etags", True)
    if "-" not in etag and md5_etag:
        return "HASH_MISMATCH", "ETag is the MD5 for sse=%s and differs" % (sse or "none"), []
    if etag.endswith("-1") and md5_etag:
        return "HASH_MISMATCH", "single-part multipart ETag differs for sse=%s" % (sse or "none"), []

    checksums = [k for k in head if k.startswith("Checksum") and k != "ChecksumType"]
    detail = "sse=%s%s checksums=%s%s" % (sse or "none", " sse-c" if ssec else "",
                                          ",".join(checksums) or "none", " (%s)" % ctype if ctype else "")
    if not getattr(s3, "trust_etags", True) and sse in (None, "AES256"):
        detail += "; ETag differs, but this endpoint may not use MD5 ETags"
    tail = etag.rsplit("-", 1)[1] if "-" in etag else ""
    if etag.endswith("-1"):
        detail += "; single-part multipart ETag is not the MD5 (encryption)"
    elif deep and tail.isdigit():
        n = int(tail)
        try:
            ps = s3.head(key, part_number=1).get("ContentLength", 0)
            hashed = ps in [key_bytes(k) for k in entry.get("etags", {})]
            if not ps or ps >= entry["size"]:
                detail += "; part 1 size unknown"
            elif ps % MiB:
                detail += "; part 1 is %d bytes, not a whole MiB (use the local folder check)" % ps
            elif not hashed:
                detail += "; part size %d MiB, re-hash with --part-sizes %d" % (ps // MiB, ps // MiB)
                hints.append(("part", ps // MiB))
            elif md5_etag and math.ceil(entry["size"] / ps) == n:
                uniform = parts_are_uniform(s3, key, ps, n, entry["size"])
                if uniform:
                    return "HASH_MISMATCH", "multipart ETag with %d MiB parts differs for sse=%s" % (
                        ps // MiB, sse or "none"), []
                detail += ("; %d MiB first part but the other parts differ, cannot rebuild the ETag" if uniform is False
                           else "; %d MiB parts, too many parts to confirm the layout") % (ps // MiB)
            elif md5_etag:
                detail += "; %d MiB parts but not uniform (%d parts), cannot rebuild the ETag" % (ps // MiB, n)
            else:
                detail += "; part size %d MiB already hashed, ETag is not an MD5 (encryption)" % (ps // MiB)
        except S3Error as e:
            detail += "; part-number head failed: %s" % e
    if "crc64nvme" in hints:
        detail += "; S3 has CRC64NVME, re-hash with --crc64nvme"
    return "SIZE_ONLY", detail, hints


def normalize_prefix(prefix):
    prefix = (prefix or "").strip().lstrip("/")
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    return prefix


def split_s3_url(bucket, prefix):
    """Accept 's3://bucket/path' typed in the bucket field."""
    bucket = (bucket or "").strip()
    if bucket.startswith("s3://"):
        rest = bucket[5:]
        bucket, _, path = rest.partition("/")
        if path and not prefix:
            prefix = path
    return bucket, prefix


class CheckResult:
    def __init__(self, rows, hints, inventory, bucket, prefix, collisions):
        self.rows, self.hints, self.inv = rows, hints, inventory
        self.bucket, self.prefix, self.collisions = bucket, prefix, collisions
        self.recount()

    def recount(self):
        self.counts = {}
        for r in self.rows:
            self.counts[r[1]] = self.counts.get(r[1], 0) + 1

    @property
    def exit_code(self):
        if any(self.counts.get(s) for s in FAIL) or self.inv.read_errors:
            return 1
        return 2 if any(self.counts.get(s) for s in WARN) else 0

    def sorted_rows(self):
        rank = {s: i for i, s in enumerate(SEVERITY)}
        return sorted(self.rows, key=lambda r: (rank[r[1]], r[0]))

    def second_round(self):
        """Return (helpable_paths, flags, crc_count, unverified_count)."""
        unverified = sorted(r[0] for r in self.rows if r[1] == "SIZE_ONLY")
        part_files = {}
        for p in unverified:
            sizes = [h[1] for h in self.hints.get(p, []) if isinstance(h, tuple)]
            if sizes:
                part_files[p] = sizes
        crc_files = [p for p in unverified if p not in part_files and "crc64nvme" in self.hints.get(p, [])]
        flags = []
        sizes = sorted({s for v in part_files.values() for s in v})
        if sizes:
            flags.append("--part-sizes %s" % ",".join(map(str, sizes)))
        if crc_files:
            flags.append("--crc64nvme")
        return sorted(set(part_files) | set(crc_files)), flags, len(crc_files), len(unverified)

    def write_report(self, path):
        with open(path, "w", encoding="utf-8", errors="backslashreplace") as f:
            f.write("status\tpath\tlocal_size\ts3_size\tdetail\n")
            for r in self.sorted_rows():
                f.write("\t".join(tsv(x) for x in (r[1], r[0], r[2], r[3], r[4])) + "\n")

    def write_unverified(self, path):
        helpable = self.second_round()[0]
        with open(path, "w", encoding="utf-8") as f:
            for p in helpable:
                f.write(json.dumps(p) + "\n")
        return len(helpable)

    def summary_lines(self, deep, direct=False, unverified_list=None, limit=200, gui=False):
        out = ["", "=== Summary: s3://%s/%s ===" % (self.bucket, self.prefix)]
        for s in SEVERITY:
            if self.counts.get(s):
                out.append("%-17s %6d   %s" % (s, self.counts[s], STATUS_HELP[s]))
        total = sum(e["size"] for e in self.inv.entries.values())
        out.append("Local bytes:      %d (%.2f GiB)" % (total, total / 1024 ** 3))
        if self.inv.read_errors:
            out.append("")
            out.append("WARNING: %d local files could not be read:" % len(self.inv.read_errors))
            out.extend("  %s: %s" % kv for kv in sorted(self.inv.read_errors.items())[:50])
        if self.collisions:
            out.append("WARNING: %d S3 keys differ only by Unicode normalization, e.g. %r"
                       % (len(self.collisions), self.collisions[0]))
        if self.counts.get("MISSING") == len(self.inv.entries) and self.inv.headers:
            root = self.inv.headers[0][1].get("root")
            out.append("")
            out.append("HINT: nothing matched. Many upload tools keep the folder name, "
                       "try the path %s%s/" % (self.prefix, root))
        problems = [r for r in self.sorted_rows() if r[1] in FAIL | WARN]
        if problems:
            out.append("")
            out.append("=== Not verified (first %d of %d, worst first) ===" % (min(limit, len(problems)), len(problems)))
            for r in problems[:limit]:
                out.append("%-17s %s  local=%s s3=%s %s" % (r[1], r[0], r[2], r[3], r[4]))
        extras = [r for r in self.rows if r[1] == "EXTRA"]
        if extras:
            out.append("")
            out.append("=== EXTRA: in S3, not in the local list (first 20 of %d) ===" % len(extras))
            out.extend("  %s (%s bytes)" % (r[0], r[3]) for r in extras[:20])
        if self.counts.get("NO_ACCESS"):
            out.append("")
            out.append("NO_ACCESS: these credentials can list the bucket but not read the object metadata. "
                       "They need s3:GetObject, without it the content can't be checked.")
        helpable, flags, crc_count, unverified = self.second_round()
        if unverified:
            out.append("")
            out.append("NEXT: %d files have no hash proof, a second round can help %d of them." % (unverified, len(helpable)))
            if not deep and not direct:
                out.append("Turn on 'find the part sizes' under advanced options and check again." if gui
                           else "Run again with --deep: it finds the part sizes to hash.")
            if helpable and not direct and gui:
                out.append("Click 'Save list for second round...' and send the list to the uploader. They open "
                           "Create manifest, show the advanced options, choose the list under 'Only these files'%s, "
                           "and send you the new manifest. Then check again with both manifest files." % (
                               " and set " + ", ".join(flags).replace("--part-sizes ", "'Part sizes' to ")
                               .replace("--crc64nvme", "tick CRC64NVME") if flags else ""))
            elif helpable and not direct:
                target = unverified_list or "<list file>"
                if not unverified_list:
                    out.append("Save the list of these files (--unverified-list) and ask the uploader to run:")
                else:
                    out.append("Send %s to the uploader and ask them to run:" % unverified_list)
                out.append("  python3 s3_upload_verify.py manifest <dir> --only %s %s -o manifest-2.jsonl"
                           % (target, " ".join(flags)))
                if crc_count:
                    out.append("(--crc64nvme runs at %s, needed for %d of these files)" % (CRC64_SPEED, crc_count))
                out.append("Then check again with both --manifest files.")
            if len(helpable) < unverified:
                out.append("The other %d files: S3 has no usable hash for them (encryption and no full-object "
                           "checksum). Only the size is verified." % (unverified - len(helpable)))
        verdict = {0: "RESULT: all files verified.",
                   1: "RESULT: PROBLEMS FOUND (missing, different or corrupt files).",
                   2: "RESULT: no errors found, but some files are verified by size only."}[self.exit_code]
        out.append("")
        out.append(verdict)
        return out


def tsv(value):
    return str(value).replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def parallel(fn, items, workers, progress, cancel, label):
    """Run fn over items in threads, in order of completion. Cancel drops the queued calls."""
    results = []
    if not items:
        return results
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers))
    try:
        futures = {pool.submit(fn, item): item for item in items}
        for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            results.append((futures[fut], fut.result()))
            progress("head", i, len(items), "%s %d/%d" % (label, i, len(items)))
    finally:
        pool.shutdown(wait=False, cancel_futures=True) if sys.version_info >= (3, 9) else pool.shutdown(wait=False)
    return results


def s3_index(objs, prefix):
    s3_rel = {k[len(prefix):]: v for k, v in objs.items() if not k.endswith("/")}
    # macOS may give decomposed (NFD) names, many upload tools send composed (NFC).
    by_nfc = {}
    for k in s3_rel:
        by_nfc.setdefault(unicodedata.normalize("NFC", k), []).append(k)
    return s3_rel, by_nfc


def s3_key_for(path, s3_rel, by_nfc):
    if path in s3_rel:
        return path, ""
    alt = by_nfc.get(unicodedata.normalize("NFC", path), [])
    if len(alt) == 1:
        return alt[0], "unicode-normalized key"
    return None, ""


def settle(rows_pending, s3, prefix, deep, workers, progress, cancel, hints):
    """Run head_check for (row, key, obj, entry) items and write the outcome into the rows."""
    def run(item):
        row, key, obj, entry = item
        return head_check(s3, prefix + key, obj, entry, deep)
    for (row, _key, _obj, _entry), (status, detail, file_hints) in parallel(
            run, rows_pending, workers, progress, cancel, "head-object"):
        row[1] = status
        row[4] = (row[5] + "; " if row[5] else "") + detail
        hints.pop(row[0], None)
        if status == "SIZE_ONLY":
            hints[row[0]] = file_hints


def compare(inv, objs, s3, bucket, prefix, deep=False, workers=16, progress=noop_progress, cancel=None):
    s3_rel, by_nfc = s3_index(objs, prefix)
    collisions = [v for v in by_nfc.values() if len(v) > 1]

    rows, matched, pending = [], set(), []
    for path, entry in sorted(inv.entries.items()):
        key, note = s3_key_for(path, s3_rel, by_nfc)
        if key is None:
            rows.append([path, "MISSING", entry["size"], "", "", ""])
            continue
        obj = s3_rel[key]
        matched.add(key)
        if obj["size"] != entry["size"]:
            rows.append([path, "SIZE_MISMATCH", entry["size"], obj["size"], note, note])
            continue
        if etag_check(obj["etag"], entry):
            rows.append([path, "OK", entry["size"], obj["size"], "etag" + ("; " + note if note else ""), note])
            continue
        row = [path, "SIZE_ONLY", entry["size"], obj["size"], note, note]
        rows.append(row)
        pending.append((row, key, obj, entry))

    hints = {}
    settle(pending, s3, prefix, deep, workers, progress, cancel, hints)

    def under_symlink(path):
        if inv.skipped.get(path, {}).get("reason") in ("symlink", "symlink loop"):
            return True
        return any(path.startswith(p + "/") for p, r in inv.skipped.items()
                   if r.get("dir") and r.get("reason") in ("symlink", "symlink loop"))

    for path in sorted(set(s3_rel) - matched):
        if under_symlink(path):
            rows.append([path, "UNHASHED_SYMLINK", "", s3_rel[path]["size"], "uploaded but not hashed (symlink)", ""])
        else:
            rows.append([path, "EXTRA", "", s3_rel[path]["size"], "", ""])
    result = CheckResult(rows, hints, inv, bucket, prefix, collisions)
    result.s3_rel, result.by_nfc = s3_rel, by_nfc
    return result


def check_manifests(manifests, s3, bucket, prefix, deep=False, workers=16, progress=noop_progress, cancel=None):
    inv = load_manifests(manifests)
    progress("list", 0, 0, "Listing s3://%s/%s ..." % (bucket, prefix))
    objs = s3.list_objects(prefix, progress, cancel)
    progress("head", 0, 0, "Comparing ...")
    return compare(inv, objs, s3, bucket, prefix, deep, workers, progress, cancel)


def check_directory(root, s3, bucket, prefix, part_sizes, exclude_hidden=False, follow_symlinks=False,
                    auto_crc64=True, workers=16, manifest_out=None, progress=noop_progress, cancel=None):
    """Hash a local folder and compare it with S3 in one go. It asks S3 for the exact part
    size of each multipart object before hashing, so there is no second round."""
    progress("list", 0, 0, "Listing s3://%s/%s ..." % (bucket, prefix))
    objs = s3.list_objects(prefix, progress, cancel)
    progress("scan", 0, 0, "Scanning %s ..." % root)
    partial = manifest_out + ".partial" if manifest_out else None
    files, records = scan(root, exclude_hidden, follow_symlinks,
                          exclude_files=(manifest_out, partial) if manifest_out else (), cancel=cancel)
    total = sum(s for _, _, s in files)
    progress("scan", 0, 0, "Found %d local files, %s, and %d objects in S3." % (len(files), fmt_bytes(total), len(objs)))

    # Exact part size of each multipart object, from part 1.
    s3_rel, by_nfc = s3_index(objs, prefix)
    probes = []
    for _, rel, size in files:
        key, _ = s3_key_for(rel, s3_rel, by_nfc)
        etag = s3_rel[key]["etag"] if key else ""
        if key and s3_rel[key]["size"] == size and "-" in etag and not etag.endswith("-1"):
            probes.append((rel, prefix + key))

    def probe(item):
        try:
            return s3.head(item[1], part_number=1).get("ContentLength", 0)
        except S3Error:
            return 0
    extra_sizes = {rel: ps for (rel, _), ps in parallel(probe, probes, workers, progress, cancel, "part sizes")
                   if ps >= 5 * MiB}

    inv = Inventory()
    for r in records:
        inv.add(r)
    header = {"type": "header", "version": MANIFEST_VERSION, "tool": "s3-upload-verify " + __version__,
              "root": os.path.basename(os.path.abspath(root)),
              "created": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
              "files": 0, "bytes": total, "only": False,
              "part_sizes_mib": [ps // MiB for ps in part_sizes], "crc64nvme": False}
    inv.headers.append(("(local directory)", header))
    hashed = {}
    for rec in hash_files(files, part_sizes, extra_part_sizes=extra_sizes, progress=progress, cancel=cancel):
        inv.add(rec)
        hashed[rec["path"]] = rec
    result = compare(inv, objs, s3, bucket, prefix, True, workers, progress, cancel)

    crc_paths = {p for p, h in result.hints.items() if "crc64nvme" in h}
    if auto_crc64 and crc_paths:
        files2 = [f for f in files if f[1] in crc_paths]
        progress("scan", 0, 0, "Computing CRC64NVME for %d files (%s, %s) ..." % (
            len(files2), fmt_bytes(sum(s for _, _, s in files2)), CRC64_SPEED))
        for rec in hash_files(files2, part_sizes, with_crc64=True, extra_part_sizes=extra_sizes,
                              progress=progress, cancel=cancel):
            inv.add(rec)
            hashed[rec["path"]] = inv.entries.get(rec["path"], rec)
        # Only the re-hashed files need another look.
        redo = []
        for row in result.rows:
            if row[0] in crc_paths and row[0] in inv.entries:
                key, _ = s3_key_for(row[0], result.s3_rel, result.by_nfc)
                redo.append((row, key, result.s3_rel[key], inv.entries[row[0]]))
        settle(redo, s3, prefix, True, workers, progress, cancel, result.hints)
        result.recount()
        header["crc64nvme"] = True

    if manifest_out:
        out = [r for r in records if r["type"] != "error"] + list(hashed.values())
        out += [{"type": "error", "path": p, "error": e} for p, e in sorted(inv.read_errors.items())]
        n_files = sum(1 for r in out if r["type"] == "file")
        n_err = sum(1 for r in out if r["type"] == "error")
        with open(partial, "w", encoding="utf-8") as f:
            f.write(json.dumps(dict(header, files=n_files + n_err)) + "\n")
            for r in out:
                f.write(json.dumps(r) + "\n")
            f.write(json.dumps({"type": "end", "files": n_files, "errors": n_err}) + "\n")
        os.replace(partial, manifest_out)
    return result


# ---------------------------------------------------------------- command line

def cli_progress(phase, done, total, text):
    if phase in ("hash", "scan", "list") or (phase == "head" and total and (done == total or done % 200 == 0)):
        if phase == "hash" and total:
            text = "%5.1f%% %s" % (100.0 * done / total, text)
        print(text, file=sys.stderr)


def make_client(args):
    bucket, prefix = split_s3_url(args.bucket, args.prefix)
    creds, profile_region = resolve_credentials(args.profile)
    s3 = S3Client(bucket, creds, region=args.region, endpoint=args.endpoint, region_hint=profile_region,
                  trust_etags=True if args.trust_endpoint_etags else None)
    return s3, bucket, normalize_prefix(prefix)


def cmd_manifest(args):
    try:
        part_sizes = parse_part_sizes(args.part_sizes)
    except ValueError as e:
        sys.exit("ERROR: %s" % e)
    if not os.path.isdir(args.directory):
        sys.exit("ERROR: %s is not a directory" % args.directory)
    if args.crc64nvme:
        print("WARNING: --crc64nvme runs at %s." % CRC64_SPEED, file=sys.stderr)
    try:
        only = read_path_list(args.only) if args.only else None
        written, errors = write_manifest(args.directory, args.output, part_sizes, args.exclude_hidden,
                                         args.follow_symlinks, only, args.crc64nvme, cli_progress)
    except OSError as e:
        sys.exit("ERROR: %s" % e)
    print("\nDone: %d files, %d errors." % (written, errors), file=sys.stderr)
    print("Send this file back: %s" % os.path.abspath(args.output), file=sys.stderr)
    return 1 if errors else 0


def cmd_check(args):
    if bool(args.manifest) == bool(args.dir):
        sys.exit("ERROR: give either --manifest (one or more) or --dir")
    try:
        s3, bucket, prefix = make_client(args)
        print("Target: s3://%s/%s (region %s)" % (bucket, prefix, s3.region), file=sys.stderr)
        if args.manifest:
            result = check_manifests(args.manifest, s3, bucket, prefix, args.deep, args.workers, cli_progress)
        else:
            result = check_directory(args.dir, s3, bucket, prefix, parse_part_sizes(args.part_sizes),
                                     args.exclude_hidden, args.follow_symlinks, not args.no_crc64nvme,
                                     args.workers, args.save_manifest, cli_progress)
    except (S3Error, ValueError, OSError) as e:
        sys.exit("ERROR: %s" % e)
    try:
        if args.unverified_list:
            result.write_unverified(args.unverified_list)
        for line in result.summary_lines(args.deep, bool(args.dir), args.unverified_list):
            print(line)
        if args.report:
            result.write_report(args.report)
            print("Report: %s" % args.report)
    except OSError as e:
        sys.exit("ERROR: %s" % e)
    return result.exit_code


def build_parser():
    ap = argparse.ArgumentParser(prog="s3_upload_verify.py",
                                 description="Check that a local directory arrived intact in Amazon S3. "
                                             "Run with no arguments to open the window.")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd")

    m = sub.add_parser("manifest", help="write a size/hash manifest of a directory (no S3 access needed)")
    m.add_argument("directory")
    m.add_argument("-o", "--output", default="manifest.jsonl", help="output file (default: manifest.jsonl)")
    m.add_argument("--part-sizes", default=",".join(map(str, DEFAULT_PART_SIZES_MIB)),
                   help="multipart part sizes in MiB (default: %(default)s)")
    m.add_argument("--exclude-hidden", action="store_true", help="skip dot files and dot directories")
    m.add_argument("--follow-symlinks", action="store_true", help="hash the targets of symbolic links")
    m.add_argument("--only", help="hash only the paths listed in this file (from check --unverified-list)")
    m.add_argument("--crc64nvme", action="store_true", help="also compute CRC64NVME (slow, use with --only)")

    c = sub.add_parser("check", help="compare a manifest or a local directory with S3 (read-only)")
    c.add_argument("--manifest", action="append", help="manifest file, repeat it to add second-round manifests")
    c.add_argument("--dir", help="local directory: hash it and compare directly (needs S3 access)")
    c.add_argument("--bucket", required=True, help="bucket name, or s3://bucket/path")
    c.add_argument("--prefix", default="", help="path inside the bucket that matches the directory")
    c.add_argument("--profile", help="AWS profile (default: env vars, then AWS_PROFILE, then 'default')")
    c.add_argument("--region", help="bucket region (default: found automatically)")
    c.add_argument("--endpoint", help="custom S3 endpoint URL (S3-compatible storage)")
    c.add_argument("--trust-endpoint-etags", action="store_true",
                   help="with --endpoint: the storage uses MD5 ETags like AWS, so a different ETag means different content")
    c.add_argument("--deep", action="store_true", help="find the part size of unverifiable multipart objects")
    c.add_argument("--workers", type=int, default=16, help="parallel S3 requests (default: 16)")
    c.add_argument("--report", help="write the per-file result as TSV")
    c.add_argument("--unverified-list", help="write the paths a second manifest round can verify")
    c.add_argument("--part-sizes", default=",".join(map(str, DEFAULT_PART_SIZES_MIB)), help="with --dir")
    c.add_argument("--exclude-hidden", action="store_true", help="with --dir")
    c.add_argument("--follow-symlinks", action="store_true", help="with --dir")
    c.add_argument("--no-crc64nvme", action="store_true", help="with --dir: never compute the slow CRC64NVME")
    c.add_argument("--save-manifest", help="with --dir: also write the manifest to this file")
    return ap


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    if not argv:
        return run_gui()
    args = build_parser().parse_args(argv)
    if args.cmd == "manifest":
        return cmd_manifest(args)
    if args.cmd == "check":
        return cmd_check(args)
    build_parser().print_help()
    return 1


# ---------------------------------------------------------------- window

def run_gui():
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        print("The window needs tkinter, which this Python does not have.\n"
              "On macOS with Homebrew: brew install python-tk. On Debian/Ubuntu: apt install python3-tk.\n"
              "Or use the command line: python3 s3_upload_verify.py --help", file=sys.stderr)
        return 1

    root = tk.Tk()
    root.title("S3 upload verify %s" % __version__)
    # Tk uses a fixed Treeview row height, I size it from the font so scaled screens don't cut the text.
    import tkinter.font as tkfont
    line = tkfont.nametofont("TkDefaultFont").metrics("linespace")
    ttk.Style(root).configure("Treeview", rowheight=int(line * 1.4))
    root.minsize(760, 620)
    events = queue.Queue()
    state = {"cancel": None, "result": None, "busy": False}

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=8, pady=8)

    def row(parent, r, label, var, browse=None, show=None, width=60):
        ttk.Label(parent, text=label).grid(row=r, column=0, sticky="w", padx=4, pady=3)
        e = ttk.Entry(parent, textvariable=var, width=width, show=show)
        e.grid(row=r, column=1, sticky="we", padx=4, pady=3)
        if browse:
            ttk.Button(parent, text="Browse...", command=browse).grid(row=r, column=2, padx=4, pady=3)
        return e

    def collapsible(parent, r, frame):
        """Hide frame behind a show/hide button placed at row r."""
        shown = tk.BooleanVar(value=False)
        btn = ttk.Button(parent, style="Toolbutton")

        def refresh():
            if shown.get():
                frame.grid()
                btn.configure(text="Hide advanced options \u25be")
            else:
                frame.grid_remove()
                btn.configure(text="Show advanced options \u25b8")
        btn.configure(command=lambda: (shown.set(not shown.get()), refresh()))
        btn.grid(row=r, column=0, columnspan=3, sticky="w", pady=(6, 0))
        root.after_idle(refresh)

    # ---- tab 1: create manifest
    t1 = ttk.Frame(nb, padding=8)
    nb.add(t1, text="Create manifest")
    t1.columnconfigure(1, weight=1)
    m_dir, m_out = tk.StringVar(), tk.StringVar(value=os.path.join(os.path.expanduser("~"), "manifest.jsonl"))
    m_parts = tk.StringVar(value=",".join(map(str, DEFAULT_PART_SIZES_MIB)))
    m_only = tk.StringVar()
    m_hidden, m_links, m_crc = tk.BooleanVar(), tk.BooleanVar(), tk.BooleanVar()
    ttk.Label(t1, text="Lists every file in a folder with its size and hashes. No S3 access needed.\n"
                       "Send the resulting file to the person who checks the bucket.",
              foreground="#555").grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 6))
    row(t1, 1, "Folder with the data:", m_dir, lambda: m_dir.set(filedialog.askdirectory() or m_dir.get()))
    row(t1, 2, "Save manifest as:", m_out, lambda: m_out.set(filedialog.asksaveasfilename(
        defaultextension=".jsonl", initialfile="manifest.jsonl") or m_out.get()))
    adv1 = ttk.LabelFrame(t1, text="Advanced (only if you were asked to)", padding=6)
    adv1.grid(row=4, column=0, columnspan=3, sticky="we", pady=6)
    collapsible(t1, 3, adv1)
    adv1.columnconfigure(1, weight=1)
    row(adv1, 0, "Part sizes (MiB):", m_parts, width=30)
    row(adv1, 1, "Only these files (list):", m_only, lambda: m_only.set(filedialog.askopenfilename() or m_only.get()))
    ttk.Checkbutton(adv1, text="Skip hidden files", variable=m_hidden).grid(row=2, column=0, sticky="w")
    ttk.Checkbutton(adv1, text="Follow symbolic links", variable=m_links).grid(row=2, column=1, sticky="w")
    ttk.Checkbutton(adv1, text="CRC64NVME (slow, %s)" % CRC64_SPEED, variable=m_crc).grid(row=3, column=0, columnspan=2, sticky="w")

    # ---- tab 2: check against S3
    t2 = ttk.Frame(nb, padding=8)
    nb.add(t2, text="Check against S3")
    t2.columnconfigure(1, weight=1)
    c_mode = tk.StringVar(value="dir")
    c_dir, c_manifests = tk.StringVar(), tk.StringVar()
    c_bucket, c_prefix, c_region, c_endpoint = tk.StringVar(), tk.StringVar(), tk.StringVar(), tk.StringVar()
    c_cred = tk.StringVar(value="keys")
    profiles = list_profiles()
    c_profile = tk.StringVar(value=profiles[0] if profiles else "")
    c_key, c_secret, c_token = tk.StringVar(), tk.StringVar(), tk.StringVar()
    c_deep = tk.BooleanVar(value=True)
    c_crc = tk.BooleanVar(value=True)
    c_save = tk.StringVar()

    src = ttk.LabelFrame(t2, text="What to check", padding=6)
    src.grid(row=0, column=0, columnspan=3, sticky="we")
    src.columnconfigure(1, weight=1)
    ttk.Radiobutton(src, text="Local folder (hash it now)", variable=c_mode, value="dir").grid(row=0, column=0, sticky="w")
    ttk.Entry(src, textvariable=c_dir).grid(row=0, column=1, sticky="we", padx=4)
    ttk.Button(src, text="Browse...", command=lambda: c_dir.set(filedialog.askdirectory() or c_dir.get())).grid(row=0, column=2)
    ttk.Radiobutton(src, text="Manifest file(s)", variable=c_mode, value="manifest").grid(row=1, column=0, sticky="w")
    ttk.Entry(src, textvariable=c_manifests).grid(row=1, column=1, sticky="we", padx=4)

    def pick_manifests():
        names = filedialog.askopenfilenames(filetypes=[("Manifest", "*.jsonl"), ("All files", "*")])
        if names:
            c_manifests.set(json.dumps(list(names)) if len(names) > 1 else names[0])
    ttk.Button(src, text="Browse...", command=pick_manifests).grid(row=1, column=2)

    cr = ttk.LabelFrame(t2, text="S3 credentials (read access is enough, they are only sent to S3)", padding=6)
    cr.grid(row=1, column=0, columnspan=3, sticky="we", pady=6)
    cr.columnconfigure(1, weight=1)
    ttk.Radiobutton(cr, text="Access key", variable=c_cred, value="keys").grid(row=0, column=0, sticky="w")
    row(cr, 1, "  Access key ID:", c_key)
    row(cr, 2, "  Secret access key:", c_secret, show="*")
    row(cr, 3, "  Session token (optional):", c_token, show="*")
    ttk.Radiobutton(cr, text="AWS profile", variable=c_cred, value="profile").grid(row=4, column=0, sticky="w")
    ttk.Combobox(cr, textvariable=c_profile, values=profiles).grid(row=4, column=1, sticky="w", padx=4)
    if profiles:
        c_cred.set("profile")

    dst = ttk.LabelFrame(t2, text="Where it was uploaded", padding=6)
    dst.grid(row=2, column=0, columnspan=3, sticky="we")
    dst.columnconfigure(1, weight=1)
    ttk.Label(dst, text="Bucket:").grid(row=0, column=0, sticky="w", padx=4, pady=3)
    bucket_box = ttk.Combobox(dst, textvariable=c_bucket)
    bucket_box.grid(row=0, column=1, sticky="we", padx=4, pady=3)
    load_btn = ttk.Button(dst, text="Load buckets")
    load_btn.grid(row=0, column=2, padx=4, pady=3)
    ttk.Label(dst, text="Path in the bucket:").grid(row=1, column=0, sticky="w", padx=4, pady=3)
    ttk.Entry(dst, textvariable=c_prefix).grid(row=1, column=1, sticky="we", padx=4, pady=3)
    browse_btn = ttk.Button(dst, text="Browse...")
    browse_btn.grid(row=1, column=2, padx=4, pady=3)
    ttk.Label(dst, text="Type the bucket if it is not listed (s3://bucket/path also works). Many upload tools "
                        "add the folder name, e.g. uploads/MyFolder/", foreground="#555",
              wraplength=620).grid(row=2, column=1, columnspan=2, sticky="w")

    adv2 = ttk.LabelFrame(t2, text="Advanced", padding=6)
    adv2.grid(row=4, column=0, columnspan=3, sticky="we", pady=6)
    collapsible(t2, 3, adv2)
    adv2.columnconfigure(1, weight=1)
    row(adv2, 0, "Region (blank = automatic):", c_region, width=20)
    row(adv2, 1, "Endpoint (S3-compatible only):", c_endpoint, width=40)
    row(adv2, 2, "Also save manifest (local folder):", c_save, lambda: c_save.set(
        filedialog.asksaveasfilename(defaultextension=".jsonl", initialfile="manifest.jsonl") or c_save.get()))
    ttk.Checkbutton(adv2, text="Manifest check: find the part sizes of unverified files",
                    variable=c_deep).grid(row=3, column=0, columnspan=3, sticky="w")
    ttk.Checkbutton(adv2, text="Local folder check: compute CRC64NVME when it is the only proof (slow)",
                    variable=c_crc).grid(row=4, column=0, columnspan=3, sticky="w")

    clients, clients_lock = {}, threading.Lock()

    resolved = {}

    def connection():
        """Read the credential and endpoint fields (main thread only). Resolving happens later, in a worker."""
        if c_cred.get() == "keys":
            if not (c_key.get().strip() and c_secret.get().strip()):
                raise ValueError("type the access key ID and the secret access key")
            req = ("keys", c_key.get().strip(), c_secret.get().strip(), c_token.get().strip())
        else:
            req = ("profile", c_profile.get().strip() or None)
        return req, c_endpoint.get().strip() or None, c_region.get().strip() or None

    def resolve(req):
        """Credentials for a connection() request, cached because SSO profiles run a slow command."""
        with clients_lock:
            if req in resolved:
                return resolved[req]
        if req[0] == "keys":
            out = resolve_credentials(access_key=req[1], secret_key=req[2], token=req[3])
        else:
            out = resolve_credentials(profile=req[1])
        with clients_lock:
            resolved[req] = out
        return out

    def client_for(bucket, conn):
        """S3Client per bucket, built in a worker thread because it can look up the region."""
        req, endpoint, region = conn
        key = (bucket, req, endpoint, region)
        with clients_lock:
            if key in clients:
                return clients[key]
        creds, profile_region = resolve(req)
        s3 = S3Client(bucket, creds, region=region, endpoint=endpoint, region_hint=profile_region)
        with clients_lock:
            clients[key] = s3
        return s3

    def in_background(fn, on_ok, on_err):
        def run():
            try:
                events.put(("call", on_ok, fn()))
            except Exception as e:  # shown to the user by on_err
                events.put(("call", on_err, e))
        threading.Thread(target=run, daemon=True).start()

    def load_buckets():
        try:
            conn = connection()
        except ValueError as e:
            messagebox.showerror("Credentials", str(e))
            return
        load_btn.configure(state="disabled", text="Loading...")

        def ok(names):
            load_btn.configure(state="normal", text="Load buckets")
            bucket_box.configure(values=names)
            status.set("%d buckets found." % len(names))
            if names and not c_bucket.get():
                c_bucket.set(names[0])
            if names:
                bucket_box.event_generate("<Down>")

        def err(e):
            load_btn.configure(state="normal", text="Load buckets")
            messagebox.showwarning("Buckets", "Cannot list the buckets: %s\n\nThese credentials may not be "
                                   "allowed to list all buckets. Type the bucket name instead." % e)
        in_background(lambda: list_buckets(resolve(conn[0])[0], conn[1]), ok, err)

    def browse_s3():
        bucket, typed_prefix = split_s3_url(c_bucket.get(), c_prefix.get())
        if not bucket:
            messagebox.showerror("Browse", "Choose or type a bucket first.")
            return
        try:
            conn = connection()
        except ValueError as e:
            messagebox.showerror("Credentials", str(e))
            return
        top = tk.Toplevel(root)
        top.title("s3://%s" % bucket)
        top.geometry("640x460")
        top.transient(root)
        frame = ttk.Frame(top, padding=6)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=("info",), selectmode="browse")
        tree.heading("#0", text="Folder")
        tree.heading("info", text="Files here")
        tree.column("info", width=tkfont.Font(font="TkDefaultFont").measure("Files here ") + 20,
                    anchor="e", stretch=False)
        sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        info = tk.StringVar(value="Loading ...")
        ttk.Label(top, textvariable=info, padding=(6, 0)).pack(fill="x")
        bar2 = ttk.Frame(top, padding=6)
        bar2.pack(fill="x")
        prefixes = {}   # tree item -> prefix
        loaded = set()

        def add_node(parent, prefix, label):
            iid = tree.insert(parent, "end", text=label, values=("",))
            prefixes[iid] = prefix
            tree.insert(iid, "end", text="loading ...")  # placeholder so the node can open
            return iid

        def load(iid):
            if iid in loaded:
                return
            loaded.add(iid)
            prefix = prefixes[iid]
            info.set("Listing s3://%s/%s ..." % (bucket, prefix))

            def ok(res):
                folders, n_objects, truncated = res
                if not tree.exists(iid):
                    return
                tree.delete(*tree.get_children(iid))
                for f in folders:
                    name = f[len(prefix):]
                    add_node(iid, f, name if name != "/" else "(no name)/")
                tree.set(iid, "info", "%d%s" % (n_objects, "+" if truncated else ""))
                info.set("s3://%s/%s: %d folders, %d files%s" % (
                    bucket, prefix, len(folders), n_objects, " (more not shown)" if truncated else ""))

            def err(e):
                loaded.discard(iid)
                info.set("Error: %s" % e)
            in_background(lambda: client_for(bucket, conn).list_folders(prefix), ok, err)

        def on_open(_event):
            iid = tree.focus()
            if iid:
                load(iid)

        def choose(_event=None):
            sel = tree.selection()
            if sel:
                c_prefix.set(prefixes[sel[0]])
                if c_bucket.get().startswith("s3://"):
                    c_bucket.set(bucket)
                top.destroy()

        tree.bind("<<TreeviewOpen>>", on_open)
        ttk.Button(bar2, text="Use this path", command=choose).pack(side="right")
        ttk.Button(bar2, text="Cancel", command=top.destroy).pack(side="right", padx=6)
        root_iid = add_node("", "", bucket + "/")
        tree.item(root_iid, open=True)
        tree.selection_set(root_iid)
        tree.focus(root_iid)
        load(root_iid)
        if typed_prefix:
            info.set("Current path: %s" % typed_prefix)

    load_btn.configure(command=load_buckets)
    browse_btn.configure(command=browse_s3)

    # ---- shared bottom: buttons, progress, output
    bottom = ttk.Frame(root, padding=(8, 0, 8, 8))
    bottom.pack(fill="both", expand=True)
    btns = ttk.Frame(bottom)
    btns.pack(fill="x")
    run_btn = ttk.Button(btns, text="Start")
    cancel_btn = ttk.Button(btns, text="Cancel", state="disabled")
    report_btn = ttk.Button(btns, text="Save report...", state="disabled")
    unv_btn = ttk.Button(btns, text="Save list for second round...", state="disabled")
    for b in (run_btn, cancel_btn, report_btn, unv_btn):
        b.pack(side="left", padx=(0, 6))
    bar = ttk.Progressbar(bottom, mode="determinate", maximum=1000)
    bar.pack(fill="x", pady=4)
    status = tk.StringVar(value="Ready.")
    ttk.Label(bottom, textvariable=status).pack(fill="x")
    out_frame = ttk.Frame(bottom)
    out_frame.pack(fill="both", expand=True, pady=(4, 0))
    text = tk.Text(out_frame, height=14, wrap="none", font=("TkFixedFont", 9))
    ys = ttk.Scrollbar(out_frame, orient="vertical", command=text.yview)
    xs = ttk.Scrollbar(out_frame, orient="horizontal", command=text.xview)
    text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
    ys.pack(side="right", fill="y")
    xs.pack(side="bottom", fill="x")
    text.pack(side="left", fill="both", expand=True)

    def log(line):
        text.insert("end", line + "\n")
        text.see("end")

    def set_busy(busy):
        state["busy"] = busy
        run_btn.configure(state="disabled" if busy else "normal")
        cancel_btn.configure(state="normal" if busy else "disabled")

    def progress(phase, done, total, msg):
        events.put(("progress", phase, done, total, msg))

    def worker(fn):
        try:
            events.put(("done", fn()))
        except Cancelled:
            events.put(("error", "Cancelled."))
        except (S3Error, ValueError, OSError) as e:
            events.put(("error", "ERROR: %s" % e))
        except Exception as e:  # keep the window alive and show what happened
            events.put(("error", "UNEXPECTED ERROR: %r" % e))

    def start():
        if state["busy"]:
            return
        text.delete("1.0", "end")
        state["result"] = None
        report_btn.configure(state="disabled")
        unv_btn.configure(state="disabled")
        cancel = threading.Event()
        state["cancel"] = cancel
        try:
            if nb.index(nb.select()) == 0:
                fn = start_manifest(cancel)
            else:
                fn = start_check(cancel)
        except (S3Error, ValueError, OSError) as e:
            messagebox.showerror("Cannot start", str(e))
            return
        set_busy(True)
        threading.Thread(target=worker, args=(fn,), daemon=True).start()

    def start_manifest(cancel):
        folder, out = m_dir.get().strip(), m_out.get().strip()
        if not os.path.isdir(folder):
            raise ValueError("choose the folder with the data")
        if not out:
            raise ValueError("choose where to save the manifest")
        parts = parse_part_sizes(m_parts.get())
        only = read_path_list(m_only.get().strip()) if m_only.get().strip() else None
        hidden, links, crc = m_hidden.get(), m_links.get(), m_crc.get()
        log("Creating manifest of %s" % folder)

        def fn():
            written, errors = write_manifest(folder, out, parts, hidden, links, only, crc, progress, cancel)
            return ("manifest", written, errors, out)
        return fn

    def start_check(cancel):
        bucket, prefix = split_s3_url(c_bucket.get(), c_prefix.get())
        if not bucket:
            raise ValueError("type the bucket name")
        prefix = normalize_prefix(prefix)
        conn = connection()
        mode = c_mode.get()
        if mode == "dir":
            folder = c_dir.get().strip()
            if not os.path.isdir(folder):
                raise ValueError("choose the local folder with the data")
        else:
            raw = c_manifests.get().strip()
            manifests = json.loads(raw) if raw.startswith("[") else [raw]
            if not raw or not all(os.path.isfile(p) for p in manifests):
                raise ValueError("choose the manifest file(s)")
        deep, auto_crc, save = c_deep.get(), c_crc.get(), c_save.get().strip() or None
        log("Checking s3://%s/%s" % (bucket, prefix))

        def fn():
            progress("scan", 0, 0, "Connecting ...")
            s3 = client_for(bucket, conn)
            progress("scan", 0, 0, "Bucket region: %s" % s3.region)
            if mode == "dir":
                result = check_directory(folder, s3, bucket, prefix, parse_part_sizes(",".join(
                    map(str, DEFAULT_PART_SIZES_MIB))), auto_crc64=auto_crc, manifest_out=save,
                    progress=progress, cancel=cancel)
            else:
                result = check_manifests(manifests, s3, bucket, prefix, deep, progress=progress, cancel=cancel)
            return ("check", result, mode == "dir", deep)
        return fn

    def cancel_run():
        if state["cancel"] is not None:
            state["cancel"].set()
            status.set("Cancelling ...")

    def save_report():
        path = filedialog.asksaveasfilename(defaultextension=".tsv", initialfile="s3-check-report.tsv")
        if path and state["result"]:
            try:
                state["result"].write_report(path)
                log("Report saved: %s" % path)
            except OSError as e:
                messagebox.showerror("Save report", str(e))

    def save_unverified():
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="unverified.txt")
        if path and state["result"]:
            try:
                n = state["result"].write_unverified(path)
                log("Saved %d paths to %s" % (n, path))
            except OSError as e:
                messagebox.showerror("Save list", str(e))

    last_log = {"t": 0.0}

    def poll():
        try:
            while True:
                ev = events.get_nowait()
                if ev[0] == "call":
                    ev[1](ev[2])
                elif ev[0] == "progress":
                    _, phase, done, total, msg = ev
                    status.set(msg)
                    if total:
                        bar.configure(mode="determinate", value=1000.0 * done / total)
                    if phase in ("scan", "list") and (time.time() - last_log["t"] > 0.5 or phase == "scan"):
                        log(msg)
                        last_log["t"] = time.time()
                elif ev[0] == "error":
                    set_busy(False)
                    log(ev[1])
                    status.set(ev[1])
                elif ev[0] == "done":
                    set_busy(False)
                    bar.configure(value=1000)
                    res = ev[1]
                    if res[0] == "manifest":
                        _, written, errors, out = res
                        log("Done: %d files, %d errors." % (written, errors))
                        log("Send this file: %s" % os.path.abspath(out))
                        status.set("Manifest written: %s" % out)
                        if errors:
                            messagebox.showwarning("Manifest", "%d files could not be read. They are listed in the "
                                                   "manifest. Send it anyway." % errors)
                    else:
                        _, result, direct, deep = res
                        state["result"] = result
                        for line in result.summary_lines(deep, direct, gui=True):
                            log(line)
                        report_btn.configure(state="normal")
                        if result.second_round()[0]:
                            unv_btn.configure(state="normal")
                        status.set(result.summary_lines(deep, direct, gui=True)[-1])
        except queue.Empty:
            pass
        root.after(100, poll)

    run_btn.configure(command=start)
    cancel_btn.configure(command=cancel_run)
    report_btn.configure(command=save_report)
    unv_btn.configure(command=save_unverified)
    root.after(100, poll)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
