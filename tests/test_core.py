import base64
import datetime
import hashlib
import json
import os
import sys
import unicodedata

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import s3_upload_verify as v  # noqa: E402

MiB = v.MiB


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def multipart_etag(data, ps):
    digests = [hashlib.md5(data[i:i + ps]).digest() for i in range(0, len(data), ps)]
    return hashlib.md5(b"".join(digests)).hexdigest() + "-%d" % len(digests)


def b64crc32(data):
    import zlib
    return base64.b64encode((zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, "big")).decode()


def b64crc64(data):
    c = v.crc64nvme_update(0xFFFFFFFFFFFFFFFF, data) ^ 0xFFFFFFFFFFFFFFFF
    return base64.b64encode(c.to_bytes(8, "big")).decode()


class FakeS3:
    """In-memory stand-in for S3Client: objects[key] = dict(size, etag, head={...}, part1=int)."""

    def __init__(self, objects, trust_etags=True):
        self.objects = objects
        self.trust_etags = trust_etags

    def list_objects(self, prefix, progress=None, cancel=None):
        return {k: {"size": o["size"], "etag": o["etag"]} for k, o in self.objects.items() if k.startswith(prefix)}

    def head(self, key, part_number=None):
        o = self.objects[key]
        if o.get("denied"):
            raise v.S3Error("HTTP 403 AccessDenied")
        if part_number:
            parts = o.get("parts")
            if parts is None and o.get("part1"):
                ps = o["part1"]
                n = -(-o["size"] // ps)
                parts = [ps] * (n - 1) + [o["size"] - (n - 1) * ps]
            parts = parts or []
            return {"ContentLength": parts[part_number - 1] if part_number <= len(parts) else 0}
        return dict(o.get("head", {}), ContentLength=o["size"])


# ---------------------------------------------------------------- hashing

def test_crc64nvme_check_value():
    assert v.crc64nvme_update(0xFFFFFFFFFFFFFFFF, b"123456789") ^ 0xFFFFFFFFFFFFFFFF == 0xAE8B14860A799888


def test_multipart_etag_matches_reference(tmp_path):
    data = os.urandom(20 * MiB + 123)
    p = tmp_path / "f"
    p.write_bytes(data)
    rec = v.hash_file(str(p), [5 * MiB, 8 * MiB, 10 * MiB])
    assert rec["md5"] == hashlib.md5(data).hexdigest()
    for ps in (5, 8, 10):
        assert rec["etags"][str(ps)] == multipart_etag(data, ps * MiB)


def test_exact_multiple_of_part_size(tmp_path):
    data = os.urandom(16 * MiB)
    p = tmp_path / "f"
    p.write_bytes(data)
    assert v.hash_file(str(p), [8 * MiB])["etags"]["8"] == multipart_etag(data, 8 * MiB)


def test_aws_cli_part_size_scaling():
    assert v.aws_cli_part_size(8 * MiB * 10000) == 8 * MiB
    assert v.aws_cli_part_size(8 * MiB * 10000 + 1) == 16 * MiB
    assert v.aws_cli_part_size(100 * 1024 ** 3) == 16 * MiB


def test_part_sizes_validation():
    for bad in ("0", "abc", "4", "6000", ""):
        with pytest.raises(ValueError):
            v.parse_part_sizes(bad)
    assert v.parse_part_sizes("8,5,8") == [5 * MiB, 8 * MiB]


# ---------------------------------------------------------------- signing

def test_sigv4_aws_documented_example():
    # "Example: GET Object" from the S3 SigV4 header-based auth documentation.
    now = datetime.datetime(2013, 5, 24, tzinfo=datetime.timezone.utc)
    creds = v.Credentials("AKIA" + "IOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    h = v.sigv4_headers("GET", "https://examplebucket.s3.amazonaws.com/test.txt", "us-east-1", creds,
                        {"Range": "bytes=0-9"}, now)
    assert h["authorization"].endswith("Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")


# ---------------------------------------------------------------- manifest

def make_tree(root):
    write(os.path.join(root, "a.txt"), b"hola\n")
    write(os.path.join(root, "sub", "b.bin"), os.urandom(3000))
    write(os.path.join(root, ".hid", "s"), b"s")
    write(os.path.join(root, ".DS_Store"), b"junk")


def test_manifest_roundtrip_and_hidden(tmp_path):
    make_tree(str(tmp_path / "d"))
    out = str(tmp_path / "m.jsonl")
    written, errors = v.write_manifest(str(tmp_path / "d"), out, v.parse_part_sizes("5,8"))
    assert (written, errors) == (3, 0)
    inv = v.load_manifests([out])
    assert set(inv.entries) == {"a.txt", "sub/b.bin", ".hid/s"}
    assert not os.path.exists(out + ".partial")


def test_truncated_manifest_rejected(tmp_path):
    make_tree(str(tmp_path / "d"))
    out = str(tmp_path / "m.jsonl")
    v.write_manifest(str(tmp_path / "d"), out, v.parse_part_sizes("5"))
    lines = open(out).read().splitlines()
    cut = tmp_path / "cut.jsonl"
    cut.write_text("\n".join(lines[:-2]) + "\n")
    with pytest.raises(ValueError, match="no end record"):
        v.load_manifests([str(cut)])
    cut.write_text("\n".join(lines[:-1]) + '\n{"type": "end", "fil')
    with pytest.raises(ValueError, match="not valid JSON"):
        v.load_manifests([str(cut)])


def test_only_manifest_alone_rejected(tmp_path):
    make_tree(str(tmp_path / "d"))
    lst = tmp_path / "only.txt"
    lst.write_text("a.txt\r\n")
    out = str(tmp_path / "m2.jsonl")
    v.write_manifest(str(tmp_path / "d"), out, v.parse_part_sizes("5"), only=v.read_path_list(str(lst)))
    with pytest.raises(ValueError, match="only --only"):
        v.load_manifests([out])


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0), reason="needs POSIX non-root")
def test_unreadable_directory_is_an_error(tmp_path):
    d = tmp_path / "d"
    write(str(d / "ok"), b"z")
    write(str(d / "locked" / "f"), b"z")
    os.chmod(str(d / "locked"), 0)
    try:
        written, errors = v.write_manifest(str(d), str(tmp_path / "m.jsonl"), v.parse_part_sizes("5"))
    finally:
        os.chmod(str(d / "locked"), 0o755)
    assert (written, errors) == (1, 1)


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_symlinks(tmp_path):
    d = tmp_path / "d"
    write(str(d / "real" / "f.bin"), b"q")
    os.makedirs(str(d / "a"))
    os.symlink("../real", str(d / "a" / "l1"))
    os.symlink("real", str(d / "l2"))
    os.symlink("..", str(d / "real" / "loop"))
    files, records = v.scan(str(d))
    assert [f[1] for f in files] == ["real/f.bin"]
    assert {r["path"] for r in records if r["reason"] == "symlink"} == {"a/l1", "l2", "real/loop"}
    files, records = v.scan(str(d), follow_symlinks=True)
    assert sorted(f[1] for f in files) == ["a/l1/f.bin", "l2/f.bin", "real/f.bin"]
    assert all(r["reason"] == "symlink loop" for r in records)


# ---------------------------------------------------------------- check logic

@pytest.fixture
def scenario(tmp_path):
    d = str(tmp_path / "d")
    data = {
        "big.bin": os.urandom(20 * MiB),
        "small.txt": b"hola\n",
        "corrupt.txt": b"hola\n",
        "kms1.bin": os.urandom(3000),
        "p7.bin": os.urandom(12 * MiB),
        "exact8.bin": os.urandom(8 * MiB),
        "mpbad.bin": os.urandom(20 * MiB),
        "kmsmp.bin": os.urandom(70 * MiB),
        "crc64.bin": os.urandom(4000),
        "missing.txt": b"a\n",
        unicodedata.normalize("NFD", "sub/café.txt"): b"x",
    }
    for k, val in data.items():
        write(os.path.join(d, k), val)
    P = "up/"
    objs = {
        P + "big.bin": {"size": 20 * MiB, "etag": multipart_etag(data["big.bin"], 8 * MiB)},
        P + "small.txt": {"size": 5, "etag": hashlib.md5(b"hola\n").hexdigest()},
        P + "corrupt.txt": {"size": 5, "etag": "0" * 32, "head": {"ServerSideEncryption": "AES256"}},
        P + "kms1.bin": {"size": 3000, "etag": "f" * 32, "head": {
            "ServerSideEncryption": "aws:kms", "ChecksumCRC32": b64crc32(data["kms1.bin"]), "ChecksumType": "FULL_OBJECT"}},
        P + "p7.bin": {"size": 12 * MiB, "etag": multipart_etag(data["p7.bin"], 7 * MiB),
                       "head": {"ServerSideEncryption": "AES256"}, "part1": 7 * MiB},
        P + "exact8.bin": {"size": 8 * MiB, "etag": hashlib.md5(hashlib.md5(data["exact8.bin"]).digest()).hexdigest() + "-1"},
        P + "mpbad.bin": {"size": 20 * MiB, "etag": "b" * 32 + "-3", "head": {"ServerSideEncryption": "AES256"},
                          "part1": 8 * MiB},
        P + "kmsmp.bin": {"size": 70 * MiB, "etag": "a" * 32 + "-3", "head": {"ServerSideEncryption": "aws:kms"},
                          "part1": 32 * MiB},
        P + "crc64.bin": {"size": 4000, "etag": "c" * 32, "head": {
            "ServerSideEncryption": "aws:kms", "ChecksumCRC64NVME": b64crc64(data["crc64.bin"]), "ChecksumType": "FULL_OBJECT"}},
        P + unicodedata.normalize("NFC", "sub/café.txt"): {"size": 1, "etag": hashlib.md5(b"x").hexdigest()},
        P + "extra.txt": {"size": 3, "etag": "e" * 32},
    }
    return d, FakeS3(objs), tmp_path


def statuses(result):
    return {r[0]: r[1] for r in result.rows}


def test_manifest_check_and_second_round(scenario):
    d, s3, tmp = scenario
    m1 = str(tmp / "m1.jsonl")
    v.write_manifest(d, m1, v.parse_part_sizes("5,8,10,15,16"))
    res = v.check_manifests([m1], s3, "b", "up/", deep=True)
    st = statuses(res)
    nfd = unicodedata.normalize("NFD", "sub/café.txt")
    assert st["big.bin"] == "OK"
    assert st["small.txt"] == "OK"
    assert st["exact8.bin"] == "OK"
    assert st[nfd] == "OK"
    assert st["corrupt.txt"] == "HASH_MISMATCH"
    assert st["mpbad.bin"] == "HASH_MISMATCH"
    assert st["kms1.bin"] == "OK_CRC32"
    assert st["p7.bin"] == "SIZE_ONLY"      # never a false HASH_MISMATCH
    assert st["kmsmp.bin"] == "SIZE_ONLY"
    assert st["crc64.bin"] == "SIZE_ONLY"
    assert st["missing.txt"] == "MISSING"
    assert st["extra.txt"] == "EXTRA"
    assert res.exit_code == 1
    helpable, flags, crc_count, unverified = res.second_round()
    assert set(helpable) == {"p7.bin", "kmsmp.bin", "crc64.bin"}
    assert flags == ["--part-sizes 7,32", "--crc64nvme"] and crc_count == 1

    lst = str(tmp / "unverified.txt")
    res.write_unverified(lst)
    m2 = str(tmp / "m2.jsonl")
    v.write_manifest(d, m2, v.parse_part_sizes("7,32"), only=v.read_path_list(lst), with_crc64=True)
    st2 = statuses(v.check_manifests([m1, m2], s3, "b", "up/", deep=True))
    assert st2["p7.bin"] == "OK"
    assert st2["crc64.bin"] == "OK_CRC64NVME"
    assert st2["kmsmp.bin"] == "SIZE_ONLY"   # KMS multipart without checksums: size only


def test_direct_check_needs_no_second_round(scenario):
    d, s3, tmp = scenario
    res = v.check_directory(d, s3, "b", "up/", v.parse_part_sizes("5,8,10,15,16"))
    st = statuses(res)
    assert st["p7.bin"] == "OK"            # exact part size read from S3 before hashing
    assert st["crc64.bin"] == "OK_CRC64NVME"
    assert st["kmsmp.bin"] == "SIZE_ONLY"
    assert st["corrupt.txt"] == "HASH_MISMATCH"


def test_prefix_hint_when_nothing_matches(scenario):
    d, s3, tmp = scenario
    m1 = str(tmp / "m1.jsonl")
    v.write_manifest(d, m1, v.parse_part_sizes("8"))
    res = v.check_manifests([m1], s3, "b", "nope/")
    assert any("try the path nope/d/" in line for line in res.summary_lines(False))


def test_report_escapes_odd_names(scenario, tmp_path):
    d, s3, tmp = scenario
    m1 = str(tmp / "m1.jsonl")
    v.write_manifest(d, m1, v.parse_part_sizes("8"))
    res = v.check_manifests([m1], s3, "b", "up/")
    res.rows.append(["bad\tname\n\udcff", "MISSING", 1, "", ""])
    rep = tmp_path / "r.tsv"
    res.write_report(str(rep))
    assert all(len(line.split("\t")) == 5 for line in rep.read_text(encoding="utf-8").splitlines())


def test_split_s3_url():
    assert v.split_s3_url("s3://bkt/some/path/", "") == ("bkt", "some/path/")
    assert v.normalize_prefix("/a/b") == "a/b/"
    assert v.normalize_prefix("") == ""


def test_uneven_parts_are_not_reported_corrupt(tmp_path):
    data = os.urandom(20 * MiB)
    write(str(tmp_path / "d" / "f.bin"), data)
    # Uploaded intact with parts of 8, 6 and 6 MiB: same part count as uniform 8 MiB parts.
    etag = hashlib.md5(b"".join(hashlib.md5(c).digest() for c in (
        data[:8 * MiB], data[8 * MiB:14 * MiB], data[14 * MiB:]))).hexdigest() + "-3"
    s3 = FakeS3({"p/f.bin": {"size": 20 * MiB, "etag": etag, "head": {"ServerSideEncryption": "AES256"},
                             "parts": [8 * MiB, 6 * MiB, 6 * MiB]}})
    m = str(tmp_path / "m.jsonl")
    v.write_manifest(str(tmp_path / "d"), m, v.parse_part_sizes("8"))
    assert statuses(v.check_manifests([m], s3, "b", "p/", deep=True))["f.bin"] == "SIZE_ONLY"
    assert statuses(v.check_directory(str(tmp_path / "d"), s3, "b", "p/", v.parse_part_sizes("8")))["f.bin"] == "SIZE_ONLY"


def test_manifest_order_does_not_matter(scenario):
    d, s3, tmp = scenario
    m1 = str(tmp / "m1.jsonl")
    v.write_manifest(d, m1, v.parse_part_sizes("5,8,10,15,16"))
    res = v.check_manifests([m1], s3, "b", "up/", deep=True)
    lst = str(tmp / "u.txt")
    res.write_unverified(lst)
    m2 = str(tmp / "m2.jsonl")
    v.write_manifest(d, m2, v.parse_part_sizes("7,32"), only=v.read_path_list(lst), with_crc64=True)
    st = statuses(v.check_manifests([m2, m1], s3, "b", "up/", deep=True))
    assert st["p7.bin"] == "OK" and st["crc64.bin"] == "OK_CRC64NVME"


def test_head_denied_is_not_hidden(tmp_path):
    write(str(tmp_path / "d" / "a.txt"), b"hola\n")
    s3 = FakeS3({"p/a.txt": {"size": 5, "etag": "0" * 32, "denied": True}})
    m = str(tmp_path / "m.jsonl")
    v.write_manifest(str(tmp_path / "d"), m, v.parse_part_sizes("8"))
    res = v.check_manifests([m], s3, "b", "p/")
    assert statuses(res)["a.txt"] == "NO_ACCESS" and res.exit_code == 1


def test_custom_endpoint_plain_etag_not_trusted(tmp_path):
    write(str(tmp_path / "d" / "a.txt"), b"hola\n")
    s3 = FakeS3({"p/a.txt": {"size": 5, "etag": "0" * 32}}, trust_etags=False)
    m = str(tmp_path / "m.jsonl")
    v.write_manifest(str(tmp_path / "d"), m, v.parse_part_sizes("8"))
    assert statuses(v.check_manifests([m], s3, "b", "p/"))["a.txt"] == "SIZE_ONLY"


def test_odd_etag_does_not_abort(tmp_path):
    write(str(tmp_path / "d" / "a.bin"), os.urandom(6 * MiB))
    s3 = FakeS3({"p/a.bin": {"size": 6 * MiB, "etag": "abc-xyz", "head": {"ServerSideEncryption": "aws:kms"}}})
    m = str(tmp_path / "m.jsonl")
    v.write_manifest(str(tmp_path / "d"), m, v.parse_part_sizes("5"))
    assert statuses(v.check_manifests([m], s3, "b", "p/", deep=True))["a.bin"] == "SIZE_ONLY"


def test_non_mib_part_size_in_direct_mode(tmp_path):
    data = os.urandom(12 * MiB)
    write(str(tmp_path / "d" / "f.bin"), data)
    ps = 6 * MiB + 1
    s3 = FakeS3({"p/f.bin": {"size": 12 * MiB, "etag": multipart_etag(data, ps), "part1": ps}})
    out = str(tmp_path / "saved.jsonl")
    res = v.check_directory(str(tmp_path / "d"), s3, "b", "p/", v.parse_part_sizes("8"), manifest_out=out)
    assert statuses(res)["f.bin"] == "OK"
    inv = v.load_manifests([out])
    assert "%dB" % ps in inv.entries["f.bin"]["etags"] and "8" in inv.entries["f.bin"]["etags"]
