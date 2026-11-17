"""End-to-end test against a local S3 emulator (moto). Skipped if moto is not installed.

It exercises the real HTTP path: SigV4 signing, ListObjectsV2 pagination and URL
decoding, HeadObject headers and partNumber, with objects uploaded by boto3.
"""
import hashlib
import os
import sys

import pytest

moto_server = pytest.importorskip("moto.server")
boto3 = pytest.importorskip("boto3")
from boto3.s3.transfer import TransferConfig  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import s3_upload_verify as v  # noqa: E402

MiB = v.MiB


@pytest.fixture(scope="module")
def endpoint():
    server = moto_server.ThreadedMotoServer(ip_address="127.0.0.1", port=0, verbose=False)
    server.start()
    host, port = server.get_host_and_port()
    yield "http://%s:%d" % (host, port)
    server.stop()


def test_end_to_end(endpoint, tmp_path):
    client = boto3.client("s3", endpoint_url=endpoint, region_name="us-east-1",
                          aws_access_key_id="testing", aws_secret_access_key="testing")
    client.create_bucket(Bucket="bkt")
    d = tmp_path / "MyFolder"
    files = {
        "small.txt": b"hola\n",
        "part10.bin": os.urandom(25 * MiB),
        "cli8.bin": os.urandom(20 * MiB),
        "odd7.bin": os.urandom(15 * MiB),
        "dir with space/café + plus%.txt": b"odd name",
        "corrupt.bin": os.urandom(4000),
        "missing.txt": b"not uploaded",
    }
    for name, data in files.items():
        p = d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    part = {"part10.bin": 10, "cli8.bin": 8, "odd7.bin": 7}
    for name, data in files.items():
        if name == "missing.txt":
            continue
        key = "uploads/MyFolder/" + name
        body = data if name != "corrupt.bin" else os.urandom(4000)
        src = tmp_path / "upload.tmp"
        src.write_bytes(body)
        ps = part.get(name, 64) * MiB
        client.upload_file(str(src), "bkt", key, Config=TransferConfig(multipart_threshold=ps, multipart_chunksize=ps))
    # Many small objects to force ListObjectsV2 pagination (1000 per page).
    for i in range(1005):
        client.put_object(Bucket="bkt", Key="uploads/MyFolder/many/%04d" % i, Body=b"")
        (d / "many").mkdir(exist_ok=True)
        (d / "many" / ("%04d" % i)).write_bytes(b"")

    creds = v.Credentials("testing", "testing")
    s3 = v.S3Client("bkt", creds, endpoint=endpoint, trust_etags=True)
    objs = s3.list_objects("uploads/MyFolder/")
    assert len(objs) == len(files) - 1 + 1005
    assert "uploads/MyFolder/dir with space/café + plus%.txt" in objs

    m1 = str(tmp_path / "m1.jsonl")
    v.write_manifest(str(d), m1, v.parse_part_sizes("5,8,10,15,16"))
    res = v.check_manifests([m1], s3, "bkt", "uploads/MyFolder/", deep=True)
    st = {r[0]: r[1] for r in res.rows}
    assert st["small.txt"].startswith("OK")
    assert st["part10.bin"].startswith("OK")
    assert st["cli8.bin"].startswith("OK")
    assert st["dir with space/café + plus%.txt"].startswith("OK")
    assert st["corrupt.bin"] == "HASH_MISMATCH"
    assert st["missing.txt"] == "MISSING"
    # Recent SDKs send a full-object CRC32 by default; then odd7 is proven by CRC32,
    # otherwise --deep must point at the 7 MiB part size.
    if st["odd7.bin"] == "SIZE_ONLY":
        assert ("part", 7) in res.hints["odd7.bin"]
    else:
        assert st["odd7.bin"].startswith("OK")

    direct = v.check_directory(str(d), s3, "bkt", "uploads/MyFolder/", v.parse_part_sizes("5,8,10,15,16"))
    st = {r[0]: r[1] for r in direct.rows}
    assert st["odd7.bin"].startswith("OK")
    assert st["corrupt.bin"] == "HASH_MISMATCH"
    assert direct.exit_code == 1


def test_wrong_keys_give_clear_error(endpoint):
    s3 = v.S3Client("bkt", v.Credentials("testing", "wrong"), endpoint=endpoint)
    try:
        s3.list_objects("")
    except v.S3Error as e:
        assert "HTTP 403" in str(e) or "HTTP 404" in str(e)


def test_list_buckets_and_folders(endpoint):
    client = boto3.client("s3", endpoint_url=endpoint, region_name="us-east-1",
                          aws_access_key_id="testing", aws_secret_access_key="testing")
    client.create_bucket(Bucket="browse-me")
    for key in ("a/x.txt", "a/b/y.txt", "a/c d+e/z.txt", "top.txt"):
        client.put_object(Bucket="browse-me", Key=key, Body=b"1")
    creds = v.Credentials("testing", "testing")
    assert "browse-me" in v.list_buckets(creds, endpoint)
    s3 = v.S3Client("browse-me", creds, endpoint=endpoint)
    assert s3.list_folders("") == (["a/"], 1, False)
    assert s3.list_folders("a/") == (["a/b/", "a/c d+e/"], 1, False)
