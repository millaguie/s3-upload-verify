# s3-upload-verify

Checks that a local folder arrived complete in Amazon S3: every file is there, with the same size and the same content.

It is one Python file with no dependencies. It has a window and a command line. It only reads from S3: it lists the bucket and reads the object metadata. It never uploads, changes or downloads anything.

## Why not just compare MD5s?

S3 keeps the MD5 of a file as its ETag only if the upload was in one piece and without SSE-KMS or SSE-C encryption. Upload tools send big files in parts. Then the ETag is the MD5 of the MD5s of the parts, so it depends on the part size. Each upload client uses its own part size, 5, 8, 10, 15 and 16 MiB are common.

So the tool does three things:

- It computes the multipart ETags for the usual part sizes. When it can ask S3, it uses the exact part size of each object.
- When the ETag proves nothing, it uses the CRC32, CRC64NVME or SHA-256 checksum that S3 may keep.
- It separates "the content is different" from "S3 has nothing to compare with", for example SSE-KMS multipart objects without a checksum.

## Download

Windows, macOS (Apple Silicon) and Linux: get the program from the [Releases](../../releases) page. The program is not signed, so the system shows a warning the first time.

- On macOS, open the app once, then go to System Settings, Privacy & Security, and click **Open Anyway**.
- On Windows, click **More info** and then **Run anyway**.

The programs only have the window. For the command line, use the Python file.

Any system with Python 3.8 or newer: download [`s3_upload_verify.py`](s3_upload_verify.py). The window needs tkinter. Python from python.org includes it. With Homebrew, run `brew install python-tk`. On Debian or Ubuntu, run `apt install python3-tk`.

## Use the window

Start the program, or run `python3 s3_upload_verify.py` with no arguments.

### Check against S3

Use this if you have the files and access to the bucket.

1. Choose the local folder.
2. Type the access key and the secret key, or choose an AWS profile.
3. Click **Load buckets** and choose the bucket, or type its name.
4. Click **Browse...** and choose the folder in the bucket. Many upload tools keep the folder name. A folder `MyFolder` uploaded to `uploads/` ends up in `uploads/MyFolder/`.
5. Click **Start**.

### Create manifest

Use this if you have the files but no access to the bucket. Choose the folder and click **Start**. The program writes `manifest.jsonl`, a list of sizes and hashes. Send it to someone who can read the bucket. That person checks it with the **Manifest file(s)** option.

## Use the command line

```sh
# Hash a folder and compare it with S3 in one go
python3 s3_upload_verify.py check --dir ./MyFolder --bucket my-bucket --prefix uploads/MyFolder/ --profile myprofile

# Or in two steps: the uploader writes a manifest...
python3 s3_upload_verify.py manifest ./MyFolder -o manifest.jsonl
# ...and someone with bucket access checks it
python3 s3_upload_verify.py check --manifest manifest.jsonl --bucket my-bucket --prefix uploads/MyFolder/ --deep \
    --report report.tsv --unverified-list unverified.txt
```

`--bucket s3://my-bucket/uploads/MyFolder/` also works. Run `check --help` and `manifest --help` to see all the options.

The tool looks for credentials in this order:

1. `--profile`
2. the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables
3. `AWS_PROFILE`, or the `default` profile

Profiles with static keys or `credential_process` work as they are. For SSO and role profiles you need AWS CLI v2 installed, the tool asks it for temporary keys.

Permissions:

- `s3:ListBucket` on the bucket.
- `s3:GetObject` on the objects. HeadObject needs it.
- With SSE-KMS objects, reading the checksums can also need `kms:Decrypt`.
- **Load buckets** needs `s3:ListAllMyBuckets`. Without it, type the bucket name.

If the credentials can list the bucket but not read the object metadata, the files show as `NO_ACCESS`.

With `--endpoint` (S3-compatible storage that is not AWS), a different plain ETag only gives `SIZE_ONLY`, because other storage may not use MD5 ETags. Add `--trust-endpoint-etags` if yours does.

## Results

| Status | Meaning |
|---|---|
| `OK` | size and ETag (MD5 or multipart MD5) match |
| `OK_SHA256`, `OK_CRC64NVME`, `OK_CRC32` | size and that S3 checksum match. CRC32 is a weaker 32-bit check |
| `SIZE_ONLY` | the size matches, but S3 has no hash to compare with |
| `UNHASHED_SYMLINK` | in S3, under a path that was a symbolic link on the local side (not hashed) |
| `MISSING` | the local file is not in S3 |
| `NO_ACCESS` | the tool could not read the object metadata (needs `s3:GetObject`) |
| `SIZE_MISMATCH` | the size is different |
| `HASH_MISMATCH` | same size, different content: a corrupt or different file |
| `EXTRA` | in S3 but not in the local folder (only for information) |

Exit code:

- `1`: a file is missing, different or corrupt, the tool could not read a local file, or it had no access to the object metadata.
- `2`: no errors, but the tool could only check the size of some files.
- `0`: the tool verified every file.

### Second round (manifest mode)

If a manifest check ends with `SIZE_ONLY` files, `--deep` finds what the uploader needs to hash, and `--unverified-list` writes the list of those files. The output shows the command for the uploader:

```sh
python3 s3_upload_verify.py manifest ./MyFolder --only unverified.txt --part-sizes 32 -o manifest-2.jsonl
python3 s3_upload_verify.py check --manifest manifest.jsonl --manifest manifest-2.jsonl --bucket ... --deep
```

The direct check (`--dir`, or **Local folder** in the window) does not need this. It asks S3 for the part size before it hashes the files.

`--crc64nvme` is slow in pure Python, about 13 MB/s, so roughly 21 hours per TB. The tool only asks for it when it is the only possible proof for a file.

## Limits

- Objects with SSE-KMS or SSE-C and no full-object checksum: the tool can only compare the size.
- A file you changed on your disk after the upload looks like a corrupt upload. The tool compares what is on the disk now.
- The tool includes hidden files and skips `.DS_Store`, `Thumbs.db` and `desktop.ini`. Use `--exclude-hidden` to skip all dot files.

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install pytest "moto[server]" boto3
.venv/bin/pytest
```

`tests/test_moto.py` tests the real HTTP calls against a local S3 emulator (moto). Without moto, pytest skips it.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
