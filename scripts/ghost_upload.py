#!/usr/bin/env python3
"""Upload images to Ghost via the Admin API and print their CDN URLs.

Usage:
    python3 ghost_upload.py <admin-api-key id:secret> <image> [<image> ...]

The API key is passed as an argument at runtime and never stored in this file.
Prints one line per image:  <local-path>\t<uploaded-url>
"""
import sys, os, hmac, hashlib, base64, json, time, mimetypes, uuid, urllib.request

BLOG = "https://blog.vmguru.io"


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")


def make_token(kid, secret):
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    now = int(time.time())
    payload = {"iat": now, "exp": now + 300, "aud": "/admin/"}
    seg = b64(json.dumps(header, separators=(",", ":")).encode()) + b"." + \
        b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(bytes.fromhex(secret), seg, hashlib.sha256).digest()
    return (seg + b"." + b64(sig)).decode()


def upload(token, path):
    boundary = "----ghost" + uuid.uuid4().hex
    ctype = mimetypes.guess_type(path)[0] or "image/png"
    fname = os.path.basename(path)
    with open(path, "rb") as f:
        data = f.read()
    parts = []
    parts.append(("--" + boundary).encode())
    parts.append(
        f'Content-Disposition: form-data; name="file"; filename="{fname}"'.encode())
    parts.append(f"Content-Type: {ctype}".encode())
    parts.append(b"")
    parts.append(data)
    parts.append(("--" + boundary).encode())
    parts.append(b'Content-Disposition: form-data; name="ref"')
    parts.append(b"")
    parts.append(fname.encode())
    parts.append(("--" + boundary + "--").encode())
    parts.append(b"")
    body = b"\r\n".join(parts)
    req = urllib.request.Request(
        BLOG + "/ghost/api/admin/images/upload/",
        data=body,
        headers={
            "Authorization": "Ghost " + token,
            "Accept-Version": "v5.0",
            "Content-Type": "multipart/form-data; boundary=" + boundary,
        },
        method="POST",
    )
    r = urllib.request.urlopen(req, timeout=60)
    out = json.loads(r.read().decode())
    return out["images"][0]["url"]


def main():
    if len(sys.argv) < 3 or ":" not in sys.argv[1]:
        print(__doc__)
        sys.exit(1)
    kid, secret = sys.argv[1].split(":", 1)
    token = make_token(kid, secret)
    for path in sys.argv[2:]:
        try:
            url = upload(token, path)
            print(f"{path}\t{url}")
        except Exception as e:
            print(f"{path}\tERROR {e!r}", file=sys.stderr)


if __name__ == "__main__":
    main()
