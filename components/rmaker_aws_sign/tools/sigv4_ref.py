#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
"""Independent reference implementation of the SigV4 spec the component signs to.

Reproduces AWS's published get-vanilla, S3 GET object and S3 presigned URL answers,
which is what validates it, and generates the test vectors the C suite asserts. When a new service or path shape
needs signing, generate the vector here first, then make the C match.

Usage:
    sigv4_ref.py            # self-check plus every vector, as C-ready values
"""

import hashlib
import hmac

UNRESERVED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~")

AK = "AKIDEXAMPLE"
SK = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
REGION = "us-east-1"
AMZDATE = "20150830T123600Z"     # epoch 1440938160
HOST = "example.amazonaws.com"


def enc(s, keep_slash):
    out = []
    for b in s.encode():
        c = chr(b)
        if c in UNRESERVED or (keep_slash and c == '/'):
            out.append(c)
        else:
            out.append("%%%02X" % b)
    return "".join(out)


def normalize(path):
    """RFC 3986 dot-segment removal plus empty-segment removal, as AWS SDKs do."""
    out = []
    for seg in path.split("/"):
        if seg == "..":
            if out:
                out.pop()
        elif seg and seg != ".":
            out.append(seg)
    trailing = "/" if out and path.endswith("/") else ""
    return "/" + "/".join(out) + trailing


def canon_uri(path, service):
    if not path:
        return "/"
    if service == "s3":
        return enc(path, True)                         # S3: as given, encoded once
    return enc(enc(normalize(path), True), True)       # non-S3: normalized, encoded twice


def canon_query(pairs):
    if not pairs:
        return ""
    ep = sorted((enc(n, False), enc(v, False)) for n, v in pairs)
    return "&".join(f"{n}={v}" for n, v in ep)


def trim(v):
    return " ".join(v.split())


def sha256hex(b):
    return hashlib.sha256(b).hexdigest()


def hmac256(k, m):
    return hmac.new(k, m.encode(), hashlib.sha256).digest()


def sign(method, host, path, qpairs, headers, payload,
         ak, sk, token, region, service, amzdate):
    ds = amzdate[:8]
    hdrs = [("host", host), ("x-amz-date", amzdate)]
    if token:
        hdrs.append(("x-amz-security-token", token))
    hdrs += [(n.lower(), v) for n, v in headers]

    merged = {}
    for n, v in hdrs:                                  # stable: dict preserves insertion order
        merged.setdefault(n, []).append(trim(v))
    names = sorted(merged)
    canon_headers = "".join(f"{n}:{','.join(merged[n])}\n" for n in names)
    signed_headers = ";".join(names)

    uri, q = canon_uri(path, service), canon_query(qpairs)
    phash = sha256hex(payload)
    creq = f"{method}\n{uri}\n{q}\n{canon_headers}\n{signed_headers}\n{phash}"

    scope = f"{ds}/{region}/{service}/aws4_request"
    sts = f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{sha256hex(creq.encode())}"

    k = hmac256(("AWS4" + sk).encode(), ds)
    k = hmac256(k, region)
    k = hmac256(k, service)
    k = hmac256(k, "aws4_request")
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()

    return {
        "canonical_uri":   uri,
        "canonical_query": q,
        "signed_headers":  signed_headers,
        "canonical_request": creq,
        "creq_sha256":     sha256hex(creq.encode()),
        "string_to_sign":  sts,
        "payload_hash":    phash,
        "signature":       sig,
        "authorization":   f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, "
                           f"SignedHeaders={signed_headers}, Signature={sig}",
    }


def presign(method, host, path, qpairs, ak, sk, token, region, service, amzdate, expires,
            token_unsigned=False, scheme="https"):
    ds = amzdate[:8]
    scope = f"{ds}/{region}/{service}/aws4_request"
    params = list(qpairs) + [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
        ("X-Amz-Credential", f"{ak}/{scope}"),
        ("X-Amz-Date", amzdate),
        ("X-Amz-Expires", str(expires)),
        ("X-Amz-SignedHeaders", "host"),
    ]
    if token and not token_unsigned:
        params.append(("X-Amz-Security-Token", token))
    q = canon_query(params)
    phash = "UNSIGNED-PAYLOAD" if service == "s3" else sha256hex(b"")
    creq = f"{method}\n{canon_uri(path, service)}\n{q}\nhost:{host}\n\nhost\n{phash}"
    sts = f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{sha256hex(creq.encode())}"

    k = hmac256(("AWS4" + sk).encode(), ds)
    k = hmac256(k, region)
    k = hmac256(k, service)
    k = hmac256(k, "aws4_request")
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()

    url = f"{scheme}://{host}{enc(path, True) if path else '/'}?{q}&X-Amz-Signature={sig}"
    if token and token_unsigned:
        url += "&X-Amz-Security-Token=" + enc(token, False)
    return {"canonical_query": q, "signature": sig, "url": url}


V6_TOKEN = "FQoGZXIvYXdzEBYaD" + "A" * 40 + "EXAMPLETOKEN"
V7_TOKEN = "IQoJb3JpZ2luX2VjE" + "Z" * 1400 + "END"

VECTORS = [
    ("V1 get-vanilla", dict(method="GET", host=HOST, path="/", qpairs=[], headers=[],
                            payload=b"", token=None, service="service")),
    ("V2 headers+query+payload",
     dict(method="GET", host=HOST, path="/",
          qpairs=[("Param1", "value1"), ("Param2", "value2")],
          headers=[("content-type", "application/json"), ("my-header", "my-value")],
          payload=b"hello", token=None, service="service")),
    ("V3 header trim", dict(method="GET", host=HOST, path="/", qpairs=[],
                            headers=[("my-header", "  a  b   c  ")],
                            payload=b"", token=None, service="service")),
    ("V4 query sort", dict(method="GET", host=HOST, path="/",
                           qpairs=[("Param", "z"), ("Param", "a"), ("aParam", "1")],
                           headers=[], payload=b"", token=None, service="service")),
    ("V5 path encoding", dict(method="GET", host=HOST, path="/a b/-_.~/c", qpairs=[],
                              headers=[], payload=b"", token=None, service="service")),
    ("V6 session token", dict(method="POST", host=HOST, path="/prod/v1/session", qpairs=[],
                              headers=[], payload=b"", token=V6_TOKEN, service="execute-api")),
    ("V7 long session token",
     dict(method="POST", host=HOST, path="/prod/v1/session", qpairs=[], headers=[],
          payload=b"", token=V7_TOKEN, service="execute-api")),
    ("V8 s3 put", dict(method="PUT", host="bkt.s3.us-east-1.amazonaws.com",
                       path="/node-data/a b/x.txt", qpairs=[],
                       headers=[("x-amz-content-sha256", sha256hex(b"hello"))],
                       payload=b"hello", token=None, service="s3")),
    ("V9 non-s3 same path", dict(method="GET", host=HOST, path="/node-data/a b/x.txt",
                                 qpairs=[], headers=[], payload=b"", token=None,
                                 service="service")),
]


# AWS's S3 documentation examples: the credentials, bucket and date they use.
S3_AK = "AKIAIOSFODNN7EXAMPLE"
S3_SK = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
S3_DATE = "20130524T000000Z"     # epoch 1369353600
S3_HOST = "examplebucket.s3.amazonaws.com"

KVS_ARN = "arn:aws:kinesisvideo:us-west-2:123456789012:channel/demo-channel/1234567890123"

PRESIGN_VECTORS = [
    ("P1 kvs signaling, signed token",
     dict(method="GET", host="m-1234abcd.kinesisvideo.us-west-2.amazonaws.com", path="/",
          qpairs=[("X-Amz-ChannelARN", KVS_ARN), ("X-Amz-ClientId", "viewer 1")],
          token="TOK/+=", region="us-west-2", service="kinesisvideo", expires=300,
          scheme="wss")),
    ("P2 iot websocket, token after signature",
     dict(method="GET", host="abc123-ats.iot.us-east-1.amazonaws.com", path="/mqtt", qpairs=[],
          token="TOK/+=", token_unsigned=True, region="us-east-1", service="iotdevicegateway",
          expires=86400, scheme="wss")),
    ("P3 s3 get, path and value to encode",
     dict(method="GET", host="bkt.s3.us-east-1.amazonaws.com", path="/node-data/a b/x.txt",
          qpairs=[("versionId", "3/L4kq+rm=")], token="TOK", region="us-east-1", service="s3",
          expires=3600)),
]


def main():
    r = sign("GET", HOST, "/", [], [], b"", AK, SK, None, REGION, "service", AMZDATE)
    assert r["signature"] == \
        "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31", "get-vanilla mismatch"
    print("get-vanilla OK")

    for path, expect in (("//example//", "9a624bd73a37c9a373b5312afbebe7a714a789de108f0bdfe846570885f57e84"),
                         ("/./example", "ef75d96142cf21edca26f06005da7988e4f8dc83a165a80865db7089db637ec5"),
                         ("/example1/example2/../..",
                          "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")):
        r = sign("GET", HOST, path, [], [], b"", AK, SK, None, REGION, "service", AMZDATE)
        assert r["signature"] == expect, f"normalized {path} mismatch"
    print("normalized paths OK")

    r = sign("GET", S3_HOST, "/test.txt", [],
             [("range", "bytes=0-9"), ("x-amz-content-sha256", sha256hex(b""))], b"",
             S3_AK, S3_SK, None, "us-east-1", "s3", S3_DATE)
    assert r["signature"] == \
        "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41", "S3 GET mismatch"
    print("S3 GET object OK")

    r = presign("GET", S3_HOST, "/test.txt", [], S3_AK, S3_SK, None, "us-east-1", "s3",
                S3_DATE, 86400)
    assert r["signature"] == \
        "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404", "S3 presign mismatch"
    print("S3 presigned URL OK\n")

    for name, kw in VECTORS:
        r = sign(ak=AK, sk=SK, region=REGION, amzdate=AMZDATE, **kw)
        print(f"{name}")
        print(f"  canonical_uri  = {r['canonical_uri']}")
        print(f"  canonical_query= {r['canonical_query']}")
        print(f"  signed_headers = {r['signed_headers']}")
        print(f"  creq_sha256    = {r['creq_sha256']}")
        print(f"  signature      = {r['signature']}")
        print(f"  content_sha256 = {r['payload_hash']}")

    for name, kw in PRESIGN_VECTORS:
        r = presign(ak=AK, sk=SK, amzdate=AMZDATE, **kw)
        print(f"{name}")
        print(f"  url = {r['url']}")


if __name__ == "__main__":
    main()
