#!/usr/bin/env python3
import argparse
import base64
import hashlib
import re
import struct
import sys
import zlib
from pathlib import Path


def round_up(value, align):
    return (value + align - 1) & ~(align - 1)


def adb_signature_ids(path):
    data = Path(path).read_bytes()
    if data.startswith(b"ADBd"):
        data = zlib.decompress(data[4:], -zlib.MAX_WBITS)
    if data[:4] != b"ADB.":
        raise ValueError(f"{path}: not an ADB file")

    pos = 8
    signatures = []
    while pos < len(data):
        if pos + 4 > len(data):
            raise ValueError(f"{path}: truncated ADB block header")

        type_size = struct.unpack_from("<I", data, pos)[0]
        block_type = type_size >> 30
        if block_type == 3:
            block_type = type_size & 0x3FFFFFFF
            if pos + 16 > len(data):
                raise ValueError(f"{path}: truncated extended ADB block header")
            raw_size = struct.unpack_from("<Q", data, pos + 8)[0]
            header_size = 16
        else:
            raw_size = type_size & 0x3FFFFFFF
            header_size = 4

        if raw_size < header_size or pos + raw_size > len(data):
            raise ValueError(f"{path}: invalid ADB block size")

        payload = data[pos + header_size : pos + raw_size]
        if block_type == 1 and len(payload) >= 18:
            signatures.append(payload[2:18].hex())

        pos += round_up(raw_size, 8)

    return signatures


def public_key_id(path):
    text = Path(path).read_text(errors="ignore")
    match = re.search(
        r"-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----",
        text,
        re.S,
    )
    if not match:
        raise ValueError(f"{path}: not a PEM public key")

    der = base64.b64decode(re.sub(r"\s+", "", match.group(1)))
    # apk-tools identifies P-256 public keys by hashing the uncompressed EC
    # point. OpenWrt/FriendlyWrt apk keys are SPKI DER with that point at EOF.
    if len(der) < 65 or der[-65] != 0x04:
        raise ValueError(f"{path}: unsupported public key format")
    return hashlib.sha512(der[-65:]).digest()[:16].hex()


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    sig = sub.add_parser("sig-id")
    sig.add_argument("adb")

    key = sub.add_parser("key-id")
    key.add_argument("pem")

    verify = sub.add_parser("verify")
    verify.add_argument("adb")
    verify.add_argument("pem")

    args = parser.parse_args()
    try:
        if args.cmd == "sig-id":
            print("\n".join(adb_signature_ids(args.adb)))
        elif args.cmd == "key-id":
            print(public_key_id(args.pem))
        elif args.cmd == "verify":
            sigs = adb_signature_ids(args.adb)
            key_id = public_key_id(args.pem)
            if key_id not in sigs:
                print(
                    f"ERROR: key id {key_id} does not match ADB signatures {sigs}",
                    file=sys.stderr,
                )
                return 1
            print(f"OK: {Path(args.adb).name} is signed by {key_id}")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
