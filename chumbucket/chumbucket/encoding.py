"""chumbucket.encoding - split module (code verbatim from the monolith)."""
import base64
import re
from scapy.all import (DNS)





def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def dns_safe_scheme(scheme: str) -> str:
    """DNS labels are case-insensitive and limited to letters/digits/hyphen, so
    base64 (and plaintext) can't survive. Coerce to a DNS-safe encoding."""
    return scheme if scheme in ("hex", "base32") else "base32"

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> bytes:
    n = int.from_bytes(raw, "big")
    out = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_B58_ALPHABET[r])
    for b in raw:            # preserve leading zero bytes as '1'
        if b == 0:
            out.append(_B58_ALPHABET[0])
        else:
            break
    return bytes(out[::-1])


def b58decode(enc: bytes) -> bytes:
    n = 0
    for ch in enc:
        n = n * 58 + _B58_ALPHABET.index(ch)
    full = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for ch in enc:
        if ch == _B58_ALPHABET[0]:
            pad += 1
        else:
            break
    return b"\x00" * pad + full

def encode_payload(raw: bytes, scheme: str, xor_key: bytes | None) -> bytes:
    """Apply an encoding scheme. Returns the encoded bytes (ascii-safe where
    the scheme implies it)."""
    if xor_key:
        raw = xor_bytes(raw, xor_key)
    if scheme == "none":
        return raw
    if scheme == "hex":
        return raw.hex().encode()
    if scheme == "base64":
        return base64.b64encode(raw)
    if scheme == "base32":
        # base32 is DNS-label safe (letters+digits, case-insensitive)
        return base64.b32encode(raw).rstrip(b"=")
    if scheme == "base58":
        return b58encode(raw)
    if scheme == "urlencode":
        return "".join("%%%02X" % b for b in raw).encode()
    raise ValueError(f"unknown scheme: {scheme}")


def describe_decode(scheme: str, xor_key: bytes | None) -> str:
    steps = []
    if scheme == "hex":
        steps.append("hex-decode")
    elif scheme == "base64":
        steps.append("base64-decode")
    elif scheme == "base32":
        steps.append("base32-decode (re-pad with '=' to a multiple of 8)")
    elif scheme == "base58":
        steps.append("base58-decode")
    elif scheme == "urlencode":
        steps.append("URL-decode (percent-decode each %XX)")
    if xor_key:
        steps.append(f"XOR with key {xor_key!r}")
    if not steps:
        steps.append("read as plaintext")
    return " then ".join(steps)


_LOWERCASING = {"dns", "kerberoast", "doh-beacon", "dga-beacon"}


_PLAINTEXT_CRED = {"ftp-creds", "telnet-creds", "brute-force"}


def challenge_name(args) -> str:
    return args.scenario if args.scenario != "none" else args.method


def effective_encoding(args) -> tuple[str, str]:
    """Return (scheme_actually_used, note). For hostname-label carriers a
    requested base64/none is coerced to a label-safe scheme."""
    chal = challenge_name(args)
    if chal in _LOWERCASING:
        eff = dns_safe_scheme(args.encode)
        if eff != args.encode:
            return eff, f"requested '{args.encode}', coerced to '{eff}' (label-safe)"
        return eff, ""
    return args.encode, ""


def _decode_block(scheme: str) -> list:
    return {"hex": ["From Hex"], "base64": ["From Base64"],
            "base32": ["From Base32"], "base58": ["From Base58"],
            "urlencode": ["URL Decode"], "none": []}.get(scheme, [])


def decode_steps(args) -> list:
    """Produce the exact ordered decode steps to recover the flag (usable in any
    decoding tool or by hand)."""
    chal = challenge_name(args)
    eff, _ = effective_encoding(args)
    steps = []
    if chal == "http-basic":
        steps.append('From Base64        # HTTP Basic = base64("user:pass")')
        steps.append('Find/Replace  ^[^:]*:  ->  (nothing)   # keep only the password')
        steps += _decode_block(args.encode)
    elif chal in _PLAINTEXT_CRED and args.encode == "none":
        steps.append("(none - the password is already plaintext on the wire)")
    else:
        if chal in _LOWERCASING and eff == "base32":
            steps.append("Upper case         # labels are stored lowercase; Base32 is case-sensitive")
        steps += _decode_block(eff)
    if args.xor:
        steps.append(f'XOR  key="{args.xor}"  (UTF8)')
    return steps or ["(flag is plaintext - no recipe needed)"]
