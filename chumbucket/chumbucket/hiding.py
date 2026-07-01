"""chumbucket.hiding - split module (code verbatim from the monolith)."""
import base64
import random
import time
from dataclasses import dataclass, field
from scapy.all import (IP, TCP, UDP, ICMP, Raw, DNS, DNSQR)

from .ui import (wrapper_parts)
from .encoding import (describe_decode, dns_safe_scheme, encode_payload)
from .network import (Network, NoiseConfig, _eth)
from .traffic import (_SERVER_BANNERS, _USER_AGENTS, _http_response, tcp_session)


@dataclass
class HideResult:
    packets: list = field(default_factory=list)
    solution: list[str] = field(default_factory=list)  # human-readable steps
    markers: list = field(default_factory=list)         # [{"pkt":..., "desc":...}]

    def mark(self, pkt, desc: str):
        """Tag a carrier packet so its exact frame number can be reported."""
        self.markers.append({"pkt": pkt, "desc": desc})
        return pkt


def hide_dns_exfil(flag: bytes, cfg: NoiseConfig, rng: random.Random,
                   scheme: str, xor_key: bytes | None, clock: list[float],
                   net: Network) -> HideResult:
    """Encode the flag and scatter it across DNS query subdomain labels, the
    classic 'someone tunneled data out over DNS' forensics scenario. The
    queries originate from a real client host and go to the LAN resolver."""
    enc = encode_payload(flag, dns_safe_scheme(scheme), xor_key)
    chunks = [enc[i:i + 30] for i in range(0, len(enc), 30)]
    domain = "tunnel.evil-c2.net"
    res = HideResult()
    host = rng.choice(net.clients)
    for idx, c in enumerate(chunks):
        qname = f"{c.decode().lower()}.{idx:02d}.{domain}"
        p = (_eth(net, host.ip, net.dns.ip) /
             IP(src=host.ip, dst=net.dns.ip) /
             UDP(sport=rng.randint(1025, 65535), dport=53) /
             DNS(rd=1, id=rng.randint(0, 65535), qd=DNSQR(qname=qname)))
        clock[0] += abs(rng.gauss(0.05, 0.02)) + 0.001
        p.time = clock[0]
        res.packets.append(p)
        res.mark(p, f"DNS exfil query, label .{idx:02d} = '{c.decode().lower()}'")
    actual_scheme = dns_safe_scheme(scheme)
    res.solution = [
        f"Filter DNS queries to '{domain}' (from host {host.ip}).",
        f"There are {len(chunks)} of them; order by the two-digit label "
        f"(.00, .01, ...) and concatenate the first label of each.",
        f"Then {describe_decode(actual_scheme, xor_key)} to recover the flag.",
    ]
    return res


def hide_split_reassembly(flag: bytes, proto: str, cfg: NoiseConfig,
                          rng: random.Random, scheme: str, xor_key: bytes | None,
                          clock: list[float], net: Network) -> HideResult:
    """Encode the flag, split into indexed chunks, and scatter across TCP or
    ICMP payloads between a real client and host. Player collects + sorts + decodes."""
    enc = encode_payload(flag, scheme, xor_key)
    n = rng.randint(4, 7)
    size = (len(enc) + n - 1) // n
    chunks = [enc[i:i + size] for i in range(0, len(enc), size)]
    client = rng.choice(net.clients)
    server = rng.choice(list(net.servers.values()))
    res = HideResult()
    marker = b"SEG"
    for idx, c in enumerate(chunks):
        body = marker + bytes([idx]) + c
        if proto == "icmp":
            p = (_eth(net, client.ip, server.ip) /
                 IP(src=client.ip, dst=server.ip) /
                 ICMP(type=8, id=0x4242, seq=idx) / Raw(load=body))
        else:
            p = (_eth(net, client.ip, server.ip) /
                 IP(src=client.ip, dst=server.ip) /
                 TCP(sport=40000 + idx, dport=9999, flags="PA",
                     seq=rng.randint(0, 2**32 - 1)) / Raw(load=body))
        clock[0] += abs(rng.gauss(0.04, 0.02)) + 0.001
        p.time = clock[0]
        res.packets.append(p)
        res.mark(p, f"flag segment #{idx} (payload after b'SEG'+index)")
    where = "ICMP echo (id 0x4242)" if proto == "icmp" else "TCP dport 9999"
    res.solution = [
        f"Find the {len(chunks)} {where} packets whose payload starts with b'SEG'.",
        "The 4th byte is the segment index; sort by it and concatenate the "
        "remaining payload bytes.",
        f"Then {describe_decode(scheme, xor_key)} to recover the flag.",
    ]
    return res


def hide_http_stream(flag: bytes, cfg: NoiseConfig, rng: random.Random,
                     scheme: str, xor_key: bytes | None, clock: list[float],
                     net: Network) -> HideResult:
    """Embed the encoded flag in an HTTP session cookie inside a full, followable
    TCP stream (handshake, request, response, teardown)."""
    enc = encode_payload(flag, scheme if scheme != "none" else "base64", xor_key)
    client = rng.choice(net.clients)
    server = net.servers.get("intranet.corp.local") or rng.choice(list(net.servers.values()))
    host = server.name
    req = (f"GET /dashboard HTTP/1.1\r\nHost: {host}\r\n"
           f"User-Agent: {rng.choice(_USER_AGENTS)}\r\n"
           f"Cookie: session={enc.decode()}\r\nAccept: */*\r\n"
           f"Connection: keep-alive\r\n\r\n").encode()
    resp = _http_response(rng, host)
    pkts = tcp_session(net, client, server, 80,
                       [("c2s", req), ("s2c", resp)], rng, clock, cfg)
    res = HideResult(packets=pkts)
    for p in pkts:
        if p.haslayer(Raw) and b"session=" in bytes(p[Raw].load):
            res.mark(p, "HTTP GET /dashboard carrying the flag in the session cookie")
            break
    actual_scheme = scheme if scheme != "none" else "base64"
    res.solution = [
        f"Follow the HTTP stream to host {host} (request /dashboard from {client.ip}).",
        "The session cookie value is the encoded flag.",
        f"{describe_decode(actual_scheme, xor_key).capitalize()} to recover it.",
    ]
    return res


_SB_CHARS = ["spongebob", "patrick", "squidward", "mrkrabs", "plankton", "sandy",
             "gary", "karen", "mrspuff", "squilliam", "larry", "pearl",
             "bubblebass", "flyingdutchman", "mermaidman", "barnacleboy",
             "oldmanjenkins", "bubblebuddy", "kingneptune", "puffyfluffy"]


_SB_WORDS = ["krabbypatty", "bikinibottom", "chumbucket", "krustykrab", "jellyfish",
             "secretformula", "spatula", "pineapple", "goofygoober", "tartarsauce",
             "barnacles", "fishpaste", "kelpshake", "anchorarms", "mocchocolate",
             "imready", "f1shh00ks", "musclebob", "buffpants", "rippedtrousers"]


_CY_CHARS = ["buffer_overflow", "priv_esc", "reverse_shell", "sql_injection",
             "race_condition", "use_after_free", "heap_spray", "rop_chain",
             "kernel_panic", "null_deref", "format_string", "stack_smash",
             "csrf_token", "xxe_payload", "deserialize", "ssrf_probe"]


_CY_WORDS = ["mimikatz", "cobaltstrike", "metasploit", "powershell", "rootkit",
             "keylogger", "ransomware", "backdoor", "payload", "shellcode",
             "exfil", "beacon", "implant", "dropper", "loader", "c2node",
             "lateral_move", "persistence", "credential_dump", "golden_ticket"]


_CY_CVE_YEARS = [2021, 2022, 2023, 2024, 2025]


_LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}


def _leetify(s: str, rng: random.Random) -> str:
    return "".join(_LEET.get(c, c) if rng.random() < 0.35 else c for c in s)


def _decoy_pools(theme: str, custom_words):
    """Return (chars, words, use_leet, allow_cve) for the chosen theme."""
    if theme == "cyber":
        return _CY_CHARS, _CY_WORDS, True, True
    if theme == "mixed":
        return _SB_CHARS + _CY_CHARS, _SB_WORDS + _CY_WORDS, True, True
    if theme == "custom":
        words = [w.strip() for w in (custom_words or []) if w.strip()]
        if not words:                       # empty custom -> fall back to spongebob
            return _SB_CHARS, _SB_WORDS, True, False
        return words, words, False, False   # custom words preserved (no leet)
    return _SB_CHARS, _SB_WORDS, True, False   # spongebob (default)


def random_decoy_text(rng: random.Random, theme: str = "spongebob",
                      custom_words=None) -> str:
    """A random fake-flag inner string for the chosen theme. Patterns vary so
    red herrings never look predictable. Custom words are preserved verbatim
    (no leet substitution); small pools fall back to simpler patterns."""
    chars, words, use_leet, allow_cve = _decoy_pools(theme, custom_words)
    pool = list(dict.fromkeys(chars + words))   # combined, de-duped

    # occasional fake-CVE decoy for cyber/mixed themes
    if allow_cve and rng.random() < 0.2:
        return f"CVE_{rng.choice(_CY_CVE_YEARS)}_{rng.randint(1000, 49999)}"

    # small pool (e.g. 1-2 custom words) -> simple, safe patterns only
    if len(pool) < 4:
        base = rng.choice(pool) if pool else "decoy"
        s = base if rng.random() < 0.4 else f"{base}_{rng.randint(10, 9999)}"
        return _leetify(s, rng) if use_leet else s

    pat = rng.randint(0, 5)
    if pat == 0:
        s = f"{rng.choice(chars)}_{rng.choice(words)}"
    elif pat == 1:
        s = f"{rng.choice(words)}_{rng.randint(10, 9999)}"
    elif pat == 2:
        s = f"{rng.choice(chars)}{rng.choice(chars)}".replace("_", "")
    elif pat == 3:
        s = f"{rng.choice(chars)}_{rng.choice(words)}"
    elif pat == 4:
        s = f"{rng.choice(words)}_{rng.choice(chars)}_{rng.randint(1, 99)}"
    else:
        s = f"not_{rng.choice(chars)}_{rng.choice(words)}"
    return _leetify(s, rng) if use_leet else s


def make_decoys(wrapper: str, count: int, cfg: NoiseConfig, rng: random.Random,
                clock: list[float], net: Network, theme: str = "spongebob",
                custom_words=None) -> list:
    """Plant plausible-but-wrong flag-shaped strings as red herrings, carried in
    real-looking HTTP traffic between actual hosts. Each decoy is a unique,
    randomized SpongeBob-themed string."""
    open_, close = wrapper_parts(wrapper)
    notes = ["# debug note: ", "# TODO remove before prod: ", "# old test flag: ",
             "<!-- staging flag ", "# leftover from CTF practice: ", "# nope: "]
    pkts = []
    for _ in range(count):
        client = rng.choice(net.clients)
        server = rng.choice(list(net.servers.values()))
        fake = f"{open_}{random_decoy_text(rng, theme, custom_words)}{close}"
        note = rng.choice(notes)
        tail = " -->" if note.startswith("<!--") else ""
        body = (f"HTTP/1.1 200 OK\r\nServer: {rng.choice(_SERVER_BANNERS)}\r\n"
                f"Content-Type: text/plain\r\nContent-Length: {len(note)+len(fake)+len(tail)+1}\r\n\r\n"
                f"{note}{fake}{tail}\n").encode()
        p = (_eth(net, server.ip, client.ip) /
             IP(src=server.ip, dst=client.ip) /
             TCP(sport=80, dport=rng.randint(1025, 65535), flags="PA",
                 seq=rng.randint(0, 2**32 - 1)) / Raw(load=body))
        clock[0] += abs(rng.gauss(cfg.jitter, cfg.jitter / 2)) + 0.001
        p.time = clock[0]
        pkts.append(p)
    return pkts
