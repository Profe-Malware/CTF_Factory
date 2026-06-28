#!/usr/bin/env python3
"""
ctf_pcapgen.py - A network-forensics CTF challenge authoring tool.

Generates a .pcap containing a controlled volume of plausible "noise" traffic
per protocol, then hides a flag inside it using one of several techniques at a
chosen difficulty. Also emits an answer-key sidecar so you can verify your own
challenge's intended solve path.

This produces a capture FILE for analysis puzzles. It does not transmit anything
on a network.

Requires: scapy  (pip install scapy)
"""

import argparse
import base64
import ipaddress
import random
import sys
from dataclasses import dataclass, field

from scapy.all import (
    IP, TCP, UDP, ICMP, Ether, Raw, DNS, DNSQR, DNSRR, ARP, BOOTP, DHCP, wrpcap,
)

# ---------------------------------------------------------------------------
# Tool metadata / signature
# ---------------------------------------------------------------------------

TOOL_NAME   = "ChumBucket"
SUBTITLE    = "Network-Forensics CTF Challenge Forge"
VERSION     = "v0.9-beta"
AUTHOR      = "Profe Malware"
DESCRIPTION = (
    "Chums the water with realistic background traffic and decoy flags, then hides\n"
    "     the real catch for your players to fish out. Built for educators, red\n"
    "     teamers, and competition designers."
)
DEFAULT_FLAG_PREFIX = "CTF"

# Big wordmark shown on launch (ANSI-shadow style).
WORDMARK = r"""
 ██████╗██╗  ██╗██╗   ██╗███╗   ███╗██████╗ ██╗   ██╗ ██████╗██╗  ██╗███████╗████████╗
██╔════╝██║  ██║██║   ██║████╗ ████║██╔══██╗██║   ██║██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝
██║     ███████║██║   ██║██╔████╔██║██████╔╝██║   ██║██║     █████╔╝ █████╗     ██║   
██║     ██╔══██║██║   ██║██║╚██╔╝██║██╔══██╗██║   ██║██║     ██╔═██╗ ██╔══╝     ██║   
╚██████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║██████╔╝╚██████╔╝╚██████╗██║  ██╗███████╗   ██║   
 ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   
""".strip("\n")


def format_flag(wrapper: str, inner: str) -> str:
    """Insert the inner flag text into the wrapper at the first 'FLAG' token."""
    return wrapper.replace("FLAG", inner, 1)


def wrapper_parts(wrapper: str) -> tuple[str, str]:
    """Return the (open, close) text surrounding the 'FLAG' placeholder.
    Uses partition so a stray second 'FLAG' never causes an unpack error."""
    open_, _, close = wrapper.partition("FLAG")
    return open_, close

THEME = {
    "banner":      "bold cyan",
    "border":      "cyan",
    "author":      "bold bright_cyan",
    "subtitle":    "bold white",
    "description": "dim white",
    "meta":        "dim cyan",
    "menu_title":  "bold cyan",
    "menu_item":   "white",
    "menu_number": "bold cyan",
    "prompt":      "bold cyan",
    "success":     "bold green",
    "warning":     "bold yellow",
    "error":       "bold red",
    "highlight":   "bold bright_white",
    "coming_soon": "dim yellow",
}

# rich is optional; degrade gracefully to plain text if it isn't installed
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    _console = Console()
    _HAS_RICH = True
except ImportError:
    _console = None
    _HAS_RICH = False


def print_banner():
    """Render the tool signature with the big wordmark. rich + THEME if available."""
    if _HAS_RICH:
        from rich.align import Align
        from rich.console import Group
        art = Text(WORDMARK, style=THEME["banner"], no_wrap=True, overflow="ignore")
        sub = Text(SUBTITLE, style=THEME["subtitle"])
        desc = Text("\n" + DESCRIPTION + "\n", style=THEME["description"])
        foot = Text()
        foot.append(VERSION, style=THEME["meta"])
        foot.append("   •   ", style=THEME["border"])
        foot.append(f"by {AUTHOR}", style=THEME["author"])
        body = Group(art, Text(), sub, desc, foot)
        _console.print(Panel(body, border_style=THEME["border"], expand=False,
                             padding=(1, 3)))
    else:
        print(WORDMARK)
        print(f"  {SUBTITLE}")
        print(f"  {DESCRIPTION}")
        print(f"  {VERSION}  -  by {AUTHOR}")
        print("=" * 86)


# ---------------------------------------------------------------------------
# Interactive prompt helpers (use rich + THEME when available)
# ---------------------------------------------------------------------------

def _style(text: str, key: str) -> str:
    """Wrap text in rich markup for THEME[key], or return plain if no rich."""
    return f"[{THEME[key]}]{text}[/]" if _HAS_RICH else text


def say(text: str, key: str = "menu_item"):
    if _HAS_RICH:
        _console.print(_style(text, key))
    else:
        print(text)


def ask(label: str, default: str = "") -> str:
    """Free-text prompt with a default shown in brackets."""
    suffix = f" [{default}]" if default else ""
    if _HAS_RICH:
        _console.print(_style(f"{label}{suffix}: ", "prompt"), end="")
    else:
        print(f"{label}{suffix}: ", end="")
    val = input().strip()
    return val if val else default


def ask_int(label: str, default: int) -> int:
    while True:
        raw = ask(label, str(default))
        try:
            return int(raw)
        except ValueError:
            say("  Please enter a whole number.", "error")


def ask_choice(title: str, options: list[tuple[str, str]], default_idx: int = 0) -> str:
    """Render a numbered menu. options is a list of (value, description).
    Returns the chosen value."""
    say(f"\n{title}", "menu_title")
    for i, (val, desc) in enumerate(options, 1):
        num = _style(f"  {i})", "menu_number")
        item = _style(f"{val}", "highlight")
        tail = _style(f" - {desc}", "menu_item")
        if _HAS_RICH:
            _console.print(f"{num} {item}{tail}")
        else:
            print(f"  {i}) {val} - {desc}")
    while True:
        raw = ask("Choose", str(default_idx + 1))
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return options[idx][0]
        except ValueError:
            pass
        say("  Invalid choice, try again.", "error")


def ask_yesno(label: str, default: bool = True) -> bool:
    d = "Y/n" if default else "y/N"
    raw = ask(f"{label} ({d})", "").lower()
    if not raw:
        return default
    return raw.startswith("y")


def interactive_config(args):
    """Walk the author through every decision, mutating `args` in place.
    Returns the populated args namespace."""
    say("\nInteractive challenge builder - press Enter to accept the [default].\n",
        "subtitle")

    # --- flag ---
    say("STEP 1 / 5  ::  The flag", "menu_title")
    fmt = ask_choice("Flag format", [
        ("CTF{FLAG}",     "classic CTF{...}"),
        ("flag{FLAG}",    "lowercase flag{...}"),
        ("FLAG{FLAG}",    "uppercase FLAG{...}"),
        ("custom",        "type your own wrapper"),
    ])
    if fmt == "custom":
        say("  Use the literal word FLAG as the placeholder, e.g. myctf-FLAG-end", "coming_soon")
        args.wrapper = ask("Wrapper template", "CTF{FLAG}") or "CTF{FLAG}"
        if "FLAG" not in args.wrapper:
            args.wrapper += "{FLAG}"
    else:
        args.wrapper = fmt
    inner = ask("Flag text (inside the wrapper)", "r34ssembly_1s_fun")
    args.flag = inner
    say(f"  -> flag will be: {format_flag(args.wrapper, inner)}", "success")

    # --- method / scenario ---
    say("\nSTEP 2 / 5  ::  Hiding technique or attack scenario", "menu_title")
    choice = ask_choice("How should the flag be hidden?", [
        ("dns",          "scatter encoded flag across DNS subdomain labels (exfil trope)"),
        ("split-tcp",    "split across TCP payloads; player reassembles by index"),
        ("split-icmp",   "split across ICMP echo payloads; player reassembles"),
        ("http",         "bury in an HTTP session cookie; found via stream follow"),
        ("kerberoast",   "SCENARIO: Kerberoasting burst; flag in a service SPN"),
        ("ftp-creds",    "SCENARIO: plaintext FTP login; flag is the password"),
        ("telnet-creds", "SCENARIO: plaintext Telnet login; flag is the password"),
        ("http-basic",   "SCENARIO: HTTP Basic auth; flag in base64 user:pass"),
        ("arp-spoof",    "SCENARIO: ARP poisoning; flag in the gratuitous-ARP padding"),
        ("port-scan",    "SCENARIO: SYN sweep; flag in the open port's banner"),
        ("brute-force",  "SCENARIO: failed logins then success; flag is cracked pw"),
        ("c2-beacon",    "SCENARIO: fixed-interval C2 callbacks; flag in a beacon"),
    ])
    if choice in _SCENARIOS:
        args.scenario = choice
        say(f"  -> scenario '{choice}' will plant a detectable attack signature.",
            "warning")
    else:
        args.scenario = "none"
        args.method = choice

    # --- encoding ---
    say("\nSTEP 3 / 5  ::  Encoding & obfuscation", "menu_title")
    args.encode = ask_choice("Encoding applied before hiding?", [
        ("base32", "DNS-label safe; good default"),
        ("base64", "compact, recognizable"),
        ("hex",    "simplest to spot/decode"),
        ("none",   "plaintext (easy mode)"),
    ])
    if ask_yesno("Add a second XOR layer to defeat lazy `strings` sweeps?", False):
        args.xor = ask("XOR key", "sekret")
    else:
        args.xor = ""

    # --- noise volumes ---
    say("\nSTEP 4 / 5  ::  Background traffic (sessions per protocol)", "menu_title")
    say("  Each session expands into several real packets (handshake, data, acks).",
        "coming_soon")
    args.http  = ask_int("  HTTP sessions",  15)
    args.https = ask_int("  HTTPS sessions", 12)
    args.dns   = ask_int("  DNS exchanges",  20)
    args.tcp   = ask_int("  Other TCP service sessions", 12)
    args.udp   = ask_int("  UDP/DNS chatter", 10)
    args.icmp  = ask_int("  ICMP pings",      8)
    args.arp   = ask_int("  ARP exchanges",   10)
    args.dhcp  = ask_int("  DHCP handshakes", 2)
    args.clients = ask_int("  Distinct client hosts on the LAN", 6)
    args.decoys = ask_int("  Decoy/red-herring fake flags", 3)
    args.normalize = ask_yesno("  Normalize timing (even spacing, tidy capture)?", False)

    # --- output ---
    say("\nSTEP 5 / 5  ::  Output & reproducibility", "menu_title")
    seed_raw = ask("Seed (blank = random each run)", "")
    args.seed = int(seed_raw) if seed_raw.strip().lstrip("-").isdigit() else None
    say("  (just a name - .pcap / .txt are added automatically)", "coming_soon")
    args.out = ask("Output pcap name", "challenge")
    args.answer_key = ask("Answer-key name (blank = <out>_answer)", "")

    # --- summary / confirm ---
    say("\n" + "-" * 50, "border")
    say("Ready to generate:", "subtitle")
    say(f"  flag      : {format_flag(args.wrapper, args.flag)}", "meta")
    challenge = args.scenario if args.scenario != "none" else args.method
    say(f"  challenge : {challenge}", "meta")
    say(f"  encoding  : {args.encode}" + (" + XOR" if args.xor else ""), "meta")
    sessions = (args.http + args.https + args.dns + args.tcp + args.udp +
                args.icmp + args.arp + args.dhcp)
    say(f"  traffic   : ~{sessions} sessions across {args.clients} hosts + carrier", "meta")
    say(f"  timing    : {'normalized' if args.normalize else 'realistic jitter'}", "meta")
    say(f"  output    : {args.out}.pcap (+ answer key)", "meta")
    say("-" * 50, "border")
    if not ask_yesno("\nGenerate now?", True):
        say("Aborted.", "warning")
        sys.exit(0)
    return args

# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def dns_safe_scheme(scheme: str) -> str:
    """DNS labels are case-insensitive and limited to letters/digits/hyphen, so
    base64 (and plaintext) can't survive. Coerce to a DNS-safe encoding."""
    return scheme if scheme in ("hex", "base32") else "base32"


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
    raise ValueError(f"unknown scheme: {scheme}")


def describe_decode(scheme: str, xor_key: bytes | None) -> str:
    steps = []
    if scheme == "hex":
        steps.append("hex-decode")
    elif scheme == "base64":
        steps.append("base64-decode")
    elif scheme == "base32":
        steps.append("base32-decode (re-pad with '=' to a multiple of 8)")
    if xor_key:
        steps.append(f"XOR with key {xor_key!r}")
    if not steps:
        steps.append("read as plaintext")
    return " then ".join(steps)


# challenges whose carrier lowercases the encoded flag (hostname/SPN labels)
_LOWERCASING = {"dns", "kerberoast"}
# challenges where the flag rides as a plaintext password unless --encode is set
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
            "base32": ["From Base32"], "none": []}.get(scheme, [])


def cyberchef_recipe(args) -> list:
    """Produce the exact ordered CyberChef recipe to recover the flag."""
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


# ---------------------------------------------------------------------------
# Noise generation
# ---------------------------------------------------------------------------

@dataclass
class NoiseConfig:
    subnet: str = "10.0.0.0/24"
    start_time: float = 1700000000.0
    jitter: float = 0.35          # session spacing (seconds), scaled
    seed: int | None = None
    normalize: bool = False       # even out timestamps for a "clean" capture
    n_clients: int = 6            # how many distinct client hosts on the LAN


def _rand_ip(net: ipaddress.IPv4Network, rng: random.Random) -> str:
    hosts = int(net.network_address) + 1
    last = int(net.broadcast_address) - 1
    return str(ipaddress.IPv4Address(rng.randint(hosts, last)))


# --- realistic data tables -------------------------------------------------

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]
_WEB_HOSTS = [
    ("www.example.com", "93.184.216.34"),
    ("api.weather.io", "104.18.32.7"),
    ("cdn.jsdelivr.net", "151.101.1.229"),
    ("update.microsoft.com", "23.45.112.61"),
    ("telemetry.corp.local", "10.0.0.20"),
    ("intranet.corp.local", "10.0.0.21"),
]
_PATHS = ["/", "/index.html", "/login", "/api/v1/status", "/static/app.js",
          "/assets/logo.png", "/dashboard", "/favicon.ico", "/health"]
_HTML_BODY = (
    "<!DOCTYPE html><html><head><title>{title}</title>"
    "<meta charset='utf-8'></head><body><h1>{title}</h1>"
    "<p>Welcome. Your session id is {sid}.</p>"
    "<ul><li>Reports</li><li>Settings</li><li>Logout</li></ul></body></html>"
)
_SERVER_BANNERS = ["nginx/1.24.0", "Apache/2.4.58 (Ubuntu)",
                   "Microsoft-IIS/10.0", "cloudflare"]


def _rand_mac(rng: random.Random) -> str:
    # locally-administered, unicast; vendor-ish OUIs
    oui = rng.choice([(0x00, 0x1a, 0x2b), (0x3c, 0x5a, 0xb4),
                      (0xf0, 0x9f, 0xc2), (0x00, 0x0c, 0x29),
                      (0xac, 0xde, 0x48)])
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        oui[0], oui[1], oui[2],
        rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255))


@dataclass
class Host:
    ip: str
    mac: str
    role: str
    name: str = ""


@dataclass
class Network:
    gateway: Host
    dns: Host
    clients: list
    servers: dict          # hostname -> Host
    subnet: ipaddress.IPv4Network

    def mac_for(self, ip: str) -> str:
        for h in [self.gateway, self.dns, *self.clients, *self.servers.values()]:
            if h.ip == ip:
                return h.mac
        # in-subnet but unknown -> deterministic mac; external -> gateway (routed)
        addr = ipaddress.IPv4Address(ip)
        if addr in self.subnet:
            seed = int(addr) & 0xFFFFFF
            return "02:%02x:%02x:%02x:%02x:%02x" % (
                (seed >> 16) & 0xFF, (seed >> 8) & 0xFF, seed & 0xFF,
                (int(addr) >> 8) & 0xFF, int(addr) & 0xFF)
        return self.gateway.mac


def build_network(cfg: NoiseConfig, rng: random.Random) -> Network:
    net = ipaddress.IPv4Network(cfg.subnet)
    base = int(net.network_address)
    gateway = Host(str(ipaddress.IPv4Address(base + 1)), _rand_mac(rng), "gateway", "gw")
    dns = Host(str(ipaddress.IPv4Address(base + 53)), _rand_mac(rng), "dns", "resolver")
    clients = [Host(str(ipaddress.IPv4Address(base + 100 + i)), _rand_mac(rng),
                    "client", f"host-{i+1:02d}") for i in range(cfg.n_clients)]
    servers = {}
    for name, ip in _WEB_HOSTS:
        addr = ipaddress.IPv4Address(ip)
        mac = _rand_mac(rng) if addr in net else gateway.mac  # external via gw
        servers[name] = Host(ip, mac, "server", name)
    return Network(gateway, dns, clients, servers, net)


# --- TLS-ish payload crafting ----------------------------------------------

def _tls_record(ctype: int, body: bytes, ver=b"\x03\x03") -> bytes:
    return bytes([ctype]) + ver + len(body).to_bytes(2, "big") + body


def _tls_client_hello(sni: str, rng: random.Random) -> bytes:
    rnd = bytes(rng.getrandbits(8) for _ in range(32))
    sni_b = sni.encode()
    server_name = b"\x00" + len(sni_b).to_bytes(2, "big") + sni_b
    sni_list = (len(server_name).to_bytes(2, "big") + server_name)
    sni_ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    exts = sni_ext
    body = (b"\x03\x03" + rnd + b"\x00" +              # ver, random, sid len
            b"\x00\x04\x13\x01\x13\x02" +              # cipher suites (2)
            b"\x01\x00" +                              # compression
            len(exts).to_bytes(2, "big") + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body  # handshake: client_hello
    return _tls_record(0x16, hs, ver=b"\x03\x01")


def _tls_app_data(n: int, rng: random.Random) -> bytes:
    return _tls_record(0x17, bytes(rng.getrandbits(8) for _ in range(n)))


# --- HTTP payload crafting -------------------------------------------------

def _http_request(host: str, path: str, ua: str) -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
            f"Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip, deflate\r\n"
            f"Connection: keep-alive\r\n\r\n").encode()


def _http_response(rng: random.Random, host: str) -> bytes:
    sid = "%016x" % rng.getrandbits(64)
    body = _HTML_BODY.format(title=host.split(".")[0].capitalize(), sid=sid)
    hdr = (f"HTTP/1.1 200 OK\r\nServer: {rng.choice(_SERVER_BANNERS)}\r\n"
           f"Date: Mon, 24 Jun 2024 10:15:32 GMT\r\nContent-Type: text/html; charset=UTF-8\r\n"
           f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\n"
           f"Set-Cookie: sid={sid}; HttpOnly; Path=/\r\n\r\n")
    return (hdr + body).encode()


# --- conversation engine ---------------------------------------------------

def _emit(pkts, frame, clock, rng, delta):
    clock[0] += delta
    frame.time = clock[0]
    pkts.append(frame)


def _eth(net: Network, src_ip: str, dst_ip: str):
    return Ether(src=net.mac_for(src_ip), dst=net.mac_for(dst_ip))


def tcp_session(net: Network, client: Host, server: Host, dport: int,
                exchanges: list, rng: random.Random, clock: list[float],
                cfg: NoiseConfig) -> list:
    """A full TCP session: 3-way handshake, the given data exchanges (each a
    ('c2s'|'s2c', payload bytes) tuple), then a clean FIN/ACK teardown.
    Sequence and ack numbers are tracked correctly throughout."""
    pkts = []
    sport = rng.randint(1025, 65535)
    cseq = rng.randint(1, 2**31)
    sseq = rng.randint(1, 2**31)
    rtt = abs(rng.gauss(0.03, 0.015)) + 0.002
    ttl_c, ttl_s = rng.choice([64, 128]), rng.choice([64, 128, 255])

    def c2s(flags, load=b"", **kw):
        return (_eth(net, client.ip, server.ip) /
                IP(src=client.ip, dst=server.ip, ttl=ttl_c) /
                TCP(sport=sport, dport=dport, flags=flags, seq=cseq, ack=sseq, **kw) /
                (Raw(load=load) if load else b""))

    def s2c(flags, load=b"", **kw):
        return (_eth(net, server.ip, client.ip) /
                IP(src=server.ip, dst=client.ip, ttl=ttl_s) /
                TCP(sport=dport, dport=sport, flags=flags, seq=sseq, ack=cseq, **kw) /
                (Raw(load=load) if load else b""))

    # handshake
    _emit(pkts, c2s("S"), clock, rng, rtt); cseq += 1
    _emit(pkts, s2c("SA"), clock, rng, rtt); sseq += 1
    _emit(pkts, c2s("A"), clock, rng, rtt)
    # data
    for direction, load in exchanges:
        if direction == "c2s":
            _emit(pkts, c2s("PA", load), clock, rng, rtt); cseq += len(load)
            _emit(pkts, s2c("A"), clock, rng, rtt)
        else:
            _emit(pkts, s2c("PA", load), clock, rng, rtt); sseq += len(load)
            _emit(pkts, c2s("A"), clock, rng, rtt)
    # teardown
    _emit(pkts, c2s("FA"), clock, rng, rtt); cseq += 1
    _emit(pkts, s2c("FA"), clock, rng, rtt); sseq += 1
    _emit(pkts, c2s("A"), clock, rng, rtt)
    return pkts


def conv_http(net, rng, clock, cfg):
    client = rng.choice(net.clients)
    host = rng.choice([h for h in net.servers if not h.endswith(".local")] or list(net.servers))
    server = net.servers[host]
    req = _http_request(host, rng.choice(_PATHS), rng.choice(_USER_AGENTS))
    resp = _http_response(rng, host)
    return tcp_session(net, client, server, 80,
                       [("c2s", req), ("s2c", resp)], rng, clock, cfg)


def conv_https(net, rng, clock, cfg):
    client = rng.choice(net.clients)
    host = rng.choice(list(net.servers))
    server = net.servers[host]
    ch = _tls_client_hello(host, rng)
    sh = _tls_record(0x16, bytes(rng.getrandbits(8) for _ in range(rng.randint(600, 1400))))
    exch = [("c2s", ch), ("s2c", sh),
            ("c2s", _tls_app_data(rng.randint(80, 400), rng)),
            ("s2c", _tls_app_data(rng.randint(200, 1200), rng))]
    return tcp_session(net, client, server, 443, exch, rng, clock, cfg)


def conv_dns(net, rng, clock, cfg):
    client = rng.choice(net.clients)
    host = rng.choice(list(net.servers))
    answer_ip = net.servers[host].ip
    txid = rng.randint(0, 65535)
    sport = rng.randint(1025, 65535)
    rtt = abs(rng.gauss(0.02, 0.01)) + 0.002
    q = (_eth(net, client.ip, net.dns.ip) /
         IP(src=client.ip, dst=net.dns.ip) /
         UDP(sport=sport, dport=53) /
         DNS(rd=1, id=txid, qd=DNSQR(qname=host)))
    a = (_eth(net, net.dns.ip, client.ip) /
         IP(src=net.dns.ip, dst=client.ip) /
         UDP(sport=53, dport=sport) /
         DNS(id=txid, qr=1, ra=1, qd=DNSQR(qname=host),
             an=DNSRR(rrname=host, type="A", ttl=rng.choice([60, 300, 3600]),
                      rdata=answer_ip)))
    pkts = []
    _emit(pkts, q, clock, rng, rtt)
    _emit(pkts, a, clock, rng, rtt)
    return pkts


def conv_icmp(net, rng, clock, cfg):
    client = rng.choice(net.clients)
    target = rng.choice(list(net.servers.values()))
    icmp_id = rng.randint(0, 65535)
    payload = (b"abcdefghijklmnopqrstuvwabcdefghi"
               + rng.randint(0, 2**32 - 1).to_bytes(4, "big"))
    rtt = abs(rng.gauss(0.025, 0.01)) + 0.002
    pkts = []
    for seq in range(1, rng.randint(2, 5)):
        req = (_eth(net, client.ip, target.ip) /
               IP(src=client.ip, dst=target.ip, ttl=64) /
               ICMP(type=8, id=icmp_id, seq=seq) / Raw(load=payload))
        rep = (_eth(net, target.ip, client.ip) /
               IP(src=target.ip, dst=client.ip, ttl=rng.choice([64, 128])) /
               ICMP(type=0, id=icmp_id, seq=seq) / Raw(load=payload))
        _emit(pkts, req, clock, rng, rtt)
        _emit(pkts, rep, clock, rng, rtt)
    return pkts


def conv_tcp_generic(net, rng, clock, cfg):
    """A generic short TCP service session (ssh-ish / db-ish) with a little
    banner data so the stream isn't empty."""
    client = rng.choice(net.clients)
    server = rng.choice(list(net.servers.values()))
    dport = rng.choice([22, 3306, 5432, 8080, 6379])
    banner = {22: b"SSH-2.0-OpenSSH_9.6\r\n", 3306: b"\x4a\x00\x00\x00\x0a8.0.36",
              5432: b"R\x00\x00\x00\x08\x00\x00\x00\x00", 6379: b"+OK\r\n",
              8080: b"HTTP/1.1 401 Unauthorized\r\nServer: gunicorn\r\n\r\n"}.get(dport, b"hello\r\n")
    exch = [("s2c", banner), ("c2s", bytes(rng.getrandbits(8) for _ in range(rng.randint(16, 64))))]
    return tcp_session(net, client, server, dport, exch, rng, clock, cfg)


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(b, 16) for b in mac.split(":"))


def conv_arp(net, rng, clock, cfg):
    """ARP who-has / is-at exchange between a client and the gateway."""
    client = rng.choice(net.clients)
    target = rng.choice([net.gateway, net.dns, *net.clients])
    if target.ip == client.ip:
        target = net.gateway
    req = (Ether(src=client.mac, dst="ff:ff:ff:ff:ff:ff") /
           ARP(op=1, hwsrc=client.mac, psrc=client.ip, pdst=target.ip))
    rep = (Ether(src=target.mac, dst=client.mac) /
           ARP(op=2, hwsrc=target.mac, psrc=target.ip,
               hwdst=client.mac, pdst=client.ip))
    pkts = []
    _emit(pkts, req, clock, rng, 0.001)
    _emit(pkts, rep, clock, rng, abs(rng.gauss(0.003, 0.001)) + 0.001)
    return pkts


def conv_dhcp(net, rng, clock, cfg):
    """A DHCP DORA handshake (Discover, Offer, Request, Ack)."""
    client = rng.choice(net.clients)
    chaddr = _mac_bytes(client.mac) + b"\x00" * 10
    xid = rng.randint(1, 2**32 - 1)
    gw, ip = net.gateway, client.ip
    pkts = []

    def boot(msgtype, src_ip, dst_ip, src_mac, dst_mac, yiaddr="0.0.0.0", opts=None):
        o = [("message-type", msgtype)] + (opts or []) + ["end"]
        return (Ether(src=src_mac, dst=dst_mac) /
                IP(src=src_ip, dst=dst_ip) / UDP(sport=68 if "0.0.0.0" == src_ip or msgtype in ("discover", "request") else 67,
                                                 dport=67 if msgtype in ("discover", "request") else 68) /
                BOOTP(chaddr=chaddr, xid=xid, yiaddr=yiaddr, ciaddr="0.0.0.0") /
                DHCP(options=o))

    disc = boot("discover", "0.0.0.0", "255.255.255.255", client.mac, "ff:ff:ff:ff:ff:ff")
    offer = boot("offer", gw.ip, "255.255.255.255", gw.mac, client.mac, yiaddr=ip,
                 opts=[("server_id", gw.ip), ("lease_time", 86400),
                       ("subnet_mask", "255.255.255.0"), ("router", gw.ip)])
    req = boot("request", "0.0.0.0", "255.255.255.255", client.mac, "ff:ff:ff:ff:ff:ff",
               opts=[("requested_addr", ip), ("server_id", gw.ip)])
    ack = boot("ack", gw.ip, "255.255.255.255", gw.mac, client.mac, yiaddr=ip,
               opts=[("server_id", gw.ip), ("lease_time", 86400),
                     ("subnet_mask", "255.255.255.0"), ("router", gw.ip)])
    for p in (disc, offer, req, ack):
        _emit(pkts, p, clock, rng, abs(rng.gauss(0.02, 0.01)) + 0.002)
    return pkts


_CONV_DISPATCH = {
    "tcp": conv_tcp_generic, "http": conv_http, "https": conv_https,
    "dns": conv_dns, "icmp": conv_icmp, "arp": conv_arp, "dhcp": conv_dhcp,
}


def make_noise(proto: str, count: int, cfg: NoiseConfig, rng: random.Random,
               clock: list[float], net: Network) -> list:
    """Generate `count` realistic *sessions* of `proto`. Each session expands
    into several packets (handshake, data, acks, teardown)."""
    # 'udp' maps onto DNS-style request/response service chatter
    fn = _CONV_DISPATCH.get("dns" if proto == "udp" else proto)
    if fn is None:
        raise ValueError(f"unknown protocol: {proto}")
    pkts = []
    for _ in range(count):
        clock[0] += abs(rng.gauss(cfg.jitter, cfg.jitter / 2))  # idle gap between sessions
        pkts += fn(net, rng, clock, cfg)
    return pkts


# ---------------------------------------------------------------------------
# Flag-hiding methods
# ---------------------------------------------------------------------------

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


def make_decoys(wrapper: str, count: int, cfg: NoiseConfig, rng: random.Random,
                clock: list[float], net: Network) -> list:
    """Plant plausible-but-wrong flag-shaped strings as red herrings, carried in
    real-looking HTTP traffic between actual hosts."""
    open_, close = wrapper_parts(wrapper)
    fakes = ["n0t_th3_fl4g", "almost_but_no", "red_herring_42", "keep_looking",
             "def_not_it", "try_again_lol"]
    pkts = []
    for _ in range(count):
        client = rng.choice(net.clients)
        server = rng.choice(list(net.servers.values()))
        body = (f"HTTP/1.1 200 OK\r\nServer: {rng.choice(_SERVER_BANNERS)}\r\n"
                f"Content-Type: text/plain\r\n\r\n"
                f"# debug note: {open_}{rng.choice(fakes)}{close}\n").encode()
        p = (_eth(net, server.ip, client.ip) /
             IP(src=server.ip, dst=client.ip) /
             TCP(sport=80, dport=rng.randint(1025, 65535), flags="PA",
                 seq=rng.randint(0, 2**32 - 1)) / Raw(load=body))
        clock[0] += abs(rng.gauss(cfg.jitter, cfg.jitter / 2)) + 0.001
        p.time = clock[0]
        pkts.append(p)
    return pkts


# ---------------------------------------------------------------------------
# Scenario engine: plant a recognizable ATTACK signature that also carries the
# flag. These are detection fixtures - the encrypted/credential material is
# synthetic. The player must first NOTICE the attack, then extract the flag.
# ---------------------------------------------------------------------------

def _krb_tgs_req(spn: str, realm: str, rng: random.Random) -> bytes:
    """Craft a recognizable (not byte-perfect) Kerberos TGS-REQ over TCP:
    the 4-byte length prefix, the APPLICATION-12 tag, an RC4/etype-23 marker,
    and the SPN/realm as KerberosStrings so an analyst can read them."""
    def kstr(s: str) -> bytes:                      # GeneralString, tag 0x1b
        b = s.encode()
        return b"\x1b" + bytes([len(b)]) + b
    etype = b"\x02\x01\x17"                          # INTEGER 23 (rc4-hmac)
    svc, host = (spn.split("/", 1) + [""])[:2]
    body = (b"\x6c\x82" +                            # APPLICATION 12 (TGS-REQ), long form
            b"\x00\x00" +                            # (placeholder length)
            b"\xa1\x03\x02\x01\x05" +                # pvno 5
            b"\xa2\x03\x02\x01\x0c" +                # msg-type 12 (TGS-REQ)
            etype + kstr(realm) + kstr(svc) + kstr(host))
    body = body[:2] + len(body[4:]).to_bytes(2, "big") + body[4:]
    return len(body).to_bytes(4, "big") + body      # TCP length prefix


def _krb_tgs_rep(realm: str, rng: random.Random) -> bytes:
    """A synthetic Kerberos TGS-REP (APPLICATION 13) whose enc-part is an opaque
    RC4-looking blob - this is the 'encrypted ticket' a real Kerberoast would crack."""
    def kstr(s):
        b = s.encode(); return b"\x1b" + bytes([len(b)]) + b
    ticket_blob = bytes(rng.getrandbits(8) for _ in range(rng.randint(180, 360)))
    enc_part = b"\xa2\x82" + len(ticket_blob).to_bytes(2, "big") + ticket_blob
    body = (b"\x6d\x82" + b"\x00\x00" +                 # APPLICATION 13 (TGS-REP)
            b"\xa0\x03\x02\x01\x05" +                   # pvno 5
            b"\xa1\x03\x02\x01\x0d" +                   # msg-type 13
            kstr(realm) + b"\x02\x01\x17" + enc_part)   # realm, etype 23, enc ticket
    body = body[:2] + len(body[4:]).to_bytes(2, "big") + body[4:]
    return len(body).to_bytes(4, "big") + body


def scenario_kerberoast(flag: bytes, rng, clock, cfg, scheme, xor_key,
                        net: Network) -> HideResult:
    """A burst of Kerberos TGS-REQ for many service SPNs (etype 23 / RC4) - the
    textbook Kerberoasting signature. One SPN's host label is the encoded flag.
    Each SPN is its own clean TCP connection (handshake, request, encrypted
    TGS-REP, teardown) so the streams look real and follow cleanly."""
    enc = encode_payload(flag, dns_safe_scheme(scheme), xor_key).decode().lower()
    realm = "CORP.LOCAL"
    attacker = rng.choice(net.clients)
    dc = net.servers.get("intranet.corp.local") or rng.choice(list(net.servers.values()))
    normal_spns = ["MSSQLSvc/db01.corp.local:1433", "HTTP/web01.corp.local",
                   "CIFS/file01.corp.local", "LDAP/dc01.corp.local",
                   "MSSQLSvc/erp.corp.local:1433", "HTTP/intranet.corp.local"]
    flag_spn = f"MSSQLSvc/{enc}.corp.local:1433"     # the odd one out
    spns = normal_spns[:]
    spns.insert(rng.randint(1, len(spns) - 1), flag_spn)

    res = HideResult()
    for spn in spns:
        req = _krb_tgs_req(spn, realm, rng)
        rep = _krb_tgs_rep(realm, rng)
        # each SPN request is its own short TCP/88 connection
        session = tcp_session(net, attacker, dc, 88,
                              [("c2s", req), ("s2c", rep)], rng, clock, cfg)
        res.packets += session
        # tag the request packet (the one carrying this SPN's bytes)
        for p in session:
            if p.haslayer(Raw) and req in bytes(p[Raw].load):
                if spn == flag_spn:
                    res.mark(p, "Kerberoast TGS-REQ with the anomalous SPN "
                                "(host label = encoded flag)")
                else:
                    res.mark(p, f"Kerberoast TGS-REQ for {spn} (decoy SPN)")
                break
        # small gap before the next connection in the burst
        clock[0] += abs(rng.gauss(0.04, 0.02)) + 0.005
    res.solution = [
        f"Notice the burst of Kerberos TGS-REQ (TCP/88) from {attacker.ip} to the DC "
        f"({dc.ip}) requesting many SPNs with RC4/etype-23 - classic Kerberoasting.",
        "List the requested SPNs; one MSSQLSvc host label is not a real hostname.",
        f"Take that host label and {describe_decode(dns_safe_scheme(scheme), xor_key)} "
        f"to recover the flag.",
    ]
    return res


def scenario_ftp_creds(flag: bytes, rng, clock, cfg, scheme, xor_key,
                       net: Network) -> HideResult:
    """A plaintext FTP login over TCP/21. The flag is the password sent in the
    clear - the 'credentials on the wire' trope. Found by following the stream."""
    # plaintext is the whole point; only encode if explicitly asked
    if scheme == "none":
        secret = flag.decode()
    else:
        secret = encode_payload(flag, scheme, xor_key).decode()
    client = rng.choice(net.clients)
    server = net.servers.get("intranet.corp.local") or rng.choice(list(net.servers.values()))
    user = rng.choice(["svc_backup", "jdoe", "ftpadmin", "deploy"])
    exch = [
        ("s2c", b"220 (vsFTPd 3.0.5)\r\n"),
        ("c2s", f"USER {user}\r\n".encode()),
        ("s2c", b"331 Please specify the password.\r\n"),
        ("c2s", f"PASS {secret}\r\n".encode()),
        ("s2c", b"230 Login successful.\r\n"),
        ("c2s", b"SYST\r\n"),
        ("s2c", b"215 UNIX Type: L8\r\n"),
    ]
    pkts = tcp_session(net, client, server, 21, exch, rng, clock, cfg)
    res = HideResult(packets=pkts)
    for p in pkts:
        if p.haslayer(Raw) and bytes(p[Raw].load).startswith(b"PASS "):
            res.mark(p, "FTP PASS command carrying the flag (cleartext password)")
            break
    tail = "read the password directly" if scheme == "none" else \
        f"take the password and {describe_decode(scheme, xor_key)}"
    res.solution = [
        f"Spot the plaintext FTP login (TCP/21) from {client.ip} to {server.ip}.",
        f"Follow the FTP control stream; the USER is '{user}' and the PASS line "
        f"carries the secret.",
        f"To get the flag, {tail}.",
    ]
    return res


def scenario_arp_spoof(flag: bytes, rng, clock, cfg, scheme, xor_key,
                       net: Network) -> HideResult:
    """ARP cache poisoning: the attacker floods gratuitous/conflicting is-at
    replies binding the gateway IP to the attacker's MAC. The encoded flag rides
    in the Ethernet padding of the malicious gratuitous ARP."""
    from scapy.all import Padding
    enc = encode_payload(flag, scheme if scheme != "none" else "base64", xor_key)
    attacker = rng.choice(net.clients)
    victim = rng.choice([c for c in net.clients if c.ip != attacker.ip])
    gw = net.gateway
    res = HideResult()
    # a few legitimate ARP first (handled by noise), then the poisoning storm:
    for i in range(rng.randint(4, 6)):
        # gratuitous/unsolicited is-at: "gateway IP is at ATTACKER mac" (the lie)
        poison = (Ether(src=attacker.mac, dst=victim.mac) /
                  ARP(op=2, hwsrc=attacker.mac, psrc=gw.ip,
                      hwdst=victim.mac, pdst=victim.ip))
        if i == 0:
            poison = poison / Padding(load=enc)   # flag tucked in the padding
        clock[0] += abs(rng.gauss(0.5, 0.2)) + 0.05
        poison.time = clock[0]
        res.packets.append(poison)
        if i == 0:
            res.mark(poison, "Malicious gratuitous ARP (gw IP -> attacker MAC); "
                             "flag is in the Ethernet padding/trailer")
        else:
            res.mark(poison, "Poisoned ARP is-at reply (decoy in the storm)")
    actual = scheme if scheme != "none" else "base64"
    res.solution = [
        f"Spot the ARP poisoning: host {attacker.ip} ({attacker.mac}) repeatedly "
        f"claims to be the gateway {gw.ip} via gratuitous is-at replies.",
        "Open the first poisoned ARP packet; the Ethernet trailer/padding holds "
        "extra non-zero bytes (not normal ARP padding).",
        f"Extract those padding bytes and {describe_decode(actual, xor_key)}.",
    ]
    return res


def scenario_port_scan(flag: bytes, rng, clock, cfg, scheme, xor_key,
                       net: Network) -> HideResult:
    """A SYN sweep across many ports of one host: closed ports answer RST, the one
    open port completes and serves a banner. The flag is in that banner."""
    enc = encode_payload(flag, scheme, xor_key).decode() if scheme != "none" else flag.decode()
    attacker = rng.choice(net.clients)
    target = rng.choice(list(net.servers.values()))
    ports = sorted(rng.sample(range(20, 1024), rng.randint(18, 28)))
    open_port = rng.choice(ports)
    res = HideResult()
    base_sport = rng.randint(20000, 40000)
    for i, port in enumerate(ports):
        sport = base_sport + i
        cseq = rng.randint(1, 2**31)
        syn = (_eth(net, attacker.ip, target.ip) / IP(src=attacker.ip, dst=target.ip) /
               TCP(sport=sport, dport=port, flags="S", seq=cseq))
        clock[0] += abs(rng.gauss(0.008, 0.003)) + 0.001
        syn.time = clock[0]
        res.packets.append(syn)
        if port == open_port:
            # SYN-ACK, ACK, then a service banner containing the flag
            sseq = rng.randint(1, 2**31)
            sa = (_eth(net, target.ip, attacker.ip) / IP(src=target.ip, dst=attacker.ip) /
                  TCP(sport=port, dport=sport, flags="SA", seq=sseq, ack=cseq + 1))
            ack = (_eth(net, attacker.ip, target.ip) / IP(src=attacker.ip, dst=target.ip) /
                   TCP(sport=sport, dport=port, flags="A", seq=cseq + 1, ack=sseq + 1))
            banner = f"220 svc ready - access token: {enc}\r\n".encode()
            data = (_eth(net, target.ip, attacker.ip) / IP(src=target.ip, dst=attacker.ip) /
                    TCP(sport=port, dport=sport, flags="PA", seq=sseq + 1, ack=cseq + 1) /
                    Raw(load=banner))
            for q in (sa, ack, data):
                clock[0] += abs(rng.gauss(0.01, 0.004)) + 0.001
                q.time = clock[0]
                res.packets.append(q)
            res.mark(data, f"Banner on the one OPEN port ({open_port}); flag is the 'access token'")
        else:
            # closed port -> RST/ACK
            rst = (_eth(net, target.ip, attacker.ip) / IP(src=target.ip, dst=attacker.ip) /
                   TCP(sport=port, dport=sport, flags="RA", seq=0, ack=cseq + 1))
            clock[0] += abs(rng.gauss(0.006, 0.002)) + 0.001
            rst.time = clock[0]
            res.packets.append(rst)
    tail = "read the token directly" if scheme == "none" else \
        f"take the token and {describe_decode(scheme, xor_key)}"
    res.solution = [
        f"Spot the SYN scan: {attacker.ip} sweeps ~{len(ports)} ports on {target.ip}; "
        f"closed ports reply RST.",
        f"Exactly one port ({open_port}) completes the handshake and returns a banner.",
        f"The banner's 'access token' is the flag - {tail}.",
    ]
    return res


def scenario_telnet_creds(flag: bytes, rng, clock, cfg, scheme, xor_key,
                          net: Network) -> HideResult:
    """Plaintext Telnet (TCP/23) login. The flag is the password typed in the clear."""
    secret = flag.decode() if scheme == "none" else encode_payload(flag, scheme, xor_key).decode()
    client = rng.choice(net.clients)
    server = rng.choice(list(net.servers.values()))
    user = rng.choice(["admin", "root", "operator", "netadmin"])
    exch = [
        ("s2c", b"\r\nUbuntu 22.04.3 LTS\r\nlogin: "),
        ("c2s", f"{user}\r\n".encode()),
        ("s2c", b"Password: "),
        ("c2s", f"{secret}\r\n".encode()),
        ("s2c", b"\r\nLast login: Tue Nov 14 09:02:11\r\n$ "),
    ]
    pkts = tcp_session(net, client, server, 23, exch, rng, clock, cfg)
    res = HideResult(packets=pkts)
    # the password is the c2s line right after the "Password:" prompt
    seen_prompt = False
    for p in pkts:
        if p.haslayer(Raw):
            load = bytes(p[Raw].load)
            if b"Password:" in load:
                seen_prompt = True
            elif seen_prompt and load.strip() and not load.startswith(b"\r\n"):
                res.mark(p, "Telnet password line (cleartext flag)")
                break
    tail = "read the password directly" if scheme == "none" else \
        f"take the password and {describe_decode(scheme, xor_key)}"
    res.solution = [
        f"Spot the plaintext Telnet login (TCP/23) from {client.ip} to {server.ip}.",
        f"Follow the stream; after the 'Password:' prompt the user '{user}' types the secret.",
        f"To get the flag, {tail}.",
    ]
    return res


def scenario_http_basic(flag: bytes, rng, clock, cfg, scheme, xor_key,
                        net: Network) -> HideResult:
    """HTTP Basic auth over cleartext. The Authorization header is
    base64("user:password") and the password is the flag."""
    pw = flag.decode() if scheme == "none" else encode_payload(flag, scheme, xor_key).decode()
    client = rng.choice(net.clients)
    server = net.servers.get("intranet.corp.local") or rng.choice(list(net.servers.values()))
    host = server.name
    user = rng.choice(["admin", "svc_web", "report_bot"])
    token = base64.b64encode(f"{user}:{pw}".encode()).decode()
    req = (f"GET /admin/ HTTP/1.1\r\nHost: {host}\r\n"
           f"Authorization: Basic {token}\r\n"
           f"User-Agent: {rng.choice(_USER_AGENTS)}\r\nAccept: */*\r\n\r\n").encode()
    resp = (b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
            b"Content-Type: text/html\r\nContent-Length: 13\r\n\r\n<h1>Admin</h1>")
    pkts = tcp_session(net, client, server, 80, [("c2s", req), ("s2c", resp)], rng, clock, cfg)
    res = HideResult(packets=pkts)
    for p in pkts:
        if p.haslayer(Raw) and b"Authorization: Basic" in bytes(p[Raw].load):
            res.mark(p, "HTTP Basic Authorization header (base64 user:flag)")
            break
    res.solution = [
        f"Spot the HTTP Basic auth (TCP/80) from {client.ip} to host {host}.",
        "Grab the 'Authorization: Basic <token>' header and base64-decode it.",
        "The part after the ':' is the password" +
        ("" if scheme == "none" else f", then {describe_decode(scheme, xor_key)}") + ".",
    ]
    return res


def scenario_brute_force(flag: bytes, rng, clock, cfg, scheme, xor_key,
                         net: Network) -> HideResult:
    """An FTP password brute-force: many failed logins, then one success. The flag
    is the password on the one attempt that worked."""
    secret = flag.decode() if scheme == "none" else encode_payload(flag, scheme, xor_key).decode()
    client = rng.choice(net.clients)
    server = rng.choice(list(net.servers.values()))
    user = rng.choice(["administrator", "svc_sql", "backup"])
    wrong = ["Password1", "letmein", "Summer2023", "Welcome1", "P@ssw0rd",
             "admin123", "qwerty", "changeme", "Spring2024!"]
    attempts = rng.sample(wrong, rng.randint(6, 9)) + [secret]  # success is last
    exch = [("s2c", b"220 ProFTPD Server ready.\r\n")]
    for i, pw in enumerate(attempts):
        exch.append(("c2s", f"USER {user}\r\n".encode()))
        exch.append(("s2c", b"331 Password required.\r\n"))
        exch.append(("c2s", f"PASS {pw}\r\n".encode()))
        exch.append(("s2c", b"230 User logged in.\r\n" if pw == secret
                     else b"530 Login incorrect.\r\n"))
    pkts = tcp_session(net, client, server, 21, exch, rng, clock, cfg)
    res = HideResult(packets=pkts)
    # mark the successful PASS (the one followed by 230)
    for i, p in enumerate(pkts):
        if p.haslayer(Raw) and bytes(p[Raw].load).startswith(f"PASS {secret}".encode()):
            res.mark(p, "Successful PASS after many failures (flag = cracked password)")
            break
    tail = "read the password directly" if scheme == "none" else \
        f"take the password and {describe_decode(scheme, xor_key)}"
    res.solution = [
        f"Spot the brute force: {len(attempts)-1} failed FTP logins (530) from "
        f"{client.ip} to {server.ip}, then one success (230).",
        f"The PASS on the successful attempt (account '{user}') is the secret.",
        f"To get the flag, {tail}.",
    ]
    return res


def scenario_c2_beacon(flag: bytes, rng, clock, cfg, scheme, xor_key,
                       net: Network) -> HideResult:
    """C2 beaconing: regular fixed-interval HTTP callbacks to one external host.
    The flag rides (encoded) in a beacon's POST body."""
    enc = encode_payload(flag, scheme if scheme != "none" else "base64", xor_key).decode()
    client = rng.choice(net.clients)
    c2 = rng.choice([s for n, s in net.servers.items() if not n.endswith(".local")]
                    or list(net.servers.values()))
    interval = rng.choice([5.0, 10.0, 15.0])      # fixed beacon interval
    n_beacons = rng.randint(5, 8)
    flag_beacon = rng.randint(1, n_beacons - 1)
    uri = "/api/v1/telemetry"
    res = HideResult()
    start = clock[0]
    for i in range(n_beacons):
        body = (f"id=7f3a&seq={i}&data=" +
                (enc if i == flag_beacon else base64.b64encode(
                    bytes(rng.getrandbits(8) for _ in range(12))).decode())).encode()
        req = (f"POST {uri} HTTP/1.1\r\nHost: {c2.name}\r\n"
               f"User-Agent: Mozilla/5.0 (Windows NT 10.0)\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(body)}\r\n\r\n").encode() + body
        resp = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 2\r\n\r\nok"
        # place each beacon at a fixed interval
        clock[0] = start + i * interval
        session = tcp_session(net, client, c2, 80, [("c2s", req), ("s2c", resp)],
                              rng, clock, cfg)
        res.packets += session
        for p in session:
            if p.haslayer(Raw) and b"POST " in bytes(p[Raw].load):
                if i == flag_beacon:
                    res.mark(p, f"C2 beacon #{i} whose POST body 'data=' carries the flag")
                else:
                    res.mark(p, f"C2 beacon #{i} (decoy callback)")
                break
    actual = scheme if scheme != "none" else "base64"
    res.solution = [
        f"Spot the C2 beaconing: {client.ip} POSTs to {c2.name} ({c2.ip}) every "
        f"~{interval:g}s - a suspiciously regular interval.",
        f"Inspect the beacon bodies; the 'data=' field of beacon #{flag_beacon} differs "
        f"from the random others.",
        f"Take that data value and {describe_decode(actual, xor_key)}.",
    ]
    return res


_SCENARIOS = {
    "kerberoast": scenario_kerberoast,
    "ftp-creds": scenario_ftp_creds,
    "telnet-creds": scenario_telnet_creds,
    "http-basic": scenario_http_basic,
    "arp-spoof": scenario_arp_spoof,
    "port-scan": scenario_port_scan,
    "brute-force": scenario_brute_force,
    "c2-beacon": scenario_c2_beacon,
}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def build_challenge(args) -> tuple[list, list[str], "Network"]:
    rng = random.Random(args.seed)
    cfg = NoiseConfig(subnet=args.subnet, seed=args.seed, jitter=args.jitter,
                      normalize=args.normalize, n_clients=args.clients)
    clock = [cfg.start_time]

    net = build_network(cfg, rng)

    flag_text = format_flag(args.wrapper, args.flag)
    flag_bytes = flag_text.encode()
    xor_key = args.xor.encode() if args.xor else None

    all_pkts = []
    # noise (counts are SESSIONS; each expands to several packets)
    for proto, n in (("arp", args.arp), ("dhcp", args.dhcp),
                     ("tcp", args.tcp), ("udp", args.udp), ("dns", args.dns),
                     ("icmp", args.icmp), ("http", args.http), ("https", args.https)):
        if n > 0:
            all_pkts += make_noise(proto, n, cfg, rng, clock, net)

    # decoys
    if args.decoys > 0:
        all_pkts += make_decoys(args.wrapper, args.decoys, cfg, rng, clock, net)

    # hidden flag: a scenario takes precedence over a plain hide method
    if args.scenario != "none":
        hr = _SCENARIOS[args.scenario](flag_bytes, rng, clock, cfg,
                                       args.encode, xor_key, net)
    elif args.method == "dns":
        hr = hide_dns_exfil(flag_bytes, cfg, rng, args.encode, xor_key, clock, net)
    elif args.method == "split-tcp":
        hr = hide_split_reassembly(flag_bytes, "tcp", cfg, rng, args.encode, xor_key, clock, net)
    elif args.method == "split-icmp":
        hr = hide_split_reassembly(flag_bytes, "icmp", cfg, rng, args.encode, xor_key, clock, net)
    elif args.method == "http":
        hr = hide_http_stream(flag_bytes, cfg, rng, args.encode, xor_key, clock, net)
    else:
        raise ValueError(f"unknown method: {args.method}")
    all_pkts += hr.packets

    # Interleave the carrier into the capture timeline. Carrier packets were
    # generated after the noise, so their timestamps are all latest; shift the
    # whole (internally-ordered) carrier burst to a random point within the
    # noise time span so it doesn't conspicuously sit at the very end.
    carrier = hr.packets
    carrier_ids = {id(p) for p in carrier}
    noise_pkts = [p for p in all_pkts if id(p) not in carrier_ids]
    if noise_pkts and carrier:
        t0 = min(float(p.time) for p in noise_pkts)
        t1 = max(float(p.time) for p in noise_pkts)
        cmin = min(float(p.time) for p in carrier)
        cmax = max(float(p.time) for p in carrier)
        span = cmax - cmin
        offset = rng.uniform(t0, max(t0, t1 - span))
        shift = offset - cmin
        for p in carrier:
            p.time = float(p.time) + shift

    # sort everything by time so carrier packets interleave with noise
    all_pkts.sort(key=lambda p: float(p.time))

    # normalize: re-space timestamps evenly for a tidy, uniform capture
    if cfg.normalize and all_pkts:
        gap = max(cfg.jitter, 0.01)
        t = cfg.start_time
        for p in all_pkts:
            t += gap
            p.time = t

    # resolve each tagged carrier packet to its final 1-based frame number
    frame_of = {id(p): i + 1 for i, p in enumerate(all_pkts)}
    located = [{"frame": frame_of.get(id(m["pkt"])), "desc": m["desc"]}
               for m in hr.markers]
    located = [m for m in located if m["frame"]]
    located.sort(key=lambda m: m["frame"])

    return all_pkts, hr.solution, net, located


def write_answer_key(path: str, args, solution: list[str], n_pkts: int,
                     located: list | None = None):
    flag_text = format_flag(args.wrapper, args.flag)
    challenge = challenge_name(args)
    eff, note = effective_encoding(args)
    enc_line = f"Encoding:       {eff}" + (f" + XOR('{args.xor}')" if args.xor else "")
    if note:
        enc_line += f"   [{note}]"
    lines = [
        "CTF CHALLENGE - ANSWER KEY",
        "=" * 48,
        f"Flag:           {flag_text}",
        f"Challenge:      {challenge}",
        enc_line,
        f"Seed:           {args.seed}",
        f"Total packets:  {n_pkts}",
        "",
        "INTENDED SOLVE PATH:",
    ]
    lines += [f"  {i}. {step}" for i, step in enumerate(solution, 1)]
    lines += ["", "CYBERCHEF RECIPE (gchq.github.io/CyberChef) - drag these in order:"]
    lines += [f"  {i}. {step}" for i, step in enumerate(cyberchef_recipe(args), 1)]
    if located:
        lines += ["", "FLAG CARRIER PACKETS (1-based frame numbers in the pcap):"]
        lines += [f"  frame {m['frame']:>5}  -  {m['desc']}" for m in located]
        lines += ["",
                  "  Verify in Wireshark: Ctrl-G (Go to packet) and enter the frame "
                  "number,",
                  "  or apply display filter  frame.number == <n>"]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def force_ext(path: str, ext: str) -> str:
    """Force a filename to end in `ext` (e.g. '.pcap'). Replaces any other
    extension so the user can just type a name."""
    import os
    root, cur = os.path.splitext(path)
    if cur.lower() == ext.lower():
        return path
    # if they typed something like 'round1.cap' or 'round1', normalize to ext
    return (root if cur else path) + ext


def self_check(pkts, args) -> bool:
    """Re-solve the generated capture to confirm the flag is recoverable.
    Returns True if the intended flag is found by following the solve path."""
    import base64 as _b64
    target = format_flag(args.wrapper, args.flag).encode()
    xor_key = args.xor.encode() if args.xor else None

    def eff_scheme():
        chal = args.scenario if args.scenario != "none" else args.method
        if chal in ("kerberoast", "dns"):
            return dns_safe_scheme(args.encode)
        if chal in ("arp-spoof", "c2-beacon"):
            return args.encode if args.encode != "none" else "base64"
        if chal == "http" and args.encode == "none":
            return "base64"
        return args.encode

    def undo(enc_bytes):
        try:
            scheme = eff_scheme()
            data = enc_bytes
            if scheme == "base32":
                pad = (-len(data)) % 8
                data = _b64.b32decode(data.upper() + b"=" * pad)
            elif scheme == "base64":
                data = _b64.b64decode(data)
            elif scheme == "hex":
                data = bytes.fromhex(data.decode())
            if xor_key:
                data = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(data))
            return data
        except Exception:
            return b""

    def hit(val):  # plaintext match or decoded match
        return val == target or undo(val) == target

    from scapy.all import Raw as _Raw, DNSQR as _DNSQR, Padding as _Padding
    import re as _re
    # --- scenarios ---
    if args.scenario in ("ftp-creds", "brute-force"):
        for p in pkts:
            if p.haslayer(_Raw) and bytes(p[_Raw].load).startswith(b"PASS "):
                secret = bytes(p[_Raw].load)[5:].split(b"\r")[0]
                if hit(secret):
                    return True
        return False
    if args.scenario == "telnet-creds":
        seen = False
        for p in pkts:
            if not p.haslayer(_Raw):
                continue
            load = bytes(p[_Raw].load)
            if b"Password:" in load:
                seen = True
            elif seen and load.strip():
                if hit(load.strip()):
                    return True
        return False
    if args.scenario == "http-basic":
        for p in pkts:
            if p.haslayer(_Raw) and b"Authorization: Basic " in bytes(p[_Raw].load):
                tok = bytes(p[_Raw].load).split(b"Authorization: Basic ")[1].split(b"\r")[0]
                try:
                    pw = _b64.b64decode(tok).split(b":", 1)[1]
                except Exception:
                    return False
                return hit(pw)
        return False
    if args.scenario == "arp-spoof":
        for p in pkts:
            if p.haslayer(_Padding):
                if hit(bytes(p[_Padding].load)):
                    return True
        return False
    if args.scenario == "port-scan":
        for p in pkts:
            if p.haslayer(_Raw):
                m = _re.search(rb"access token: (\S+)", bytes(p[_Raw].load))
                if m and hit(m.group(1)):
                    return True
        return False
    if args.scenario == "c2-beacon":
        for p in pkts:
            if p.haslayer(_Raw):
                m = _re.search(rb"data=([A-Za-z0-9+/=]+)", bytes(p[_Raw].load))
                if m and undo(m.group(1)) == target:
                    return True
        return False
    if args.scenario == "kerberoast":
        for p in pkts:
            if p.haslayer(_Raw) and p.haslayer(TCP) and p[TCP].dport == 88:
                load = bytes(p[_Raw].load)
                for m in _re.finditer(rb"([a-z0-9]+)\.corp\.local", load):
                    if undo(m.group(1)) == target:
                        return True
        return False

    if args.method == "dns":
        labels = {}
        for p in pkts:
            if p.haslayer(_DNSQR):
                q = p[_DNSQR].qname.decode().rstrip(".")
                if "tunnel.evil-c2.net" in q:
                    parts = q.split(".")
                    labels[int(parts[1])] = parts[0]
        enc = "".join(labels[k] for k in sorted(labels)).encode()
        return undo(enc) == target
    elif args.method in ("split-tcp", "split-icmp"):
        segs = []
        for p in pkts:
            if p.haslayer(_Raw):
                load = bytes(p[_Raw].load)
                if load.startswith(b"SEG"):
                    segs.append((load[3], load[4:]))
        segs.sort()
        enc = b"".join(c for _, c in segs)
        return undo(enc) == target
    elif args.method == "http":
        for p in pkts:
            if p.haslayer(_Raw):
                load = bytes(p[_Raw].load)
                if b"session=" in load and b"GET /dashboard" in load:
                    val = load.split(b"session=")[1].split(b";")[0].split(b"\r")[0]
                    return undo(val) == target
    return False


def main():
    ap = argparse.ArgumentParser(
        description="Generate a realistic network-forensics CTF pcap with a hidden flag.")
    # flag
    ap.add_argument("--flag", default="r34ssembly_1s_fun",
                    help="inner flag text (without the wrapper)")
    ap.add_argument("--wrapper", default=f"{DEFAULT_FLAG_PREFIX}{{FLAG}}",
                    help="flag wrapper; the literal 'FLAG' is replaced by --flag")
    # hiding
    ap.add_argument("--method", default="dns",
                    choices=["dns", "split-tcp", "split-icmp", "http"],
                    help="how the flag is hidden (ignored if --scenario is set)")
    ap.add_argument("--scenario", default="none",
                    choices=["none", "kerberoast", "ftp-creds", "telnet-creds",
                             "http-basic", "arp-spoof", "port-scan", "brute-force",
                             "c2-beacon"],
                    help="plant an attack signature that also carries the flag")
    ap.add_argument("--encode", default="base32",
                    choices=["none", "hex", "base64", "base32"],
                    help="encoding applied before hiding")
    ap.add_argument("--xor", default="",
                    help="optional XOR key applied before encoding (meatier)")
    ap.add_argument("--decoys", type=int, default=3,
                    help="number of red-herring fake flags to plant")
    # noise volumes (sessions; each expands to several packets)
    ap.add_argument("--tcp", type=int, default=12, help="generic TCP service sessions")
    ap.add_argument("--udp", type=int, default=10, help="(maps to DNS service chatter)")
    ap.add_argument("--dns", type=int, default=20, help="DNS query/response exchanges")
    ap.add_argument("--icmp", type=int, default=8, help="ICMP echo/reply pings")
    ap.add_argument("--http", type=int, default=15, help="HTTP request/response sessions")
    ap.add_argument("--https", type=int, default=12, help="TLS-looking HTTPS sessions")
    ap.add_argument("--arp", type=int, default=10, help="ARP who-has/is-at exchanges")
    ap.add_argument("--dhcp", type=int, default=2, help="DHCP DORA handshakes")
    ap.add_argument("--clients", type=int, default=6,
                    help="number of distinct client hosts on the LAN")
    # realism / timing
    ap.add_argument("--subnet", default="10.0.0.0/24")
    ap.add_argument("--jitter", type=float, default=0.35,
                    help="mean idle gap between sessions (seconds)")
    ap.add_argument("--normalize", action="store_true",
                    help="re-space all timestamps evenly for a tidy capture")
    ap.add_argument("--seed", type=int, default=None,
                    help="RNG seed for reproducible challenges")
    # output
    ap.add_argument("-o", "--out", default="challenge",
                    help="output pcap name; .pcap is added automatically")
    ap.add_argument("--answer-key", default="",
                    help="answer-key name; defaults to <out>_answer.txt")
    ap.add_argument("--no-check", action="store_true",
                    help="skip the post-generation solvability self-check")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("-i", "--interactive", action="store_true",
                    help="force the interactive menu even if other flags are given")
    args = ap.parse_args()

    # Bare launch (no args) or explicit -i -> interactive menu.
    go_interactive = args.interactive or len(sys.argv) == 1

    if not args.quiet:
        print_banner()

    if go_interactive:
        args = interactive_config(args)

    # force standard extensions; user only supplies a name
    args.out = force_ext(args.out, ".pcap")
    if not args.answer_key:
        import os
        args.answer_key = os.path.splitext(args.out)[0] + "_answer.txt"
    else:
        args.answer_key = force_ext(args.answer_key, ".txt")

    pkts, solution, net, located = build_challenge(args)
    wrpcap(args.out, pkts)
    write_answer_key(args.answer_key, args, solution, len(pkts), located)

    ok = None
    if not args.no_check:
        ok = self_check(pkts, args)

    if not args.quiet:
        _eff, _note = effective_encoding(args)
        if _note:
            say(f"[!] Encoding note: {_note}", "warning")
        say(f"[+] Wrote {len(pkts)} packets to {args.out}", "success")
        say(f"[+] Answer key -> {args.answer_key}", "success")
        say(f"[+] Hosts on LAN: {len(net.clients)} clients + gateway + resolver", "meta")
        say(f"[+] Flag: {format_flag(args.wrapper, args.flag)}", "highlight")
        if ok is True:
            say("[+] Self-check: flag is recoverable from the capture. OK", "success")
        elif ok is False:
            say("[!] Self-check: could NOT recover the flag - review settings!", "error")
        if located:
            say("[+] Flag carrier frame(s): "
                + ", ".join(str(m["frame"]) for m in located), "meta")
        say("[+] Solve path:", "menu_title")
        for i, s in enumerate(solution, 1):
            say(f"      {i}. {s}", "menu_item")


if __name__ == "__main__":
    main()
