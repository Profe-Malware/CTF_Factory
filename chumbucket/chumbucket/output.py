"""chumbucket.output - split module (code verbatim from the monolith)."""
import base64
import random
import textwrap
import os
import time
import re
from scapy.all import (TCP, Raw, DNS, DNSQR, BOOTP, DHCP, Padding)
from .encoding import (b58decode, challenge_name, decode_steps, dns_safe_scheme, effective_encoding)

from .ui import (format_flag)
from .network import (NoiseConfig, build_network)
from .traffic import (make_noise)
from .hiding import (hide_dns_exfil, hide_http_stream, hide_split_reassembly, make_decoys)
from .scenarios import (_SCENARIOS)


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
        "BRIEFING:",
    ]
    import textwrap
    for line in textwrap.wrap(challenge_briefing(args), 72):
        lines.append("  " + line)
    lines += ["", "INTENDED SOLVE PATH:"]
    lines += [f"  {i}. {step}" for i, step in enumerate(solution, 1)]
    lines += ["", "DECODE STEPS (apply in order, in any decoder or by hand):"]
    lines += [f"  {i}. {step}" for i, step in enumerate(decode_steps(args), 1)]
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
            elif scheme == "base58":
                data = b58decode(data)
            elif scheme == "urlencode":
                data = bytes.fromhex(data.replace(b"%", b"").decode())
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
                m = _re.search(rb"data=([^&\s]+)", bytes(p[_Raw].load))
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
                m = _re.search(rb"sid=([^&\s\"]+)", bytes(p[_Raw].load))
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
