"""chumbucket.traffic - split module (code verbatim from the monolith)."""
import gzip
import random
import copy
import json
from scapy.all import (IP, TCP, UDP, ICMP, Ether, Raw, DNS, DNSQR, DNSRR, ARP, BOOTP, DHCP)

from .network import (Host, Network, NoiseConfig, _emit, _eth, _mac_bytes)


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


def tcp_session(net: Network, client: Host, server: Host, dport: int,
                exchanges: list, rng: random.Random, clock: list[float],
                cfg: NoiseConfig) -> list:
    """A full TCP session: 3-way handshake, the given data exchanges (each a
    ('c2s'|'s2c', payload bytes) tuple), then a clean FIN/ACK teardown.
    Sequence and ack numbers are tracked correctly throughout. SYNs carry
    realistic options (MSS, SACK-permitted, timestamps, window scale) and hosts
    advertise believable window sizes, so packets look real on inspection."""
    pkts = []
    sport = rng.randint(1025, 65535)
    cseq = rng.randint(1, 2**31)
    sseq = rng.randint(1, 2**31)
    rtt = abs(rng.gauss(0.03, 0.015)) + 0.002
    ttl_c, ttl_s = rng.choice([64, 128]), rng.choice([64, 128, 255])
    # per-session TCP characteristics
    mss = rng.choice([1460, 1440, 1360])
    wsc_c, wsc_s = rng.choice([7, 8]), rng.choice([7, 8])
    syn_win_c = rng.choice([64240, 65535])
    syn_win_s = rng.choice([65160, 64240, 28960])
    est_win_c = rng.choice([501, 502, 509, 513, 1024])
    est_win_s = rng.choice([501, 502, 510, 1024, 2048])
    ts_c = [rng.randint(1_000_000, 4_000_000_000)]
    ts_s = [rng.randint(1_000_000, 4_000_000_000)]

    def _c_ts():
        ts_c[0] = (ts_c[0] + rng.randint(1, 40)) & 0xFFFFFFFF
        return ts_c[0]

    def _s_ts():
        ts_s[0] = (ts_s[0] + rng.randint(1, 40)) & 0xFFFFFFFF
        return ts_s[0]

    def c2s(flags, load=b"", win=None, opts=None):
        t = TCP(sport=sport, dport=dport, flags=flags, seq=cseq, ack=sseq,
                window=win if win is not None else est_win_c)
        if opts is not None:
            t.options = opts
        return (_eth(net, client.ip, server.ip) /
                IP(src=client.ip, dst=server.ip, ttl=ttl_c) /
                t / (Raw(load=load) if load else b""))

    def s2c(flags, load=b"", win=None, opts=None):
        t = TCP(sport=dport, dport=sport, flags=flags, seq=sseq, ack=cseq,
                window=win if win is not None else est_win_s)
        if opts is not None:
            t.options = opts
        return (_eth(net, server.ip, client.ip) /
                IP(src=server.ip, dst=client.ip, ttl=ttl_s) /
                t / (Raw(load=load) if load else b""))

    def est_c():
        return [('NOP', None), ('NOP', None), ('Timestamp', (_c_ts(), ts_s[0]))]

    def est_s():
        return [('NOP', None), ('NOP', None), ('Timestamp', (_s_ts(), ts_c[0]))]

    syn_opts_c = [('MSS', mss), ('SAckOK', b''), ('Timestamp', (_c_ts(), 0)),
                  ('NOP', None), ('WScale', wsc_c)]
    syn_opts_s = [('MSS', mss), ('SAckOK', b''), ('Timestamp', (_s_ts(), ts_c[0])),
                  ('NOP', None), ('WScale', wsc_s)]

    # handshake
    _emit(pkts, c2s("S", win=syn_win_c, opts=syn_opts_c), clock, rng, rtt); cseq += 1
    _emit(pkts, s2c("SA", win=syn_win_s, opts=syn_opts_s), clock, rng, rtt); sseq += 1
    _emit(pkts, c2s("A", opts=est_c()), clock, rng, rtt)
    # data
    for direction, load in exchanges:
        if direction == "c2s":
            _emit(pkts, c2s("PA", load, opts=est_c()), clock, rng, rtt); cseq += len(load)
            _emit(pkts, s2c("A", opts=est_s()), clock, rng, rtt)
        else:
            _emit(pkts, s2c("PA", load, opts=est_s()), clock, rng, rtt); sseq += len(load)
            _emit(pkts, c2s("A", opts=est_c()), clock, rng, rtt)
    # teardown
    _emit(pkts, c2s("FA", opts=est_c()), clock, rng, rtt); cseq += 1
    _emit(pkts, s2c("FA", opts=est_s()), clock, rng, rtt); sseq += 1
    _emit(pkts, c2s("A", opts=est_c()), clock, rng, rtt)
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
